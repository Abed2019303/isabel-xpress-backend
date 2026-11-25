require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const express = require('express');
const bcrypt = require('bcryptjs');
const { Server } = require('socket.io');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: true, limit: '20kb' }));
app.use(express.json({ limit: '20kb' }));

app.use((req, res, next) => {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('X-Frame-Options', 'DENY');
    res.set('Referrer-Policy', 'no-referrer');
    next();
});

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' }, maxHttpBufferSize: 20000 });

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// ---------------------------------------------------------------------------
// Settings (set these in the Render dashboard, never in the code)
// ---------------------------------------------------------------------------
const JWT_SECRET = process.env.JWT_SECRET || '';
const ADMIN_KEY = process.env.ADMIN_KEY || '';
const BREVO_API_KEY = process.env.BREVO_API_KEY || '';
const MAIL_FROM = process.env.MAIL_FROM || '';
const MAIL_FROM_NAME = process.env.MAIL_FROM_NAME || 'Isabel-Xpress';

if (JWT_SECRET.length < 32) {
    console.error('WARNING: JWT_SECRET is missing or shorter than 32 characters. Logins are disabled until it is set.');
}

const TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;   // 30 days (saved login)
const RESET_CODE_MINUTES = 10;
const RESET_MAX_ATTEMPTS = 5;
const PENDING_EXPIRY_MINUTES = 15;

// ---------------------------------------------------------------------------
// Passwords
// ---------------------------------------------------------------------------
const PASSWORD_MESSAGE =
    'Password must be at least 12 characters long and include a number, capital letter, and special character (@#$%^&+=!_).';

const isValidPassword = (password) => {
    const regex = /^(?=.*\d)(?=.*[A-Z])(?=.*[@#$%^&+=!_]).{12,}$/;
    return typeof password === 'string' && regex.test(password);
};

const hashPassword = (plain) => bcrypt.hash(plain, 10);

async function verifyPassword(table, row, plain) {
    const stored = row.password || '';
    if (stored.startsWith('$2')) {
        return bcrypt.compare(plain, stored);
    }
    if (stored === plain) {
        const upgraded = await hashPassword(plain);
        await supabase.from(table).update({ password: upgraded }).eq('id', row.id);
        return true;
    }
    return false;
}

const stripPassword = (row) => {
    if (!row) return row;
    const { password, ...safe } = row;
    return safe;
};

const normalizeEmail = (e) => String(e || '').trim().toLowerCase();
const isEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 254;

// ---------------------------------------------------------------------------
// Tokens (HS256 JWT built with Node's crypto, so no extra package is needed)
// ---------------------------------------------------------------------------
const b64url = (buf) => Buffer.from(buf).toString('base64url');

function signToken(payload) {
    const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const now = Math.floor(Date.now() / 1000);
    const body = b64url(JSON.stringify({ ...payload, iat: now, exp: now + TOKEN_TTL_SECONDS }));
    const sig = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
    return `${header}.${body}.${sig}`;
}

function verifyToken(token) {
    if (JWT_SECRET.length < 32 || typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${parts[0]}.${parts[1]}`).digest();
    let given;
    try { given = Buffer.from(parts[2], 'base64url'); } catch (e) { return null; }
    if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;

    try {
        const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
        if (header.alg !== 'HS256') return null;
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        if (!payload.sub || !payload.role || !payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
        return payload;
    } catch (e) {
        return null;
    }
}

function requireAuth(role) {
    return (req, res, next) => {
        const header = req.get('authorization') || '';
        const token = header.startsWith('Bearer ') ? header.slice(7) : '';
        const payload = verifyToken(token);

        if (!payload) {
            return res.status(401).json({ success: false, message: 'Please log in again.' });
        }
        if (role && payload.role !== role) {
            return res.status(403).json({ success: false, message: 'This action is not allowed for your account type.' });
        }
        req.auth = payload;
        next();
    };
}

// ---------------------------------------------------------------------------
// Rate limiting (in memory; fine for one Render instance)
// ---------------------------------------------------------------------------
const hits = new Map();

function rateLimit(name, max, windowMs) {
    return (req, res, next) => {
        const key = `${name}:${req.ip}`;
        const now = Date.now();
        const rec = hits.get(key);

        if (!rec || rec.reset < now) {
            hits.set(key, { count: 1, reset: now + windowMs });
            return next();
        }
        rec.count += 1;
        if (rec.count > max) {
            return res.status(429).json({ success: false, message: 'Too many attempts. Please wait a few minutes and try again.' });
        }
        next();
    };
}

setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset < now) hits.delete(k);
}, 10 * 60 * 1000).unref();

// ---------------------------------------------------------------------------
// Admin protection
// ---------------------------------------------------------------------------
const adminFails = new Map();

function requireAdmin(req, res, next) {
    const ip = req.ip;
    const rec = adminFails.get(ip) || { count: 0, until: 0 };

    if (rec.until > Date.now()) {
        return res.status(429).json({ success: false, message: 'Too many attempts. Try again later.' });
    }

    const provided = Buffer.from(req.get('x-admin-key') || '');
    const expected = Buffer.from(ADMIN_KEY);
    const ok = ADMIN_KEY.length > 0 &&
        provided.length === expected.length &&
        crypto.timingSafeEqual(provided, expected);

    if (!ok) {
        rec.count += 1;
        if (rec.count >= 10) {
            rec.until = Date.now() + 15 * 60 * 1000;
            rec.count = 0;
        }
        adminFails.set(ip, rec);
        return res.status(401).json({ success: false, message: 'Invalid admin key.' });
    }

    adminFails.delete(ip);
    next();
}

// ---------------------------------------------------------------------------
// Fare (the server is the only place that decides the price)
// ---------------------------------------------------------------------------
function computeFare(origin, destination, discounted) {
    const R = 6371;
    const toRad = (deg) => deg * (Math.PI / 180);
    const dLat = toRad(destination.latitude - origin.latitude);
    const dLon = toRad(destination.longitude - origin.longitude);
    const a =
        Math.sin(dLat / 2) * Math.sin(dLat / 2) +
        Math.cos(toRad(origin.latitude)) * Math.cos(toRad(destination.latitude)) *
        Math.sin(dLon / 2) * Math.sin(dLon / 2);
    const distanceKm = R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

    let baseFare = 15.0;
    if (distanceKm > 1.0) baseFare += (distanceKm - 1.0) * 8.0;

    const totalFare = discounted ? baseFare * 0.8 : baseFare;

    return {
        distanceKm: parseFloat(distanceKm.toFixed(2)),
        baseFare: parseFloat(baseFare.toFixed(2)),
        totalFare: parseFloat(totalFare.toFixed(2)),
        isDiscounted: discounted
    };
}

// ---------------------------------------------------------------------------
// Email (Brevo HTTPS API, because Render's free tier blocks SMTP)
// ---------------------------------------------------------------------------
async function sendResetEmail(toEmail, code) {
    if (!BREVO_API_KEY || !MAIL_FROM) {
        console.error('EMAIL NOT CONFIGURED: set BREVO_API_KEY and MAIL_FROM on Render.');
        return false;
    }

    try {
        const res = await fetch('https://api.brevo.com/v3/smtp/email', {
            method: 'POST',
            headers: { 'api-key': BREVO_API_KEY, 'content-type': 'application/json', accept: 'application/json' },
            body: JSON.stringify({
                sender: { name: MAIL_FROM_NAME, email: MAIL_FROM },
                to: [{ email: toEmail }],
                subject: 'Your Isabel-Xpress password reset code',
                htmlContent:
                    `<p>Your Isabel-Xpress password reset code is:</p>` +
                    `<p style="font-size:28px;font-weight:bold;letter-spacing:6px">${code}</p>` +
                    `<p>It expires in ${RESET_CODE_MINUTES} minutes. If you did not ask for this, ignore this email; your password has not changed.</p>`
            })
        });

        if (!res.ok) {
            console.error('BREVO ERROR:', res.status, (await res.text()).slice(0, 300));
            return false;
        }
        return true;
    } catch (err) {
        console.error('BREVO FETCH ERROR:', err.message);
        return false;
    }
}

const tableFor = (role) => (role === 'driver' ? 'drivers' : 'passengers');

// ---------------------------------------------------------------------------
// Public routes
// ---------------------------------------------------------------------------
app.get('/', (req, res) => {
    res.status(200).json({ success: true, message: 'Isabel-Xpress backend is running' });
});

app.post('/register', rateLimit('register', 10, 60 * 60 * 1000), async (req, res) => {
    try {
        const { full_name, fullName, password } = req.body;
        const email = normalizeEmail(req.body.email);
        const nameToSave = String(fullName || full_name || '').trim();

        if (!nameToSave || !email || !password) {
            return res.status(400).json({ success: false, message: 'All fields are required.' });
        }
        if (!isEmail(email)) {
            return res.status(400).json({ success: false, message: 'Please enter a valid email address.' });
        }
        if (nameToSave.length > 100) {
            return res.status(400).json({ success: false, message: 'Name is too long.' });
        }
        if (!isValidPassword(password)) {
            return res.status(400).json({ success: false, message: PASSWORD_MESSAGE });
        }

        const { error } = await supabase
            .from('passengers')
            .insert([{ full_name: nameToSave, email, password: await hashPassword(password) }]);

        if (error) {
            console.error('PASSENGER INSERT ERROR:', error);
            return res.status(400).json({ success: false, message: 'Could not register. This email may already be in use.' });
        }

        res.status(200).json({ success: true, message: 'User registered successfully!' });
    } catch (err) {
        console.error('PASSENGER REGISTER ERROR:', err);
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.post('/login', rateLimit('login', 20, 15 * 60 * 1000), async (req, res) => {
    try {
        const email = normalizeEmail(req.body.email);
        const { password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password are required.' });
        }
        if (JWT_SECRET.length < 32) {
            return res.status(500).json({ success: false, message: 'Server is not configured. Please contact the administrator.' });
        }

        const { data, error } = await supabase.from('passengers').select('*').eq('email', email).maybeSingle();

        if (error) {
            console.error('PASSENGER LOGIN ERROR:', error);
            return res.status(500).json({ success: false, message: 'Server error.' });
        }

        if (!data || !(await verifyPassword('passengers', data, password))) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const token = signToken({ sub: data.id, role: 'passenger', name: data.full_name });
        res.status(200).json({ success: true, message: 'Login successful', token, user: stripPassword(data) });
    } catch (err) {
        console.error('PASSENGER LOGIN CRASH:', err);
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.post('/driver-register', rateLimit('driver-register', 10, 60 * 60 * 1000), async (req, res) => {
    try {
        const { full_name, fullName, password, toda_body_number, bodyNumber } = req.body;
        const email = normalizeEmail(req.body.email);
        const nameToSave = String(fullName || full_name || '').trim();
        const bodyToSave = String(bodyNumber || toda_body_number || '').trim();

        if (!nameToSave || !email || !password || !bodyToSave) {
            return res.status(400).json({ success: false, message: 'All fields are required.' });
        }
        if (!isEmail(email)) {
            return res.status(400).json({ success: false, message: 'Please enter a valid email address.' });
        }
        if (nameToSave.length > 100 || bodyToSave.length > 20) {
            return res.status(400).json({ success: false, message: 'Name or body number is too long.' });
        }
        if (!isValidPassword(password)) {
            return res.status(400).json({ success: false, message: PASSWORD_MESSAGE });
        }

        const { data, error } = await supabase
            .from('drivers')
            .insert([{
                full_name: nameToSave,
                email,
                password: await hashPassword(password),
                toda_body_number: bodyToSave,
                is_online: false,
                is_verified: false
            }])
            .select();

        if (error) {
            console.error('DRIVER INSERT ERROR:', error);
            return res.status(400).json({ success: false, message: 'Could not register. This email may already be in use.' });
        }

        res.status(200).json({
            success: true,
            message: 'Registration received. You can log in after the administrator verifies your TODA details.',
            user: stripPassword(data[0])
        });
    } catch (err) {
        console.error('DRIVER REGISTER ERROR:', err);
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.post('/driver-login', rateLimit('driver-login', 20, 15 * 60 * 1000), async (req, res) => {
    try {
        const email = normalizeEmail(req.body.email);
        const { password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password are required.' });
        }
        if (JWT_SECRET.length < 32) {
            return res.status(500).json({ success: false, message: 'Server is not configured. Please contact the administrator.' });
        }

        const { data, error } = await supabase.from('drivers').select('*').eq('email', email).maybeSingle();

        if (error) {
            console.error('DRIVER LOGIN ERROR:', error);
            return res.status(500).json({ success: false, message: 'Server error.' });
        }

        if (!data || !(await verifyPassword('drivers', data, password))) {
            return res.status(401).json({ success: false, message: 'Invalid driver credentials' });
        }

        if (!data.is_verified) {
            return res.status(403).json({
                success: false,
                message: 'Your account is waiting for verification by the administrator. Please try again later.'
            });
        }

        const token = signToken({ sub: data.id, role: 'driver', name: data.full_name });
        res.status(200).json({ success: true, message: 'Login successful', token, user: stripPassword(data) });
    } catch (err) {
        console.error('DRIVER LOGIN CRASH:', err);
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// ---- Password reset with an emailed 6-digit code ----

app.post('/forgot-password', rateLimit('forgot', 5, 15 * 60 * 1000), async (req, res) => {
    // The reply is always the same, so nobody can use this to find out which emails are registered
    const generic = { success: true, message: 'If this email is registered, a 6-digit code has been sent to it.' };

    try {
        const email = normalizeEmail(req.body.email);
        const role = req.body.role === 'driver' ? 'driver' : 'passenger';

        if (!isEmail(email)) {
            return res.status(400).json({ success: false, message: 'Please enter a valid email address.' });
        }

        const { data: user } = await supabase.from(tableFor(role)).select('id').eq('email', email).maybeSingle();
        if (!user) return res.status(200).json(generic);

        // One code per email at a time: wait 60 seconds before another is sent
        const { data: recent } = await supabase
            .from('password_resets')
            .select('created_at')
            .eq('email', email)
            .eq('role', role)
            .order('created_at', { ascending: false })
            .limit(1);

        if (recent && recent.length && Date.now() - new Date(recent[0].created_at).getTime() < 60 * 1000) {
            return res.status(200).json(generic);
        }

        const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');

        await supabase.from('password_resets').update({ used: true }).eq('email', email).eq('role', role).eq('used', false);

        const { error } = await supabase.from('password_resets').insert([{
            role,
            email,
            code_hash: await bcrypt.hash(code, 8),
            expires_at: new Date(Date.now() + RESET_CODE_MINUTES * 60 * 1000).toISOString()
        }]);

        if (error) {
            console.error('RESET INSERT ERROR:', error);
            return res.status(500).json({ success: false, message: 'Server error. Please try again.' });
        }

        const sent = await sendResetEmail(email, code);
        if (!sent) {
            return res.status(500).json({ success: false, message: 'Could not send the email right now. Please try again later.' });
        }

        res.status(200).json(generic);
    } catch (err) {
        console.error('FORGOT ERROR:', err);
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.post('/reset-password', rateLimit('reset', 15, 15 * 60 * 1000), async (req, res) => {
    const bad = { success: false, message: 'The code is wrong or has expired. Request a new one.' };

    try {
        const email = normalizeEmail(req.body.email);
        const role = req.body.role === 'driver' ? 'driver' : 'passenger';
        const code = String(req.body.code || '').trim();
        const { newPassword } = req.body;

        if (!isEmail(email) || !/^\d{6}$/.test(code) || !newPassword) {
            return res.status(400).json({ success: false, message: 'Email, 6-digit code and new password are required.' });
        }
        if (!isValidPassword(newPassword)) {
            return res.status(400).json({ success: false, message: PASSWORD_MESSAGE });
        }

        const { data: rows } = await supabase
            .from('password_resets')
            .select('*')
            .eq('email', email)
            .eq('role', role)
            .eq('used', false)
            .order('created_at', { ascending: false })
            .limit(1);

        const row = rows && rows[0];
        if (!row || new Date(row.expires_at).getTime() < Date.now() || row.attempts >= RESET_MAX_ATTEMPTS) {
            return res.status(400).json(bad);
        }

        if (!(await bcrypt.compare(code, row.code_hash))) {
            await supabase.from('password_resets').update({ attempts: row.attempts + 1 }).eq('id', row.id);
            return res.status(400).json(bad);
        }

        const { data: user } = await supabase.from(tableFor(role)).select('id').eq('email', email).maybeSingle();
        if (!user) return res.status(400).json(bad);

        const { error } = await supabase
            .from(tableFor(role))
            .update({ password: await hashPassword(newPassword) })
            .eq('id', user.id);

        if (error) {
            return res.status(400).json({ success: false, message: 'Failed to update password.' });
        }

        await supabase.from('password_resets').update({ used: true }).eq('id', row.id);
        res.status(200).json({ success: true, message: 'Password updated. You can now log in.' });
    } catch (err) {
        console.error('RESET ERROR:', err);
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// The old reset endpoints let anyone change anyone's password, so they are gone
const gone = (req, res) => res.status(410).json({ success: false, message: 'Please update the app.' });
app.post('/reset-password-direct', gone);
app.post('/driver-reset-password', gone);

app.get('/landmarks', async (req, res) => {
    try {
        const { data, error } = await supabase.from('landmarks').select('*');
        if (error) return res.status(400).json({ success: false, message: error.message });
        res.status(200).json(data);
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.post('/calculate-fare', rateLimit('fare', 120, 15 * 60 * 1000), async (req, res) => {
    try {
        const { originLandmarkId, destinationLandmarkId, isDiscounted } = req.body;

        if (!originLandmarkId || !destinationLandmarkId) {
            return res.status(400).json({ success: false, message: 'Origin and destination are required.' });
        }
        if (String(originLandmarkId) === String(destinationLandmarkId)) {
            return res.status(400).json({ success: false, message: 'Pickup and destination cannot be the same location.' });
        }

        const { data: landmarks, error } = await supabase
            .from('landmarks')
            .select('*')
            .in('id', [originLandmarkId, destinationLandmarkId]);

        if (error || !landmarks || landmarks.length < 2) {
            return res.status(400).json({ success: false, message: 'Invalid landmarks specified.' });
        }

        const origin = landmarks.find((l) => String(l.id) === String(originLandmarkId));
        const destination = landmarks.find((l) => String(l.id) === String(destinationLandmarkId));
        if (!origin || !destination) {
            return res.status(400).json({ success: false, message: 'Invalid landmarks specified.' });
        }

        res.status(200).json(computeFare(origin, destination, isDiscounted === true || isDiscounted === 'true'));
    } catch (err) {
        console.error('FARE ERROR:', err);
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// ---------------------------------------------------------------------------
// Logged-in routes
// ---------------------------------------------------------------------------

// Drivers never see a passenger's email
const viewFor = (role, booking) => {
    if (!booking) return booking;
    if (role === 'driver') {
        const { passenger_email, ...rest } = booking;
        return rest;
    }
    return booking;
};

const isParticipant = (auth, b) =>
    (auth.role === 'passenger' && b.passenger_id === auth.sub) ||
    (auth.role === 'driver' && b.driver_id === auth.sub);

app.post('/driver-status', requireAuth('driver'), async (req, res) => {
    try {
        const driverId = req.auth.sub;
        const { isOnline } = req.body;

        if (typeof isOnline !== 'boolean') {
            return res.status(400).json({ success: false, message: 'isOnline (true/false) is required.' });
        }

        if (isOnline) {
            const { data: driver } = await supabase.from('drivers').select('id, is_verified').eq('id', driverId).maybeSingle();
            if (!driver) return res.status(404).json({ success: false, message: 'Driver not found.' });
            if (!driver.is_verified) {
                return res.status(403).json({ success: false, message: 'Your account is not verified yet.' });
            }
        }

        const { error } = await supabase.from('drivers').update({ is_online: isOnline }).eq('id', driverId);
        if (error) return res.status(400).json({ success: false, message: error.message });
        res.status(200).json({ success: true, message: 'Status updated successfully' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.get('/available-drivers', requireAuth(), async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('drivers')
            .select('id, full_name, toda_body_number, is_online, current_latitude, current_longitude, location_updated_at')
            .eq('is_online', true)
            .eq('is_verified', true);

        if (error) return res.status(400).json({ success: false, message: error.message });

        const now = Date.now();
        const drivers = (data || []).map((d) => ({
            ...d,
            location_age_seconds: d.location_updated_at
                ? Math.round((now - new Date(d.location_updated_at).getTime()) / 1000)
                : null
        }));

        res.status(200).json({ success: true, drivers });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.post('/bookings', requireAuth('passenger'), rateLimit('booking', 30, 60 * 60 * 1000), async (req, res) => {
    try {
        const passengerId = req.auth.sub;
        const { pickupName, destinationName, isDiscounted } = req.body;

        if (!pickupName || !destinationName) {
            return res.status(400).json({ success: false, message: 'Missing booking details.' });
        }
        if (pickupName === destinationName) {
            return res.status(400).json({ success: false, message: 'Pickup and destination cannot be the same location.' });
        }

        const { data: passenger } = await supabase
            .from('passengers').select('id, full_name, email').eq('id', passengerId).maybeSingle();
        if (!passenger) {
            return res.status(401).json({ success: false, message: 'Please log in again.' });
        }

        // The price is computed here from the landmark coordinates; whatever the phone sends is ignored
        const { data: landmarks } = await supabase
            .from('landmarks').select('*').in('name', [pickupName, destinationName]);

        const origin = (landmarks || []).find((l) => l.name === pickupName);
        const destination = (landmarks || []).find((l) => l.name === destinationName);
        if (!origin || !destination) {
            return res.status(400).json({ success: false, message: 'Invalid pickup or destination.' });
        }

        const fare = computeFare(origin, destination, isDiscounted === true);

        const { data: existing } = await supabase
            .from('bookings')
            .select('id')
            .eq('passenger_id', passengerId)
            .in('status', ['PENDING', 'ACCEPTED'])
            .limit(1);

        if (existing && existing.length > 0) {
            return res.status(409).json({ success: false, message: 'You already have an active booking.' });
        }

        const { data, error } = await supabase
            .from('bookings')
            .insert([{
                passenger_id: passengerId,
                passenger_name: passenger.full_name,
                passenger_email: passenger.email,
                pickup_name: origin.name,
                destination_name: destination.name,
                distance_km: fare.distanceKm,
                fare: fare.totalFare,
                is_discounted: fare.isDiscounted,
                status: 'PENDING'
            }])
            .select()
            .single();

        if (error) {
            console.error('BOOKING INSERT ERROR:', error);
            return res.status(400).json({ success: false, message: 'Could not create the booking.' });
        }

        io.to('drivers').emit('new_booking', viewFor('driver', data));
        res.status(200).json({ success: true, message: 'Booking created', booking: data });
    } catch (err) {
        console.error('BOOKING CREATE ERROR:', err);
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.get('/bookings/available', requireAuth('driver'), async (req, res) => {
    try {
        const { data: driver } = await supabase.from('drivers').select('is_verified').eq('id', req.auth.sub).maybeSingle();
        if (!driver || !driver.is_verified) {
            return res.status(403).json({ success: false, message: 'Your account is not verified.' });
        }

        const { data, error } = await supabase
            .from('bookings')
            .select('*')
            .eq('status', 'PENDING')
            .order('created_at', { ascending: true });

        if (error) return res.status(400).json({ success: false, message: error.message });
        res.status(200).json({ success: true, bookings: (data || []).map((b) => viewFor('driver', b)) });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// Who you are comes from the token, so the old ?passengerId= and ?driverId= values are ignored
app.get('/bookings/active', requireAuth(), async (req, res) => {
    try {
        let query = supabase.from('bookings').select('*');

        if (req.auth.role === 'passenger') {
            query = query.eq('passenger_id', req.auth.sub).in('status', ['PENDING', 'ACCEPTED']);
        } else {
            query = query.eq('driver_id', req.auth.sub).eq('status', 'ACCEPTED');
        }

        const { data, error } = await query.order('created_at', { ascending: false }).limit(1);
        if (error) return res.status(400).json({ success: false, message: error.message });

        res.status(200).json({
            success: true,
            booking: data && data.length ? viewFor(req.auth.role, data[0]) : null
        });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.get('/my/bookings', requireAuth(), async (req, res) => {
    try {
        const column = req.auth.role === 'driver' ? 'driver_id' : 'passenger_id';

        const { data, error } = await supabase
            .from('bookings')
            .select('*')
            .eq(column, req.auth.sub)
            .in('status', ['COMPLETED', 'CANCELLED'])
            .order('created_at', { ascending: false })
            .limit(50);

        if (error) return res.status(400).json({ success: false, message: error.message });
        res.status(200).json({ success: true, bookings: (data || []).map((b) => viewFor(req.auth.role, b)) });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.get('/bookings/:id', requireAuth(), async (req, res) => {
    try {
        const { data, error } = await supabase.from('bookings').select('*').eq('id', req.params.id).maybeSingle();

        if (error) return res.status(400).json({ success: false, message: 'Booking not found.' });
        if (!data || !isParticipant(req.auth, data)) {
            return res.status(404).json({ success: false, message: 'Booking not found.' });
        }

        res.status(200).json({ success: true, booking: viewFor(req.auth.role, data) });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.post('/bookings/:id/accept', requireAuth('driver'), async (req, res) => {
    try {
        const driverId = req.auth.sub;

        const { data: driver } = await supabase
            .from('drivers')
            .select('id, full_name, toda_body_number, is_verified')
            .eq('id', driverId)
            .maybeSingle();

        if (!driver) return res.status(404).json({ success: false, message: 'Driver not found.' });
        if (!driver.is_verified) {
            return res.status(403).json({ success: false, message: 'Your account is not verified yet.' });
        }

        const { data: busy } = await supabase
            .from('bookings').select('id').eq('driver_id', driverId).eq('status', 'ACCEPTED').limit(1);

        if (busy && busy.length > 0) {
            return res.status(409).json({ success: false, message: 'Finish your current trip first.' });
        }

        const { data, error } = await supabase
            .from('bookings')
            .update({
                status: 'ACCEPTED',
                driver_id: driver.id,
                driver_name: driver.full_name,
                driver_body_number: driver.toda_body_number,
                accepted_at: new Date().toISOString()
            })
            .eq('id', req.params.id)
            .eq('status', 'PENDING')
            .select();

        if (error) return res.status(400).json({ success: false, message: 'Could not accept this booking.' });
        if (!data || data.length === 0) {
            return res.status(409).json({ success: false, message: 'This booking was already taken.' });
        }

        const booking = data[0];
        io.to(`passenger:${booking.passenger_id}`).emit('booking_accepted', booking);
        io.to('drivers').emit('booking_taken', { id: booking.id });

        res.status(200).json({ success: true, message: 'Booking accepted', booking: viewFor('driver', booking) });
    } catch (err) {
        console.error('BOOKING ACCEPT ERROR:', err);
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.post('/bookings/:id/complete', requireAuth('driver'), async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('bookings')
            .update({ status: 'COMPLETED', completed_at: new Date().toISOString() })
            .eq('id', req.params.id)
            .eq('driver_id', req.auth.sub)
            .eq('status', 'ACCEPTED')
            .select();

        if (error) return res.status(400).json({ success: false, message: 'Could not complete the trip.' });
        if (!data || data.length === 0) {
            return res.status(409).json({ success: false, message: 'No active trip to complete.' });
        }

        const booking = data[0];
        io.to(`passenger:${booking.passenger_id}`).emit('booking_completed', booking);

        res.status(200).json({ success: true, message: 'Trip completed', booking: viewFor('driver', booking) });
    } catch (err) {
        console.error('BOOKING COMPLETE ERROR:', err);
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// A passenger can cancel while waiting or after a driver accepted
app.post('/bookings/:id/cancel', requireAuth('passenger'), async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('bookings')
            .update({ status: 'CANCELLED', cancelled_at: new Date().toISOString() })
            .eq('id', req.params.id)
            .eq('passenger_id', req.auth.sub)
            .in('status', ['PENDING', 'ACCEPTED'])
            .select();

        if (error) return res.status(400).json({ success: false, message: 'Could not cancel the booking.' });
        if (!data || data.length === 0) {
            return res.status(409).json({ success: false, message: 'This booking can no longer be cancelled.' });
        }

        const booking = data[0];
        io.to(`booking:${booking.id}`).emit('booking_cancelled', { id: booking.id });
        io.to('drivers').emit('booking_taken', { id: booking.id });   // removes it from every driver's list

        res.status(200).json({ success: true, message: 'Booking cancelled', booking });
    } catch (err) {
        console.error('BOOKING CANCEL ERROR:', err);
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// Passenger rates the driver once, after the trip
app.post('/bookings/:id/rate', requireAuth('passenger'), async (req, res) => {
    try {
        const rating = Number(req.body.rating);
        const comment = String(req.body.comment || '').trim().slice(0, 300);

        if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
            return res.status(400).json({ success: false, message: 'Rating must be from 1 to 5.' });
        }

        const { data, error } = await supabase
            .from('bookings')
            .update({ rating, rating_comment: comment || null, rated_at: new Date().toISOString() })
            .eq('id', req.params.id)
            .eq('passenger_id', req.auth.sub)
            .eq('status', 'COMPLETED')
            .is('rating', null)
            .select();

        if (error) return res.status(400).json({ success: false, message: 'Could not save the rating.' });
        if (!data || data.length === 0) {
            return res.status(409).json({ success: false, message: 'This trip cannot be rated (already rated or not completed).' });
        }

        res.status(200).json({ success: true, message: 'Thank you for your feedback!' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// Passenger reports a driver; the administrator reviews it
const REPORT_REASONS = [
    'Overcharged / wrong fare',
    'Rude or unsafe driving',
    'Driver did not match registered details',
    'Other'
];

app.post('/reports', requireAuth('passenger'), rateLimit('report', 10, 60 * 60 * 1000), async (req, res) => {
    try {
        const { bookingId } = req.body;
        const reason = String(req.body.reason || '').trim();
        const details = String(req.body.details || '').trim().slice(0, 500);

        if (!bookingId || !REPORT_REASONS.includes(reason)) {
            return res.status(400).json({ success: false, message: 'Choose a reason for the report.' });
        }

        const { data: booking } = await supabase
            .from('bookings').select('id, passenger_id, driver_id').eq('id', bookingId).maybeSingle();

        if (!booking || booking.passenger_id !== req.auth.sub || !booking.driver_id) {
            return res.status(404).json({ success: false, message: 'Trip not found.' });
        }

        const { data: dup } = await supabase
            .from('reports').select('id').eq('booking_id', booking.id).eq('passenger_id', req.auth.sub).limit(1);
        if (dup && dup.length > 0) {
            return res.status(409).json({ success: false, message: 'You already reported this trip.' });
        }

        const { error } = await supabase.from('reports').insert([{
            booking_id: booking.id,
            driver_id: booking.driver_id,
            passenger_id: req.auth.sub,
            reason,
            details: details || null,
            status: 'OPEN'
        }]);

        if (error) {
            console.error('REPORT INSERT ERROR:', error);
            return res.status(400).json({ success: false, message: 'Could not save the report.' });
        }

        res.status(200).json({ success: true, message: 'Report sent. The administrator will review it.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// ---------------------------------------------------------------------------
// Administrator
// ---------------------------------------------------------------------------
app.get('/admin', (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/admin/api/drivers', requireAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('drivers')
            .select('id, full_name, email, toda_body_number, vehicle_model, is_online, is_verified, verified_at, created_at')
            .order('created_at', { ascending: false });

        if (error) return res.status(400).json({ success: false, message: error.message });

        const { data: rated } = await supabase
            .from('bookings').select('driver_id, rating').not('rating', 'is', null);
        const { data: reps } = await supabase
            .from('reports').select('driver_id').eq('status', 'OPEN');

        const sums = {};
        for (const r of rated || []) {
            const s = sums[r.driver_id] || (sums[r.driver_id] = { total: 0, n: 0 });
            s.total += r.rating;
            s.n += 1;
        }
        const openReports = {};
        for (const r of reps || []) openReports[r.driver_id] = (openReports[r.driver_id] || 0) + 1;

        const drivers = (data || []).map((d) => ({
            ...d,
            avg_rating: sums[d.id] ? parseFloat((sums[d.id].total / sums[d.id].n).toFixed(2)) : null,
            rating_count: sums[d.id] ? sums[d.id].n : 0,
            open_reports: openReports[d.id] || 0
        }));

        res.status(200).json({ success: true, drivers });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.post('/admin/api/drivers/:id/verify', requireAdmin, async (req, res) => {
    try {
        const verified = req.body.verified === true;

        const update = verified
            ? { is_verified: true, verified_at: new Date().toISOString() }
            : { is_verified: false, verified_at: null, is_online: false };

        const { data, error } = await supabase
            .from('drivers')
            .update(update)
            .eq('id', req.params.id)
            .select('id, full_name, is_verified');

        if (error) return res.status(400).json({ success: false, message: error.message });
        if (!data || data.length === 0) {
            return res.status(404).json({ success: false, message: 'Driver not found.' });
        }

        res.status(200).json({ success: true, message: verified ? 'Driver verified' : 'Driver suspended', driver: data[0] });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.get('/admin/api/bookings', requireAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('bookings')
            .select('*')
            .order('created_at', { ascending: false })
            .limit(200);

        if (error) return res.status(400).json({ success: false, message: error.message });
        res.status(200).json({ success: true, bookings: data });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.get('/admin/api/reports', requireAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('reports').select('*').order('created_at', { ascending: false }).limit(200);
        if (error) return res.status(400).json({ success: false, message: error.message });

        const driverIds = [...new Set((data || []).map((r) => r.driver_id))];
        const passengerIds = [...new Set((data || []).map((r) => r.passenger_id))];

        const { data: drivers } = driverIds.length
            ? await supabase.from('drivers').select('id, full_name, toda_body_number').in('id', driverIds)
            : { data: [] };
        const { data: passengers } = passengerIds.length
            ? await supabase.from('passengers').select('id, full_name').in('id', passengerIds)
            : { data: [] };

        const dMap = Object.fromEntries((drivers || []).map((d) => [d.id, d]));
        const pMap = Object.fromEntries((passengers || []).map((p) => [p.id, p]));

        const reports = (data || []).map((r) => ({
            ...r,
            driver_name: dMap[r.driver_id] ? dMap[r.driver_id].full_name : null,
            driver_body_number: dMap[r.driver_id] ? dMap[r.driver_id].toda_body_number : null,
            passenger_name: pMap[r.passenger_id] ? pMap[r.passenger_id].full_name : null
        }));

        res.status(200).json({ success: true, reports });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.post('/admin/api/reports/:id/resolve', requireAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('reports')
            .update({ status: 'RESOLVED', resolved_at: new Date().toISOString() })
            .eq('id', req.params.id)
            .select('id');

        if (error) return res.status(400).json({ success: false, message: error.message });
        if (!data || data.length === 0) return res.status(404).json({ success: false, message: 'Report not found.' });
        res.status(200).json({ success: true, message: 'Report marked as resolved' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// ---------------------------------------------------------------------------
// Waiting bookings that nobody accepts expire after 15 minutes
// ---------------------------------------------------------------------------
setInterval(async () => {
    try {
        const cutoff = new Date(Date.now() - PENDING_EXPIRY_MINUTES * 60 * 1000).toISOString();
        const { data } = await supabase
            .from('bookings')
            .update({ status: 'CANCELLED', cancelled_at: new Date().toISOString() })
            .eq('status', 'PENDING')
            .lt('created_at', cutoff)
            .select();

        for (const b of data || []) {
            io.to(`passenger:${b.passenger_id}`).emit('booking_cancelled', { id: b.id });
            io.to('drivers').emit('booking_taken', { id: b.id });
        }
    } catch (err) {
        console.error('EXPIRY ERROR:', err);
    }
}, 60 * 1000).unref();

// ---------------------------------------------------------------------------
// Sockets (every connection must carry a valid token)
// ---------------------------------------------------------------------------
const driverSockets = new Map();
const lastLocationWrite = new Map();

io.use((socket, next) => {
    const token = socket.handshake.auth && socket.handshake.auth.token;
    const payload = verifyToken(token);
    if (!payload) return next(new Error('unauthorized'));
    socket.data.auth = payload;
    socket.data.bookingRooms = new Set();
    next();
});

async function markDriverOffline(socket) {
    try {
        const driverId = socket.data.driverId;
        if (!driverId) return;
        socket.data.driverId = null;
        socket.data.driverInfo = null;

        if (driverSockets.get(driverId) !== socket.id) return;
        driverSockets.delete(driverId);

        const { error } = await supabase.from('drivers').update({ is_online: false }).eq('id', driverId);
        if (error) console.error('MARK OFFLINE ERROR:', error);

        io.emit('driver_offline', { driverId });
    } catch (err) {
        console.error('MARK OFFLINE CRASH:', err);
    }
}

io.on('connection', (socket) => {
    const auth = socket.data.auth;
    console.log('Socket connected:', socket.id, auth.role);

    // Rooms come from the token, never from what the phone says
    if (auth.role === 'passenger') socket.join(`passenger:${auth.sub}`);

    socket.on('join_passenger', () => {
        if (auth.role === 'passenger') socket.join(`passenger:${auth.sub}`);
    });

    socket.on('join_drivers', async () => {
        if (auth.role !== 'driver') return;
        const { data: driver } = await supabase.from('drivers').select('is_verified').eq('id', auth.sub).maybeSingle();
        if (driver && driver.is_verified) socket.join('drivers');
    });

    socket.on('join_booking', async (d) => {
        try {
            if (!d || !d.bookingId) return;
            const { data: b } = await supabase
                .from('bookings').select('id, passenger_id, driver_id, status').eq('id', d.bookingId).maybeSingle();

            if (b && isParticipant(auth, b) && ['PENDING', 'ACCEPTED'].includes(b.status)) {
                socket.join(`booking:${b.id}`);
                socket.data.bookingRooms.add(b.id);
            }
        } catch (err) {
            console.error('JOIN BOOKING ERROR:', err);
        }
    });

    socket.on('chat_message', (d) => {
        if (!d || !d.bookingId || !socket.data.bookingRooms.has(d.bookingId)) return;
        const message = String(d.message || '').trim().slice(0, 500);
        if (!message) return;

        socket.to(`booking:${d.bookingId}`).emit('chat_message', {
            bookingId: d.bookingId,
            sender: `${auth.name || 'User'} (${auth.role === 'driver' ? 'Driver' : 'Passenger'})`,
            message
        });
    });

    socket.on('driver_online', async () => {
        try {
            if (auth.role !== 'driver') return;

            const { data: driver } = await supabase
                .from('drivers')
                .select('id, full_name, toda_body_number, is_verified')
                .eq('id', auth.sub)
                .maybeSingle();

            if (!driver || !driver.is_verified) return;

            socket.data.driverId = driver.id;
            socket.data.driverInfo = { fullName: driver.full_name, bodyNumber: driver.toda_body_number };
            driverSockets.set(driver.id, socket.id);

            await supabase.from('drivers').update({ is_online: true }).eq('id', driver.id);
        } catch (err) {
            console.error('DRIVER ONLINE ERROR:', err);
        }
    });

    socket.on('driver_offline', () => { markDriverOffline(socket); });

    socket.on('location_changed', async (d) => {
        try {
            const driverId = socket.data.driverId;
            const info = socket.data.driverInfo;
            if (!driverId || !info || !d) return;

            const lat = d.latitude;
            const lng = d.longitude;
            if (typeof lat !== 'number' || typeof lng !== 'number' ||
                !Number.isFinite(lat) || !Number.isFinite(lng) ||
                Math.abs(lat) > 90 || Math.abs(lng) > 180) return;

            socket.broadcast.emit('location_changed', {
                driverId,
                fullName: info.fullName,
                bodyNumber: info.bodyNumber,
                latitude: lat,
                longitude: lng
            });

            const now = Date.now();
            if (now - (lastLocationWrite.get(driverId) || 0) >= 10000) {
                lastLocationWrite.set(driverId, now);
                const { error } = await supabase
                    .from('drivers')
                    .update({
                        current_latitude: lat,
                        current_longitude: lng,
                        location_updated_at: new Date().toISOString()
                    })
                    .eq('id', driverId);
                if (error) console.error('LOCATION SAVE ERROR:', error);
            }
        } catch (err) {
            console.error('LOCATION ERROR:', err);
        }
    });

    socket.on('disconnect', () => {
        console.log('Socket disconnected:', socket.id);
        markDriverOffline(socket);
    });
});

const PORT = process.env.PORT || 10000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});
