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
const smallJson = express.json({ limit: '20kb' });
const photoJson = express.json({ limit: '250kb' });   // only the driver photo upload may be larger
app.use((req, res, next) => (req.path === '/driver/profile' ? photoJson : smallJson)(req, res, next));

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

function signToken(payload, ttlSeconds = TOKEN_TTL_SECONDS) {
    const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const now = Math.floor(Date.now() / 1000);
    const body = b64url(JSON.stringify({ ...payload, iat: now, exp: now + ttlSeconds }));
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

        if (!payload || !['passenger', 'driver'].includes(payload.role)) {
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
async function sendResetEmail(toEmail, code, purpose = 'reset') {
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
                subject: purpose === 'verify' ? 'Verify your Isabel-Xpress email' : 'Your Isabel-Xpress password reset code',
                htmlContent:
                    `<p>${purpose === 'verify' ? 'Welcome to Isabel-Xpress! Your email verification code is:' : 'Your Isabel-Xpress password reset code is:'}</p>` +
                    `<p style="font-size:28px;font-weight:bold;letter-spacing:6px">${code}</p>` +
                    `<p>It expires in ${RESET_CODE_MINUTES} minutes. If you did not ask for this, ignore this email.</p>`
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

// Creates a one-time 6-digit code (stored hashed) and returns it, or null if it could not be saved
async function issueCode(email, role, purpose) {
    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');

    await supabase.from('password_resets').update({ used: true })
        .eq('email', email).eq('role', role).eq('purpose', purpose).eq('used', false);

    const { error } = await supabase.from('password_resets').insert([{
        role,
        email,
        purpose,
        code_hash: await bcrypt.hash(code, 8),
        expires_at: new Date(Date.now() + RESET_CODE_MINUTES * 60 * 1000).toISOString()
    }]);

    if (error) {
        console.error('CODE INSERT ERROR:', error);
        return null;
    }
    return code;
}

// Returns true only when the code is right, unused, unexpired and not over the attempt limit
async function consumeCode(email, role, purpose, code) {
    const { data: rows } = await supabase
        .from('password_resets').select('*')
        .eq('email', email).eq('role', role).eq('purpose', purpose).eq('used', false)
        .order('created_at', { ascending: false }).limit(1);

    const row = rows && rows[0];
    if (!row || new Date(row.expires_at).getTime() < Date.now() || row.attempts >= RESET_MAX_ATTEMPTS) return false;

    if (!(await bcrypt.compare(code, row.code_hash))) {
        await supabase.from('password_resets').update({ attempts: row.attempts + 1 }).eq('id', row.id);
        return false;
    }

    await supabase.from('password_resets').update({ used: true }).eq('id', row.id);
    return true;
}

function logAdmin(action, detail) {
    supabase.from('admin_logs').insert([{ action, detail: String(detail || '').slice(0, 300) }])
        .then(({ error }) => { if (error) console.error('ADMIN LOG ERROR:', error.message); });
}

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
            .insert([{ full_name: nameToSave, email, password: await hashPassword(password), email_verified: false }]);

        if (error) {
            console.error('PASSENGER INSERT ERROR:', error);
            return res.status(400).json({ success: false, message: 'Could not register. This email may already be in use.' });
        }

        const code = await issueCode(email, 'passenger', 'verify');
        const sent = code ? await sendResetEmail(email, code, 'verify') : false;
        res.status(200).json({
            success: true,
            needsVerification: true,
            message: sent
                ? 'Registered! We sent a 6-digit code to your email.'
                : 'Registered, but the code email could not be sent. Tap "Resend code" on the next screen.'
        });
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

        if (data.email_verified === false) {
            return res.status(403).json({
                success: false,
                needsVerification: true,
                message: 'Please verify your email first. Enter the 6-digit code we sent you.'
            });
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
                is_verified: false,
                email_verified: false
            }])
            .select();

        if (error) {
            console.error('DRIVER INSERT ERROR:', error);
            return res.status(400).json({ success: false, message: 'Could not register. This email may already be in use.' });
        }

        const code = await issueCode(email, 'driver', 'verify');
        const sent = code ? await sendResetEmail(email, code, 'verify') : false;
        res.status(200).json({
            success: true,
            needsVerification: true,
            message: (sent
                ? 'Registered! We sent a 6-digit code to your email. '
                : 'Registered, but the code email could not be sent. Tap "Resend code" on the next screen. ') +
                'You can log in after you verify your email and the administrator verifies your TODA details.',
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

        if (data.email_verified === false) {
            return res.status(403).json({
                success: false,
                needsVerification: true,
                message: 'Please verify your email first. Enter the 6-digit code we sent you.'
            });
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
            .eq('purpose', 'reset')
            .order('created_at', { ascending: false })
            .limit(1);

        if (recent && recent.length && Date.now() - new Date(recent[0].created_at).getTime() < 60 * 1000) {
            return res.status(200).json(generic);
        }

        const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');

        await supabase.from('password_resets').update({ used: true }).eq('email', email).eq('role', role).eq('purpose', 'reset').eq('used', false);

        const { error } = await supabase.from('password_resets').insert([{
            role,
            email,
            purpose: 'reset',
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
            .eq('purpose', 'reset')
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

// ---- Email verification after registration ----

app.post('/send-verification', rateLimit('sendverify', 5, 15 * 60 * 1000), async (req, res) => {
    const generic = { success: true, message: 'If this email needs verification, a new code has been sent.' };
    try {
        const email = normalizeEmail(req.body.email);
        const role = req.body.role === 'driver' ? 'driver' : 'passenger';
        if (!isEmail(email)) {
            return res.status(400).json({ success: false, message: 'Please enter a valid email address.' });
        }

        const { data: user } = await supabase.from(tableFor(role)).select('id, email_verified').eq('email', email).maybeSingle();
        if (!user || user.email_verified !== false) return res.status(200).json(generic);

        const { data: recent } = await supabase
            .from('password_resets').select('created_at')
            .eq('email', email).eq('role', role).eq('purpose', 'verify')
            .order('created_at', { ascending: false }).limit(1);
        if (recent && recent.length && Date.now() - new Date(recent[0].created_at).getTime() < 60 * 1000) {
            return res.status(200).json(generic);
        }

        const code = await issueCode(email, role, 'verify');
        if (!code || !(await sendResetEmail(email, code, 'verify'))) {
            return res.status(500).json({ success: false, message: 'Could not send the email right now. Please try again later.' });
        }
        res.status(200).json(generic);
    } catch (err) {
        console.error('SEND VERIFY ERROR:', err);
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.post('/verify-email', rateLimit('verifyemail', 15, 15 * 60 * 1000), async (req, res) => {
    try {
        const email = normalizeEmail(req.body.email);
        const role = req.body.role === 'driver' ? 'driver' : 'passenger';
        const code = String(req.body.code || '').trim();

        if (!isEmail(email) || !/^\d{6}$/.test(code)) {
            return res.status(400).json({ success: false, message: 'Enter your email and the 6-digit code.' });
        }

        if (!(await consumeCode(email, role, 'verify', code))) {
            return res.status(400).json({ success: false, message: 'The code is wrong or has expired. Request a new one.' });
        }

        const { error } = await supabase.from(tableFor(role)).update({ email_verified: true }).eq('email', email);
        if (error) return res.status(500).json({ success: false, message: 'Could not verify. Please try again.' });

        res.status(200).json({ success: true, message: 'Email verified. You can now log in.' });
    } catch (err) {
        console.error('VERIFY EMAIL ERROR:', err);
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

// ---- Driver profile, photo, QR code ----

// What a passenger may know about a driver. The photo is shown only after the administrator approved it.
async function driverPublicProfile(driverId) {
    const { data: d } = await supabase
        .from('drivers')
        .select('id, full_name, toda_body_number, vehicle_model, plate_number, photo, photo_status, is_verified')
        .eq('id', driverId).maybeSingle();
    if (!d) return null;

    const { data: rated } = await supabase
        .from('bookings').select('rating').eq('driver_id', driverId).not('rating', 'is', null);
    const { count } = await supabase
        .from('bookings').select('id', { count: 'exact', head: true }).eq('driver_id', driverId).eq('status', 'COMPLETED');

    const n = (rated || []).length;
    const total = (rated || []).reduce((sum, r) => sum + r.rating, 0);

    return {
        id: d.id,
        full_name: d.full_name,
        toda_body_number: d.toda_body_number,
        vehicle_model: d.vehicle_model,
        plate_number: d.plate_number,
        is_verified: d.is_verified === true,
        photo_status: d.photo_status,
        photo: d.photo_status === 'APPROVED' ? d.photo : null,
        avg_rating: n ? parseFloat((total / n).toFixed(2)) : null,
        rating_count: n,
        trips: count || 0
    };
}

app.get('/drivers/:id/profile', requireAuth('passenger'), async (req, res) => {
    try {
        const profile = await driverPublicProfile(req.params.id);
        if (!profile) return res.status(404).json({ success: false, message: 'Driver not found.' });
        res.status(200).json({ success: true, driver: profile });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// The driver's own profile, including their photo even while it waits for approval
app.get('/driver/me', requireAuth('driver'), async (req, res) => {
    try {
        const profile = await driverPublicProfile(req.auth.sub);
        if (!profile) return res.status(404).json({ success: false, message: 'Driver not found.' });

        const { data: own } = await supabase.from('drivers').select('photo').eq('id', req.auth.sub).maybeSingle();
        res.status(200).json({ success: true, driver: { ...profile, photo: own ? own.photo : null } });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.post('/driver/profile', requireAuth('driver'), rateLimit('driverprofile', 20, 60 * 60 * 1000), async (req, res) => {
    try {
        const update = {};

        if (req.body.plate_number !== undefined) {
            update.plate_number = cleanText(req.body.plate_number, 12).toUpperCase() || null;
        }

        if (req.body.photo) {
            const photo = String(req.body.photo);
            const m = /^data:image\/jpeg;base64,([A-Za-z0-9+/=]+)$/.exec(photo);
            if (!m || photo.length > 200000) {
                return res.status(400).json({ success: false, message: 'The photo must be a small JPEG image.' });
            }
            const bytes = Buffer.from(m[1], 'base64');
            if (bytes.length < 1000 || bytes[0] !== 0xff || bytes[1] !== 0xd8) {
                return res.status(400).json({ success: false, message: 'That file is not a valid JPEG photo.' });
            }
            update.photo = photo;
            update.photo_status = 'PENDING';
        }

        if (Object.keys(update).length === 0) {
            return res.status(400).json({ success: false, message: 'Nothing to save.' });
        }

        const { error } = await supabase.from('drivers').update(update).eq('id', req.auth.sub);
        if (error) return res.status(400).json({ success: false, message: 'Could not save your profile.' });

        res.status(200).json({
            success: true,
            message: update.photo ? 'Saved. Your photo is waiting for administrator approval.' : 'Saved.'
        });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// A QR code that lasts 5 minutes. A passenger scans it to confirm who the driver really is.
app.get('/driver/qr', requireAuth('driver'), async (req, res) => {
    try {
        const { data: driver } = await supabase.from('drivers').select('is_verified').eq('id', req.auth.sub).maybeSingle();
        if (!driver || !driver.is_verified) {
            return res.status(403).json({ success: false, message: 'Your account is not verified.' });
        }
        const token = signToken({ sub: req.auth.sub, role: 'qr' }, 300);
        res.status(200).json({ success: true, code: 'ISABEL:' + token, expires_in: 300 });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.post('/verify-driver', requireAuth('passenger'), rateLimit('verifyqr', 60, 60 * 60 * 1000), async (req, res) => {
    try {
        const raw = String(req.body.code || '');
        if (!raw.startsWith('ISABEL:')) {
            return res.status(400).json({ success: false, message: 'This is not an Isabel-Xpress driver QR code.' });
        }

        const payload = verifyToken(raw.slice(7));
        if (!payload || payload.role !== 'qr') {
            return res.status(400).json({ success: false, message: 'This QR code is invalid or expired. Ask the driver to refresh it.' });
        }

        const profile = await driverPublicProfile(payload.sub);
        if (!profile) return res.status(404).json({ success: false, message: 'Driver not found.' });

        res.status(200).json({ success: true, driver: profile });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// ---- Driver earnings (cash trips, Philippine time) ----

app.get('/my/earnings', requireAuth('driver'), async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('bookings').select('fare, completed_at')
            .eq('driver_id', req.auth.sub).eq('status', 'COMPLETED').limit(5000);
        if (error) return res.status(400).json({ success: false, message: 'Could not load earnings.' });

        const offset = 8 * 60 * 60 * 1000;                        // UTC+8
        const nowPh = new Date(Date.now() + offset);
        const dayStart = Date.UTC(nowPh.getUTCFullYear(), nowPh.getUTCMonth(), nowPh.getUTCDate()) - offset;
        const weekStart = dayStart - ((nowPh.getUTCDay() + 6) % 7) * 24 * 60 * 60 * 1000;   // Monday

        const out = { today_trips: 0, today_total: 0, week_trips: 0, week_total: 0, all_trips: 0, all_total: 0 };
        for (const b of data || []) {
            const fare = Number(b.fare) || 0;
            const t = b.completed_at ? new Date(b.completed_at).getTime() : 0;
            out.all_trips += 1; out.all_total += fare;
            if (t >= weekStart) { out.week_trips += 1; out.week_total += fare; }
            if (t >= dayStart) { out.today_trips += 1; out.today_total += fare; }
        }
        for (const k of ['today_total', 'week_total', 'all_total']) out[k] = parseFloat(out[k].toFixed(2));

        res.status(200).json({ success: true, earnings: out });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// ---- Announcements ----

app.get('/announcements/latest', requireAuth(), async (req, res) => {
    try {
        const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
        const { data } = await supabase
            .from('announcements').select('id, message, created_at')
            .gte('created_at', since).order('created_at', { ascending: false }).limit(1);
        res.status(200).json({ success: true, announcement: data && data.length ? data[0] : null });
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
            .select('id, full_name, email, toda_body_number, vehicle_model, plate_number, photo_status, email_verified, is_online, is_verified, verified_at, created_at')
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

        logAdmin(verified ? 'DRIVER_VERIFIED' : 'DRIVER_SUSPENDED', data[0].full_name);
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
        logAdmin('REPORT_RESOLVED', req.params.id);
        res.status(200).json({ success: true, message: 'Report marked as resolved' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// ---- Admin: edit / delete drivers and passengers ----

const cleanText = (v, max) => String(v === undefined || v === null ? '' : v).trim().slice(0, max);

app.patch('/admin/api/drivers/:id', requireAdmin, async (req, res) => {
    try {
        const update = {};

        if (req.body.full_name !== undefined) {
            const v = cleanText(req.body.full_name, 100);
            if (!v) return res.status(400).json({ success: false, message: 'Name cannot be empty.' });
            update.full_name = v;
        }
        if (req.body.email !== undefined) {
            const v = normalizeEmail(req.body.email);
            if (!isEmail(v)) return res.status(400).json({ success: false, message: 'Enter a valid email address.' });
            update.email = v;
        }
        if (req.body.toda_body_number !== undefined) {
            const v = cleanText(req.body.toda_body_number, 20);
            if (!v) return res.status(400).json({ success: false, message: 'Body number cannot be empty.' });
            update.toda_body_number = v;
        }
        if (req.body.vehicle_model !== undefined) {
            update.vehicle_model = cleanText(req.body.vehicle_model, 60) || null;
        }
        if (Object.keys(update).length === 0) {
            return res.status(400).json({ success: false, message: 'Nothing to update.' });
        }

        const { data, error } = await supabase
            .from('drivers').update(update).eq('id', req.params.id)
            .select('id, full_name, email, toda_body_number, vehicle_model');

        if (error) return res.status(400).json({ success: false, message: 'Could not save. That email may already be used.' });
        if (!data || data.length === 0) return res.status(404).json({ success: false, message: 'Driver not found.' });
        logAdmin('DRIVER_EDITED', data[0].full_name + ' (' + Object.keys(update).join(', ') + ')');
        res.status(200).json({ success: true, message: 'Driver updated', driver: data[0] });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.delete('/admin/api/drivers/:id', requireAdmin, async (req, res) => {
    try {
        const { data: active } = await supabase
            .from('bookings').select('id').eq('driver_id', req.params.id).eq('status', 'ACCEPTED').limit(1);
        if (active && active.length > 0) {
            return res.status(409).json({ success: false, message: 'This driver is on a trip. Cancel that booking first.' });
        }

        const { data, error } = await supabase.from('drivers').delete().eq('id', req.params.id).select('id');

        if (error) {
            return res.status(409).json({ success: false, message: 'This driver has trip or report records and cannot be deleted. Use Suspend instead.' });
        }
        if (!data || data.length === 0) return res.status(404).json({ success: false, message: 'Driver not found.' });

        driverSockets.delete(req.params.id);
        io.emit('driver_offline', { driverId: req.params.id });
        logAdmin('DRIVER_DELETED', req.params.id);
        res.status(200).json({ success: true, message: 'Driver deleted' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.get('/admin/api/passengers', requireAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('passengers').select('id, full_name, email, email_verified, created_at').order('created_at', { ascending: false });
        if (error) return res.status(400).json({ success: false, message: error.message });
        res.status(200).json({ success: true, passengers: data });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.patch('/admin/api/passengers/:id', requireAdmin, async (req, res) => {
    try {
        const update = {};

        if (req.body.full_name !== undefined) {
            const v = cleanText(req.body.full_name, 100);
            if (!v) return res.status(400).json({ success: false, message: 'Name cannot be empty.' });
            update.full_name = v;
        }
        if (req.body.email !== undefined) {
            const v = normalizeEmail(req.body.email);
            if (!isEmail(v)) return res.status(400).json({ success: false, message: 'Enter a valid email address.' });
            update.email = v;
        }
        if (Object.keys(update).length === 0) {
            return res.status(400).json({ success: false, message: 'Nothing to update.' });
        }

        const { data, error } = await supabase
            .from('passengers').update(update).eq('id', req.params.id).select('id, full_name, email');

        if (error) return res.status(400).json({ success: false, message: 'Could not save. That email may already be used.' });
        if (!data || data.length === 0) return res.status(404).json({ success: false, message: 'Passenger not found.' });
        logAdmin('PASSENGER_EDITED', data[0].full_name + ' (' + Object.keys(update).join(', ') + ')');
        res.status(200).json({ success: true, message: 'Passenger updated', passenger: data[0] });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.delete('/admin/api/passengers/:id', requireAdmin, async (req, res) => {
    try {
        const { data: active } = await supabase
            .from('bookings').select('id').eq('passenger_id', req.params.id).in('status', ['PENDING', 'ACCEPTED']).limit(1);
        if (active && active.length > 0) {
            return res.status(409).json({ success: false, message: 'This passenger has an active booking. Cancel it first.' });
        }

        const { data, error } = await supabase.from('passengers').delete().eq('id', req.params.id).select('id');

        if (error) {
            return res.status(409).json({ success: false, message: 'This passenger has trip or report records and cannot be deleted.' });
        }
        if (!data || data.length === 0) return res.status(404).json({ success: false, message: 'Passenger not found.' });
        logAdmin('PASSENGER_DELETED', req.params.id);
        res.status(200).json({ success: true, message: 'Passenger deleted' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// Cancel a booking that is stuck (for example a driver's phone died mid-trip)
app.post('/admin/api/bookings/:id/cancel', requireAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('bookings')
            .update({ status: 'CANCELLED', cancelled_at: new Date().toISOString() })
            .eq('id', req.params.id)
            .in('status', ['PENDING', 'ACCEPTED'])
            .select();

        if (error) return res.status(400).json({ success: false, message: 'Could not cancel the booking.' });
        if (!data || data.length === 0) {
            return res.status(409).json({ success: false, message: 'Only waiting or in-progress bookings can be cancelled.' });
        }

        const b = data[0];
        io.to(`booking:${b.id}`).emit('booking_cancelled', { id: b.id });
        io.to(`passenger:${b.passenger_id}`).emit('booking_cancelled', { id: b.id });
        io.to('drivers').emit('booking_taken', { id: b.id });
        logAdmin('BOOKING_CANCELLED', (b.passenger_name || '') + ': ' + (b.pickup_name || '') + ' to ' + (b.destination_name || ''));
        res.status(200).json({ success: true, message: 'Booking cancelled' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.delete('/admin/api/reports/:id', requireAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase.from('reports').delete().eq('id', req.params.id).select('id');
        if (error) return res.status(400).json({ success: false, message: 'Could not delete the report.' });
        if (!data || data.length === 0) return res.status(404).json({ success: false, message: 'Report not found.' });
        logAdmin('REPORT_DELETED', req.params.id);
        res.status(200).json({ success: true, message: 'Report deleted' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// ---- Admin: driver photo review ----

app.get('/admin/api/drivers/:id/photo', requireAdmin, async (req, res) => {
    try {
        const { data } = await supabase
            .from('drivers').select('full_name, plate_number, photo, photo_status').eq('id', req.params.id).maybeSingle();
        if (!data) return res.status(404).json({ success: false, message: 'Driver not found.' });
        res.status(200).json({ success: true, driver: data });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.post('/admin/api/drivers/:id/photo-review', requireAdmin, async (req, res) => {
    try {
        const approve = req.body.approve === true;
        const { data, error } = await supabase
            .from('drivers').update({ photo_status: approve ? 'APPROVED' : 'REJECTED' })
            .eq('id', req.params.id).not('photo', 'is', null).select('full_name');
        if (error) return res.status(400).json({ success: false, message: 'Could not save the review.' });
        if (!data || data.length === 0) return res.status(404).json({ success: false, message: 'This driver has no photo.' });
        logAdmin(approve ? 'PHOTO_APPROVED' : 'PHOTO_REJECTED', data[0].full_name);
        res.status(200).json({ success: true, message: approve ? 'Photo approved' : 'Photo rejected' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// ---- Admin: announcements to drivers ----

app.get('/admin/api/announcements', requireAdmin, async (req, res) => {
    try {
        const { data } = await supabase
            .from('announcements').select('*').order('created_at', { ascending: false }).limit(30);
        res.status(200).json({ success: true, announcements: data || [] });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.post('/admin/api/announcements', requireAdmin, async (req, res) => {
    try {
        const message = cleanText(req.body.message, 200);
        if (!message) return res.status(400).json({ success: false, message: 'Type a message first.' });

        const { error } = await supabase.from('announcements').insert([{ message }]);
        if (error) return res.status(400).json({ success: false, message: 'Could not save the announcement.' });

        io.to('drivers').emit('announcement', { message });
        logAdmin('ANNOUNCEMENT', message);
        res.status(200).json({ success: true, message: 'Sent to all online drivers' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.delete('/admin/api/announcements/:id', requireAdmin, async (req, res) => {
    try {
        const { error } = await supabase.from('announcements').delete().eq('id', req.params.id);
        if (error) return res.status(400).json({ success: false, message: 'Could not delete.' });
        res.status(200).json({ success: true, message: 'Announcement deleted' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// ---- Admin: activity log and dashboard numbers ----

app.get('/admin/api/logs', requireAdmin, async (req, res) => {
    try {
        const { data } = await supabase
            .from('admin_logs').select('*').order('created_at', { ascending: false }).limit(200);
        res.status(200).json({ success: true, logs: data || [] });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});

app.get('/admin/api/stats', requireAdmin, async (req, res) => {
    try {
        const { data: rows, error } = await supabase
            .from('bookings')
            .select('status, fare, pickup_name, destination_name, driver_id, driver_name, rating, created_at')
            .order('created_at', { ascending: false }).limit(3000);
        if (error) return res.status(400).json({ success: false, message: error.message });

        const offset = 8 * 60 * 60 * 1000;
        const dayKey = (iso) => new Date(new Date(iso).getTime() + offset).toISOString().slice(0, 10);

        // Last 14 days (Philippine time), oldest first
        const days = [];
        for (let i = 13; i >= 0; i--) {
            days.push(new Date(Date.now() + offset - i * 24 * 60 * 60 * 1000).toISOString().slice(0, 10));
        }
        const perDay = Object.fromEntries(days.map((d) => [d, { date: d, completed: 0, cancelled: 0 }]));

        const routes = {};
        const pickups = {};
        const byDriver = {};
        let revenue = 0, completed = 0, cancelled = 0;

        for (const b of rows || []) {
            const k = b.created_at ? dayKey(b.created_at) : null;
            if (b.status === 'COMPLETED') {
                completed += 1;
                revenue += Number(b.fare) || 0;
                if (k && perDay[k]) perDay[k].completed += 1;

                const route = (b.pickup_name || '-') + ' to ' + (b.destination_name || '-');
                routes[route] = (routes[route] || 0) + 1;
                pickups[b.pickup_name || '-'] = (pickups[b.pickup_name || '-'] || 0) + 1;

                if (b.driver_id) {
                    const d = byDriver[b.driver_id] || (byDriver[b.driver_id] = { name: b.driver_name || '-', trips: 0, sum: 0, n: 0 });
                    d.trips += 1;
                    if (b.rating) { d.sum += b.rating; d.n += 1; }
                }
            } else if (b.status === 'CANCELLED') {
                cancelled += 1;
                if (k && perDay[k]) perDay[k].cancelled += 1;
            }
        }

        const top = (obj, n) => Object.entries(obj).sort((a, b) => b[1] - a[1]).slice(0, n).map(([label, count]) => ({ label, count }));

        res.status(200).json({
            success: true,
            totals: { completed, cancelled, revenue: parseFloat(revenue.toFixed(2)) },
            perDay: days.map((d) => perDay[d]),
            topRoutes: top(routes, 5),
            topPickups: top(pickups, 5),
            drivers: Object.values(byDriver)
                .map((d) => ({ name: d.name, trips: d.trips, avg_rating: d.n ? parseFloat((d.sum / d.n).toFixed(2)) : null, rating_count: d.n }))
                .sort((a, b) => b.trips - a.trips).slice(0, 10)
        });
    } catch (err) {
        console.error('STATS ERROR:', err);
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
    if (!payload || !['passenger', 'driver'].includes(payload.role)) return next(new Error('unauthorized'));
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
