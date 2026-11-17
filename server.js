require('dotenv').config();
const express = require('express');
const http = require('http');
const bcrypt = require('bcryptjs');
const { Server } = require('socket.io');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PASSWORD_MESSAGE =
    'Password must be at least 12 characters long and include a number, capital letter, and special character (@#$%^&+=!_).';

const isValidPassword = (password) => {
    const regex = /^(?=.*\d)(?=.*[A-Z])(?=.*[@#$%^&+=!_]).{12,}$/;
    return typeof password === 'string' && regex.test(password);
};

const hashPassword = (plain) => bcrypt.hash(plain, 10);

// Supports old plain-text rows: if the stored value is not a bcrypt hash,
// compare directly and upgrade the row to a hash on success.
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

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------
app.get('/', (req, res) => {
    res.status(200).json({ success: true, message: 'Isabel-Xpress backend is running' });
});

// ---------------------------------------------------------------------------
// Passenger
// ---------------------------------------------------------------------------

app.post('/register', async (req, res) => {
    try {
        const { full_name, fullName, email, password } = req.body;
        const nameToSave = fullName || full_name;

        if (!nameToSave || !email || !password) {
            return res.status(400).json({ success: false, message: 'All fields are required.' });
        }
        if (!isValidPassword(password)) {
            return res.status(400).json({ success: false, message: PASSWORD_MESSAGE });
        }

        const { error } = await supabase
            .from('passengers')
            .insert([{ full_name: nameToSave, email, password: await hashPassword(password) }]);

        if (error) {
            console.error('PASSENGER INSERT ERROR:', error);
            return res.status(400).json({ success: false, message: error.message });
        }

        res.status(200).json({ success: true, message: 'User registered successfully!' });
    } catch (err) {
        console.error('PASSENGER REGISTER ERROR:', err);
        res.status(500).json({ success: false, message: 'Server error: ' + err.message });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password are required.' });
        }

        const { data, error } = await supabase
            .from('passengers')
            .select('*')
            .eq('email', email)
            .maybeSingle();

        if (error) {
            console.error('PASSENGER LOGIN ERROR:', error);
            return res.status(500).json({ success: false, message: 'Server error.' });
        }

        if (!data || !(await verifyPassword('passengers', data, password))) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        res.status(200).json({ success: true, message: 'Login successful', user: stripPassword(data) });
    } catch (err) {
        console.error('PASSENGER LOGIN CRASH:', err);
        res.status(500).json({ success: false, message: 'Server error: ' + err.message });
    }
});

// WARNING: anyone who knows an email can change that account's password.
// Replace with an emailed-code flow before real users rely on this app.
app.post('/reset-password-direct', async (req, res) => {
    try {
        const { email, newPassword } = req.body;

        if (!email || !newPassword) {
            return res.status(400).json({ success: false, message: 'Email and new password are required.' });
        }
        if (!isValidPassword(newPassword)) {
            return res.status(400).json({ success: false, message: PASSWORD_MESSAGE });
        }

        const { data: user } = await supabase
            .from('passengers')
            .select('id')
            .eq('email', email)
            .maybeSingle();

        if (!user) {
            return res.status(404).json({ success: false, message: 'This email is not registered.' });
        }

        const { error: updateError } = await supabase
            .from('passengers')
            .update({ password: await hashPassword(newPassword) })
            .eq('id', user.id);

        if (updateError) {
            return res.status(400).json({ success: false, message: 'Failed to update password.' });
        }

        res.status(200).json({ success: true, message: 'Password updated successfully!' });
    } catch (err) {
        console.error('PASSENGER RESET ERROR:', err);
        res.status(500).json({ success: false, message: 'Server error: ' + err.message });
    }
});

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

app.post('/driver-register', async (req, res) => {
    try {
        const { full_name, fullName, email, password, toda_body_number, bodyNumber } = req.body;
        const nameToSave = fullName || full_name;
        const bodyToSave = bodyNumber || toda_body_number;

        if (!nameToSave || !email || !password || !bodyToSave) {
            return res.status(400).json({ success: false, message: 'All fields are required.' });
        }
        if (!isValidPassword(password)) {
            return res.status(400).json({ success: false, message: PASSWORD_MESSAGE });
        }

        const { data, error } = await supabase
            .from('drivers')
            .insert([{
                full_name: nameToSave,
                email: email,
                password: await hashPassword(password),
                toda_body_number: bodyToSave,
                is_online: false
            }])
            .select();

        if (error) {
            console.error('SUPABASE INSERT ERROR:', error);
            return res.status(400).json({ success: false, message: error.message });
        }

        res.status(200).json({
            success: true,
            message: 'Driver registered successfully',
            user: stripPassword(data[0])
        });
    } catch (err) {
        console.error('SERVER CRASH ERROR:', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/driver-login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password are required.' });
        }

        const { data, error } = await supabase
            .from('drivers')
            .select('*')
            .eq('email', email)
            .maybeSingle();

        if (error) {
            console.error('DRIVER LOGIN ERROR:', error);
            return res.status(500).json({ success: false, message: 'Server error.' });
        }

        if (!data || !(await verifyPassword('drivers', data, password))) {
            return res.status(401).json({ success: false, message: 'Invalid driver credentials' });
        }

        res.status(200).json({ success: true, message: 'Login successful', user: stripPassword(data) });
    } catch (err) {
        console.error('DRIVER LOGIN CRASH:', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// WARNING: same takeover risk as the passenger route. Replace before release.
app.post('/driver-reset-password', async (req, res) => {
    try {
        const { email, newPassword } = req.body;

        if (!email || !newPassword) {
            return res.status(400).json({ success: false, message: 'Email and new password are required.' });
        }
        if (!isValidPassword(newPassword)) {
            return res.status(400).json({ success: false, message: PASSWORD_MESSAGE });
        }

        const { data: user } = await supabase
            .from('drivers')
            .select('id')
            .eq('email', email)
            .maybeSingle();

        if (!user) {
            return res.status(404).json({ success: false, message: 'Driver email is not registered.' });
        }

        const { error: updateError } = await supabase
            .from('drivers')
            .update({ password: await hashPassword(newPassword) })
            .eq('id', user.id);

        if (updateError) {
            return res.status(400).json({ success: false, message: 'Failed to update driver password.' });
        }

        res.status(200).json({ success: true, message: 'Driver password updated successfully!' });
    } catch (err) {
        console.error('DRIVER RESET ERROR:', err);
        res.status(500).json({ success: false, message: 'Server error: ' + err.message });
    }
});

app.post('/driver-status', async (req, res) => {
    try {
        const { driverId, isOnline } = req.body;

        if (driverId === undefined || typeof isOnline !== 'boolean') {
            return res.status(400).json({ success: false, message: 'driverId and isOnline (true/false) are required.' });
        }

        const { error } = await supabase
            .from('drivers')
            .update({ is_online: isOnline })
            .eq('id', driverId);

        if (error) return res.status(400).json({ success: false, message: error.message });
        res.status(200).json({ success: true, message: 'Status updated successfully' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/available-drivers', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('drivers')
            .select('id, full_name, toda_body_number, is_online')
            .eq('is_online', true);

        if (error) return res.status(400).json({ success: false, message: error.message });
        res.status(200).json({ success: true, drivers: data });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ---------------------------------------------------------------------------
// Landmarks and fare
// ---------------------------------------------------------------------------

app.get('/landmarks', async (req, res) => {
    try {
        const { data, error } = await supabase.from('landmarks').select('*');
        if (error) return res.status(400).json({ success: false, message: error.message });
        res.status(200).json(data);
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error: ' + err.message });
    }
});

app.post('/calculate-fare', async (req, res) => {
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

        const R = 6371;
        const toRad = (deg) => deg * (Math.PI / 180);
        const dLat = toRad(destination.latitude - origin.latitude);
        const dLon = toRad(destination.longitude - origin.longitude);
        const a =
            Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(toRad(origin.latitude)) * Math.cos(toRad(destination.latitude)) *
            Math.sin(dLon / 2) * Math.sin(dLon / 2);
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        const distanceKm = R * c;

        let baseFare = 15.0;
        if (distanceKm > 1.0) {
            baseFare += (distanceKm - 1.0) * 8.0;
        }

        const discounted = isDiscounted === true || isDiscounted === 'true';
        const totalFare = discounted ? baseFare * 0.8 : baseFare;

        res.status(200).json({
            distanceKm: parseFloat(distanceKm.toFixed(2)),
            baseFare: parseFloat(baseFare.toFixed(2)),
            totalFare: parseFloat(totalFare.toFixed(2)),
            isDiscounted: discounted
        });
    } catch (err) {
        console.error('FARE ERROR:', err);
        res.status(500).json({ success: false, message: 'Server error: ' + err.message });
    }
});

// ---------------------------------------------------------------------------
// Socket.IO
// ---------------------------------------------------------------------------

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

io.on('connection', (socket) => {
    console.log('Socket connected:', socket.id);

    socket.on('passenger_booking_request', (data) => {
        socket.broadcast.emit('passenger_booking_request', data);
    });

    socket.on('driver_accept_booking', (data) => {
        socket.broadcast.emit('booking_accepted', data);
    });

    socket.on('chat_message', (data) => {
        socket.broadcast.emit('chat_message', data);
    });

    socket.on('location_changed', (data) => {
        socket.broadcast.emit('location_changed', data);
    });

    socket.on('disconnect', () => {
        console.log('Socket disconnected:', socket.id);
    });
});

const PORT = process.env.PORT || 10000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});
