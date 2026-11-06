require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// Helper function for password complexity validation (min 12 chars, 1 uppercase, 1 number, 1 special char)
const isValidPassword = (password) => {
    const regex = /^(?=.*\d)(?=.*[A-Z])(?=.*[@#$%^&+=!_]).{12,}$/;
    return regex.test(password);
};

// Register Endpoint (Passenger)
app.post('/register', async (req, res) => {
    const { full_name, fullName, email, password } = req.body;
    const nameToSave = fullName || full_name;

    if (!nameToSave || !email || !password) {
        return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    if (!isValidPassword(password)) {
        return res.status(400).json({ 
            success: false, 
            message: 'Password must be at least 12 characters long and include a number, capital letter, and special character.' 
        });
    }

    try {
        const { data, error } = await supabase
            .from('passengers')
            .insert([{ full_name: nameToSave, email, password }]);

        if (error) {
            return res.status(400).json({ success: false, message: error.message });
        }

        res.status(200).json({ success: true, message: 'User registered successfully!' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error: ' + err.message });
    }
});

// Login Endpoint (Passenger - Supports Email or Username lookup)
app.post('/login', async (req, res) => {
    const { email, username, password } = req.body;
    const identifier = email || username;

    if (!identifier || !password) {
        return res.status(400).json({ success: false, message: 'Username/Email and password are required.' });
    }

    try {
        const { data, error } = await supabase
            .from('passengers')
            .select('*')
            .or(`email.eq.${identifier},full_name.eq.${identifier}`)
            .eq('password', password)
            .single();

        if (error || !data) {
            return res.status(400).json({ success: false, message: 'Invalid credentials' });
        }

        res.status(200).json({ success: true, message: 'Login successful', user: data });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error: ' + err.message });
    }
});

// Direct In-App Reset Password
app.post('/reset-password-direct', async (req, res) => {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
        return res.status(400).json({ success: false, message: 'Email and new password are required.' });
    }

    if (!isValidPassword(newPassword)) {
        return res.status(400).json({ 
            success: false, 
            message: 'Password must be at least 12 characters long and include a number, capital letter, and special character.' 
        });
    }

    try {
        const { data: user, error: checkError } = await supabase
            .from('passengers')
            .select('*')
            .eq('email', email)
            .single();

        if (checkError || !user) {
            return res.status(404).json({ success: false, message: 'This email is not registered.' });
        }

        const { error: updateError } = await supabase
            .from('passengers')
            .update({ password: newPassword })
            .eq('email', email);

        if (updateError) {
            return res.status(400).json({ success: false, message: 'Failed to update password.' });
        }

        res.status(200).json({ success: true, message: 'Password updated successfully!' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error: ' + err.message });
    }
});

// Driver Registration Endpoint
app.post('/driver-register', async (req, res) => {
    try {
        const { fullName, email, password, bodyNumber } = req.body;
        const { data, error } = await supabase
            .from('drivers')
            .insert([{ full_name: fullName, email, password, body_number: bodyNumber, is_online: false }])
            .select();

        if (error) return res.status(400).json({ success: false, message: error.message });
        res.status(200).json({ success: true, message: 'Driver registered successfully', user: data[0] });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// Driver Login Endpoint
app.post('/driver-login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const { data, error } = await supabase
            .from('drivers')
            .select('*')
            .eq('email', email)
            .eq('password', password)
            .single();

        if (error || !data) return res.status(401).json({ success: false, message: 'Invalid driver credentials' });
        res.status(200).json({ success: true, message: 'Login successful', user: data });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// Update Driver Online Status
app.post('/driver-status', async (req, res) => {
    try {
        const { driverId, isOnline } = req.body;
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

// Fetch Available Online Drivers for Passengers
app.get('/available-drivers', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('drivers')
            .select('*')
            .eq('is_online', true);

        if (error) return res.status(400).json({ success: false, message: error.message });
        res.status(200).json({ success: true, drivers: data });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// Landmarks Endpoint
app.get('/landmarks', async (req, res) => {
    try {
        const { data, error } = await supabase.from('landmarks').select('*');
        if (error) return res.status(400).json({ success: false, message: error.message });
        res.status(200).json(data);
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error: ' + err.message });
    }
});

// Calculate Fare Endpoint
app.post('/calculate-fare', async (req, res) => {
    const { originLandmarkId, destinationLandmarkId, isDiscounted } = req.body;

    try {
        const { data: landmarks, error } = await supabase
            .from('landmarks')
            .select('*')
            .in('id', [originLandmarkId, destinationLandmarkId]);

        if (error || !landmarks || landmarks.length < 2) {
            return res.status(400).json({ success: false, message: 'Invalid landmarks specified.' });
        }

        const origin = landmarks.find(l => l.id == originLandmarkId);
        const destination = landmarks.find(l => l.id == destinationLandmarkId);

        const R = 6371;
        const dLat = (destination.latitude - origin.latitude) * (Math.PI / 180);
        const dLon = (destination.longitude - origin.longitude) * (Math.PI / 180);
        const a = 
            Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(origin.latitude * (Math.PI / 180)) * Math.cos(destination.latitude * (Math.PI / 180)) * 
            Math.sin(dLon / 2) * Math.sin(dLon / 2);
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        const distanceKm = R * c;

        let baseFare = 15.0;
        if (distanceKm > 1.0) {
            baseFare += (distanceKm - 1.0) * 8.0;
        }

        let totalFare = baseFare;
        if (isDiscounted) totalFare *= 0.8;

        res.status(200).json({
            distanceKm: parseFloat(distanceKm.toFixed(2)),
            baseFare: parseFloat(baseFare.toFixed(2)),
            totalFare: parseFloat(totalFare.toFixed(2)),
            isDiscounted: isDiscounted || false
        });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error: ' + err.message });
    }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});
