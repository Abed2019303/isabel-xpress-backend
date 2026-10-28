require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

// 1. Initialize Supabase Client
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// 2. Register Endpoint
app.post('/register', async (req, res) => {
    const { full_name, fullName, email, password } = req.body;
    const nameToSave = fullName || full_name;

    if (!nameToSave || !email || !password) {
        return res.status(400).json({ success: false, message: 'All fields are required.' });
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

// 3. Login Endpoint (Supports Username or Email)
app.post('/login', async (req, res) => {
    const { email, username, password } = req.body;
    const identifier = username || email;

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

// 4. Direct In-App Reset Password Endpoint (No Emails Required!)
app.post('/reset-password-direct', async (req, res) => {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
        return res.status(400).json({ success: false, message: 'Email and new password are required.' });
    }

    try {
        // First check if the email exists in Supabase
        const { data: user, error: checkError } = await supabase
            .from('passengers')
            .select('*')
            .eq('email', email)
            .single();

        if (checkError || !user) {
            return res.status(404).json({ success: false, message: 'This email is not registered.' });
        }

        // Update the password directly
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

// 5. Get Landmarks Endpoint
app.get('/landmarks', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('landmarks')
            .select('*');

        if (error) {
            return res.status(400).json({ success: false, message: error.message });
        }

        res.status(200).json(data);
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error: ' + err.message });
    }
});

// 6. Calculate Fare Endpoint
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
        if (isDiscounted) {
            totalFare *= 0.8;
        }

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

// 7. Start Server
const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});
