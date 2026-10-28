require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const { createClient } = require('@supabase/supabase-js');
const { Resend } = require('resend');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

// 1. Initialize Clients
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const resend = new Resend(process.env.RESEND_API_KEY);

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

// 4. Forgot Password Endpoint (Using Resend HTTPS API)
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: 'Email is required.' });
    }

    try {
        const { data, error } = await supabase
            .from('passengers')
            .select('*')
            .eq('email', email)
            .single();

        if (error || !data) {
            return res.status(404).json({ success: false, message: 'Email not found in database' });
        }

        const resetLink = `https://isabel-xpress-backend.onrender.com/reset-password?email=${encodeURIComponent(email)}`;

        const response = await resend.emails.send({
            from: 'onboarding@resend.dev',
            to: email,
            subject: 'Password Reset - Isabel Xpress',
            html: `<h3>Password Reset Request</h3>
                   <p>Click the link below to reset your password:</p>
                   <a href="${resetLink}">Reset Password</a>
                   <p>If you didn't request this, please ignore this email.</p>`
        });

        if (response.error) {
            return res.status(500).json({ success: false, message: response.error.message });
        }

        res.status(200).json({ success: true, message: 'Password reset link sent to your email.' });
    } catch (err) {
        console.error('Email error:', err);
        res.status(500).json({ success: false, message: 'Email error: ' + err.message });
    }
});

// 5. Reset Password Web View (GET)
app.get('/reset-password', (req, res) => {
    const email = req.query.email;
    res.send(`
        <html>
            <head><title>Reset Password - Isabel Xpress</title></head>
            <body style="font-family: Arial; padding: 40px; text-align: center;">
                <h2>Reset Your Password</h2>
                <form action="/reset-password" method="POST">
                    <input type="hidden" name="email" value="${email}" />
                    <input type="password" name="newPassword" placeholder="Enter new password" required style="padding: 10px; width: 250px;" /><br><br>
                    <button type="submit" style="padding: 10px 20px; background: #007BFF; color: white; border: none; cursor: pointer;">Update Password</button>
                </form>
            </body>
        </html>
    `);
});

// 6. Handle Password Update Submission (POST)
app.post('/reset-password', async (req, res) => {
    const { email, newPassword } = req.body;

    try {
        const { error } = await supabase
            .from('passengers')
            .update({ password: newPassword })
            .eq('email', email);

        if (error) {
            return res.status(400).send('Failed to update password.');
        }

        res.send('<h3 style="color: green; text-align: center; margin-top: 50px;">Password updated successfully! You can now log in to the mobile app.</h3>');
    } catch (err) {
        res.status(500).send('Server error.');
    }
});

// 7. Get Landmarks Endpoint
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

// 8. Calculate Fare Endpoint
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

// 9. Start Server
const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});
