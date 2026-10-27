require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

// 1. Initialize Supabase Client using .env
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// 2. Initialize Nodemailer Transporter using .env
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// ==========================================
// ROUTE 1: USER REGISTRATION + CONFIRMATION EMAIL
// ==========================================
app.post('/api/register', async (req, res) => {
    const { email, password, fullName } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        // Check if user already exists in Supabase
        const { data: existingUser } = await supabase
            .from('passengers')
            .select('email')
            .eq('email', email)
            .single();

        if (existingUser) {
            return res.status(400).json({ error: 'Email is already registered' });
        }

        // Insert new user into Supabase 'passengers' table
        const { error: dbError } = await supabase
            .from('passengers')
            .insert([{ email, password, full_name: fullName }]);

        if (dbError) throw dbError;

        // Send Registration Confirmation Email
        const mailOptions = {
            from: `Isabel-Xpress Support <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Welcome to Isabel-Xpress!',
            html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; line-height: 1.6;">
          <h2 style="color: #003366;">Registration Successful!</h2>
          <p>Hello <b>${fullName || 'Passenger'}</b>,</p>
          <p>Thank you for registering with <b>Isabel-Xpress</b>. Your account with email address <b>${email}</b> is now active.</p>
          <p>You can now log in to the app and start booking your rides!</p>
        </div>
      `
        };

        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: 'Registration successful! Confirmation email sent.' });

    } catch (error) {
        console.error('Registration Error:', error);
        res.status(500).json({ error: 'Server error during registration' });
    }
});

// ==========================================
// ROUTE 2: FORGOT PASSWORD (SUPABASE DB CHECK)
// ==========================================
app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email is required' });
    }

    try {
        // Query Supabase to ensure email actually exists
        const { data: user, error: dbError } = await supabase
            .from('passengers')
            .select('email')
            .eq('email', email)
            .single();

        if (dbError || !user) {
            return res.status(404).json({ error: 'Email not registered in system' });
        }

        // Generate web reset link for this email
        const resetLink = `http://10.0.2.2:5000/reset-password?email=${encodeURIComponent(email)}`;

        const mailOptions = {
            from: `Isabel-Xpress Support <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Isabel-Xpress Password Reset Request',
            html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; line-height: 1.6;">
          <h2 style="color: #003366;">Reset Password Request</h2>
          <p>We received a password reset request for registered account: <b>${email}</b>.</p>
          <p>Click the button below to update your password:</p>
          <a href="${resetLink}" style="background-color: #2E7D32; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">Reset Password</a>
        </div>
      `
        };

        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: 'Reset email sent successfully' });

    } catch (error) {
        console.error('Forgot Password Error:', error);
        res.status(500).json({ error: 'Server error processing request' });
    }
});

// ==========================================
// ROUTE 3: RESET PASSWORD WEB PAGE
// ==========================================
app.get('/reset-password', (req, res) => {
    const email = req.query.email;
    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Reset Password - Isabel-Xpress</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body { font-family: Arial, sans-serif; background-color: #FAFAFA; padding: 40px; display: flex; justify-content: center; }
        .card { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }
        h2 { color: #003366; text-align: center; }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background-color: #2E7D32; color: white; border: none; border-radius: 4px; font-weight: bold; cursor: pointer; margin-top: 10px; }
      </style>
    </head>
    <body>
      <div class="card">
        <h2>Reset Password</h2>
        <p style="text-align: center; color: #666;">Account: <b>${email}</b></p>
        <form action="/reset-password-submit" method="POST">
          <input type="hidden" name="email" value="${email}" />
          <input type="password" name="newPassword" placeholder="New Password" required />
          <input type="password" name="confirmPassword" placeholder="Confirm New Password" required />
          <button type="submit">Update Password</button>
        </form>
      </div>
    </body>
    </html>
  `);
});

// ==========================================
// ROUTE 4: SUBMIT NEW PASSWORD TO SUPABASE
// ==========================================
app.post('/reset-password-submit', async (req, res) => {
    const { email, newPassword, confirmPassword } = req.body;

    if (newPassword !== confirmPassword) {
        return res.send("<script>alert('Passwords do not match!'); window.history.back();</script>");
    }

    try {
        const { error: updateError } = await supabase
            .from('passengers')
            .update({ password: newPassword })
            .eq('email', email);

        if (updateError) throw updateError;

        res.send(`
      <div style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
        <h2 style="color: #2E7D32;">Password Updated Successfully!</h2>
        <p>You can now open your Isabel-Xpress app and log in with your new password for <b>${email}</b>.</p>
      </div>
    `);
    } catch (error) {
        console.error('Password Update Error:', error);
        res.status(500).send("Server error updating password.");
    }
});

app.listen(5000, () => {
    console.log('Server running on http://localhost:5000');
});