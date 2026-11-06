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
