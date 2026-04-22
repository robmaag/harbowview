require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();

app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true }));

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// API Routes
app.use('/api/auth',         require('./routes/auth'));
app.use('/api/units',        require('./routes/units'));
app.use('/api/applications', require('./routes/applications'));
app.use('/api/leases',       require('./routes/leases'));
app.use('/api/invoices',     require('./routes/invoices'));
app.use('/api/payments',     require('./routes/payments'));
app.use('/api/maintenance',  require('./routes/maintenance'));
app.use('/api/documents',    require('./routes/documents'));
app.use('/api/admin',        require('./routes/admin'));

app.use((err, req, res, next) => {
  res.status(500).json({ success: false, message: err.message });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Server running on port ' + PORT));
module.exports = app;
