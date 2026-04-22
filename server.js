// routes/auth.js — Register, Login, Profile
const router  = require('express').Router();
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const db      = require('../database/db');
const { requireAuth } = require('../middleware/auth');

const makeToken = (userId) =>
  jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });

// POST /api/auth/register
router.post('/register', async (req, res) => {
  try {
    const { first_name, last_name, email, password, phone, unit_number } = req.body;
    if (!first_name || !last_name || !email || !password)
      return res.status(400).json({ success: false, message: 'Required fields missing' });

    const [exists] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
    if (exists.length)
      return res.status(409).json({ success: false, message: 'Email already registered' });

    const hash = await bcrypt.hash(password, 12);
    const [result] = await db.query(
      'INSERT INTO users (first_name, last_name, email, password_hash, phone) VALUES (?,?,?,?,?)',
      [first_name, last_name, email, hash, phone || null]
    );
    const token = makeToken(result.insertId);
    res.status(201).json({ success: true, token, user: { id: result.insertId, first_name, last_name, email, role: 'tenant' } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// POST /api/auth/login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [rows] = await db.query('SELECT * FROM users WHERE email = ? AND is_active = 1', [email]);
    if (!rows.length) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    const token = makeToken(user.id);
    const { password_hash, ...safe } = user;
    res.json({ success: true, token, user: safe });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/auth/me
router.get('/me', requireAuth, async (req, res) => {
  try {
    // Also fetch active lease info
    const [lease] = await db.query(
      `SELECT l.*, u.unit_number, u.building_name, u.floor
       FROM leases l JOIN units u ON l.unit_id = u.id
       WHERE l.tenant_id = ? AND l.status = 'active' LIMIT 1`,
      [req.user.id]
    );
    res.json({ success: true, user: req.user, lease: lease[0] || null });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// PUT /api/auth/profile
router.put('/profile', requireAuth, async (req, res) => {
  try {
    const { first_name, last_name, phone } = req.body;
    await db.query('UPDATE users SET first_name=?, last_name=?, phone=? WHERE id=?',
      [first_name, last_name, phone, req.user.id]);
    res.json({ success: true, message: 'Profile updated' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// PUT /api/auth/password
router.put('/password', requireAuth, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    const [rows] = await db.query('SELECT password_hash FROM users WHERE id=?', [req.user.id]);
    const valid = await bcrypt.compare(current_password, rows[0].password_hash);
    if (!valid) return res.status(400).json({ success: false, message: 'Current password incorrect' });
    const hash = await bcrypt.hash(new_password, 12);
    await db.query('UPDATE users SET password_hash=? WHERE id=?', [hash, req.user.id]);
    res.json({ success: true, message: 'Password updated' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
