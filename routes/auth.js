const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../database/db');

const makeToken = (id) => jwt.sign({ userId: id }, process.env.JWT_SECRET || 'secret123', { expiresIn: '7d' });

router.post('/register', async (req, res) => {
  try {
    const { first_name, last_name, email, password, phone } = req.body;
    const [exists] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
    if (exists.length) return res.status(409).json({ success: false, message: 'Email already registered' });
    const hash = await bcrypt.hash(password, 12);
    const [result] = await db.query('INSERT INTO users (first_name, last_name, email, password_hash, phone) VALUES (?,?,?,?,?)', [first_name, last_name, email, hash, phone || null]);
    res.status(201).json({ success: true, token: makeToken(result.insertId), user: { id: result.insertId, first_name, last_name, email, role: 'tenant' } });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [rows] = await db.query('SELECT * FROM users WHERE email = ? AND is_active = 1', [email]);
    if (!rows.length) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, rows[0].password_hash);
    if (!valid) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    const { password_hash, ...safe } = rows[0];
    res.json({ success: true, token: makeToken(rows[0].id), user: safe });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

router.get('/me', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'No token' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    const [rows] = await db.query('SELECT id, first_name, last_name, email, role, phone FROM users WHERE id = ?', [decoded.userId]);
    if (!rows.length) return res.status(401).json({ success: false, message: 'User not found' });
    const [lease] = await db.query("SELECT l.*, u.unit_number, u.building_name FROM leases l JOIN units u ON l.unit_id=u.id WHERE l.tenant_id=? AND l.status='active' LIMIT 1", [decoded.userId]);
    res.json({ success: true, user: rows[0], lease: lease[0] || null });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

router.put('/profile', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    const { first_name, last_name, phone } = req.body;
    await db.query('UPDATE users SET first_name=?, last_name=?, phone=? WHERE id=?', [first_name, last_name, phone, decoded.userId]);
    res.json({ success: true, message: 'Profile updated' });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

router.put('/password', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    const { current_password, new_password } = req.body;
    const [rows] = await db.query('SELECT password_hash FROM users WHERE id=?', [decoded.userId]);
    const valid = await bcrypt.compare(current_password, rows[0].password_hash);
    if (!valid) return res.status(400).json({ success: false, message: 'Current password incorrect' });
    const hash = await bcrypt.hash(new_password, 12);
    await db.query('UPDATE users SET password_hash=? WHERE id=?', [hash, decoded.userId]);
    res.json({ success: true, message: 'Password updated' });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

module.exports = router;
