require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true }));

// ── Database ──────────────────────────────────────────────────
const pool = mysql.createPool({
  host:     process.env.MYSQLHOST     || 'mysql.railway.internal',
  port:     parseInt(process.env.MYSQLPORT) || 3306,
  database: process.env.MYSQL_DATABASE || 'railway',
  user:     process.env.MYSQLUSER      || 'root',
  password: process.env.MYSQLPASSWORD  || '',
  waitForConnections: true,
  connectionLimit: 10,
});

pool.getConnection()
  .then(c => { console.log('✅ MySQL connected'); c.release(); })
  .catch(e => console.error('❌ MySQL error:', e.message));

// ── Auth helpers ──────────────────────────────────────────────
const SECRET = process.env.JWT_SECRET || 'harborview_secret_2026';
const makeToken = (id) => jwt.sign({ userId: id }, SECRET, { expiresIn: '7d' });
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'No token' });
    const decoded = jwt.verify(token, SECRET);
    const [rows] = await pool.query('SELECT id, first_name, last_name, email, role, phone, is_active FROM users WHERE id = ?', [decoded.userId]);
    if (!rows.length || !rows[0].is_active) return res.status(401).json({ success: false, message: 'User not found' });
    req.user = rows[0];
    next();
  } catch (e) { res.status(401).json({ success: false, message: 'Invalid token' }); }
};
const adminOnly = (req, res, next) => req.user?.role === 'admin' ? next() : res.status(403).json({ success: false, message: 'Admin only' });

// ── File upload ───────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname).toLowerCase())
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ── Health check ──────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date() }));

// ══════════════════════════════════════════════════════════════
// AUTH ROUTES
// ══════════════════════════════════════════════════════════════
app.post('/api/auth/register', async (req, res) => {
  try {
    const { first_name, last_name, email, password, phone } = req.body;
    if (!first_name || !last_name || !email || !password)
      return res.status(400).json({ success: false, message: 'Required fields missing' });
    const [exists] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (exists.length) return res.status(409).json({ success: false, message: 'Email already registered' });
    const hash = await bcrypt.hash(password, 12);
    const [result] = await pool.query(
      'INSERT INTO users (first_name, last_name, email, password_hash, phone) VALUES (?,?,?,?,?)',
      [first_name, last_name, email, hash, phone || null]
    );
    res.status(201).json({ success: true, token: makeToken(result.insertId), user: { id: result.insertId, first_name, last_name, email, role: 'tenant' } });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ? AND is_active = 1', [email]);
    if (!rows.length) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, rows[0].password_hash);
    if (!valid) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    const { password_hash, ...safe } = rows[0];
    res.json({ success: true, token: makeToken(rows[0].id), user: safe });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const [lease] = await pool.query(
      "SELECT l.*, u.unit_number, u.building_name, u.floor FROM leases l JOIN units u ON l.unit_id=u.id WHERE l.tenant_id=? AND l.status='active' LIMIT 1",
      [req.user.id]
    );
    res.json({ success: true, user: req.user, lease: lease[0] || null });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/auth/profile', authMiddleware, async (req, res) => {
  try {
    const { first_name, last_name, phone } = req.body;
    await pool.query('UPDATE users SET first_name=?, last_name=?, phone=? WHERE id=?', [first_name, last_name, phone, req.user.id]);
    res.json({ success: true, message: 'Profile updated' });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/auth/password', authMiddleware, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    const [rows] = await pool.query('SELECT password_hash FROM users WHERE id=?', [req.user.id]);
    const valid = await bcrypt.compare(current_password, rows[0].password_hash);
    if (!valid) return res.status(400).json({ success: false, message: 'Current password incorrect' });
    const hash = await bcrypt.hash(new_password, 12);
    await pool.query('UPDATE users SET password_hash=? WHERE id=?', [hash, req.user.id]);
    res.json({ success: true, message: 'Password updated' });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// UNITS ROUTES
// ══════════════════════════════════════════════════════════════
app.get('/api/units', async (req, res) => {
  try {
    const { status, bedrooms, max_rent } = req.query;
    let sql = `SELECT u.*, (SELECT filepath FROM unit_photos WHERE unit_id=u.id AND is_primary=1 LIMIT 1) AS primary_photo FROM units u WHERE 1=1`;
    const params = [];
    if (status)    { sql += ' AND u.status=?';        params.push(status); }
    if (bedrooms !== undefined && bedrooms !== '') { sql += ' AND u.bedrooms=?'; params.push(bedrooms); }
    if (max_rent)  { sql += ' AND u.monthly_rent<=?'; params.push(max_rent); }
    sql += ' ORDER BY u.monthly_rent ASC';
    const [rows] = await pool.query(sql, params);
    rows.forEach(r => { try { r.amenities = JSON.parse(r.amenities); } catch {} });
    res.json({ success: true, units: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/units/:id', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM units WHERE id=?', [req.params.id]);
    if (!rows.length) return res.status(404).json({ success: false, message: 'Unit not found' });
    const unit = rows[0];
    try { unit.amenities = JSON.parse(unit.amenities); } catch {}
    const [photos] = await pool.query('SELECT * FROM unit_photos WHERE unit_id=? ORDER BY sort_order ASC', [req.params.id]);
    res.json({ success: true, unit, photos });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/units/:id/photos', authMiddleware, adminOnly, upload.array('photos', 20), async (req, res) => {
  try {
    const unitId = req.params.id;
    const [existing] = await pool.query('SELECT COUNT(*) as cnt FROM unit_photos WHERE unit_id=?', [unitId]);
    const inserts = req.files.map((f, i) => [unitId, f.filename, `/uploads/${f.filename}`, null, i, existing[0].cnt === 0 && i === 0 ? 1 : 0]);
    await pool.query('INSERT INTO unit_photos (unit_id,filename,filepath,caption,sort_order,is_primary) VALUES ?', [inserts]);
    res.json({ success: true, message: `${req.files.length} photos uploaded` });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// APPLICATIONS ROUTES
// ══════════════════════════════════════════════════════════════
app.post('/api/applications', async (req, res) => {
  try {
    const fields = ['unit_id','first_name','last_name','email','phone','dob','ssn_last4','current_address','desired_movein','num_occupants','pets','employment_status','employer_name','employer_address','employer_phone','supervisor_name','job_title','employment_start','annual_income','additional_income','prev_address1','prev_rent1','prev_duration1','prev_landlord1','prev_landlord_phone1','prev_reason1','prev_address2','prev_rent2','prev_duration2','prev_landlord2','prev_landlord_phone2','ever_evicted','ever_broken_lease','rental_notes','ref1_name','ref1_relationship','ref1_phone','ref1_email','ref2_name','ref2_relationship','ref2_phone','ref2_email','signature','signed_date'];
    const values = fields.map(f => req.body[f] ?? null);
    const [result] = await pool.query(`INSERT INTO applications (${fields.join(',')}) VALUES (${fields.map(()=>'?').join(',')})`, values);
    res.status(201).json({ success: true, application_id: result.insertId, reference: `HV-${new Date().getFullYear()}-${String(result.insertId).padStart(4,'0')}` });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/applications', authMiddleware, async (req, res) => {
  try {
    let sql = 'SELECT a.*, u.unit_number FROM applications a LEFT JOIN units u ON a.unit_id=u.id WHERE 1=1';
    const params = [];
    if (req.user.role !== 'admin') { sql += ' AND a.email=?'; params.push(req.user.email); }
    sql += ' ORDER BY a.created_at DESC';
    const [rows] = await pool.query(sql, params);
    res.json({ success: true, applications: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// LEASES ROUTES
// ══════════════════════════════════════════════════════════════
app.get('/api/leases', authMiddleware, async (req, res) => {
  try {
    let sql = `SELECT l.*, u.unit_number, u.building_name, u.floor, usr.first_name, usr.last_name FROM leases l JOIN units u ON l.unit_id=u.id JOIN users usr ON l.tenant_id=usr.id WHERE 1=1`;
    const params = [];
    if (req.user.role !== 'admin') { sql += ' AND l.tenant_id=?'; params.push(req.user.id); }
    const [rows] = await pool.query(sql, params);
    res.json({ success: true, leases: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/leases', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { unit_id, tenant_id, lease_start, lease_end, monthly_rent, security_deposit, parking_fee, pet_fee, notes } = req.body;
    const [result] = await pool.query("INSERT INTO leases (unit_id,tenant_id,lease_start,lease_end,monthly_rent,security_deposit,parking_fee,pet_fee,status,notes) VALUES (?,?,?,?,?,?,?,?,'active',?)", [unit_id, tenant_id, lease_start, lease_end, monthly_rent, security_deposit, parking_fee||0, pet_fee||0, notes]);
    await pool.query("UPDATE units SET status='occupied' WHERE id=?", [unit_id]);
    res.status(201).json({ success: true, lease_id: result.insertId });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// INVOICES ROUTES
// ══════════════════════════════════════════════════════════════
app.get('/api/invoices', authMiddleware, async (req, res) => {
  try {
    let sql = `SELECT i.*, u.unit_number FROM invoices i JOIN leases l ON i.lease_id=l.id JOIN units u ON l.unit_id=u.id WHERE 1=1`;
    const params = [];
    if (req.user.role !== 'admin') { sql += ' AND i.tenant_id=?'; params.push(req.user.id); }
    if (req.query.status) { sql += ' AND i.status=?'; params.push(req.query.status); }
    sql += ' ORDER BY i.due_date DESC';
    const [rows] = await pool.query(sql, params);
    res.json({ success: true, invoices: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/invoices', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { tenant_id, lease_id, invoice_type, description, amount, due_date, period_start, period_end } = req.body;
    const [result] = await pool.query('INSERT INTO invoices (tenant_id,lease_id,invoice_type,description,amount,due_date,period_start,period_end) VALUES (?,?,?,?,?,?,?,?)', [tenant_id, lease_id, invoice_type, description, amount, due_date, period_start, period_end]);
    res.status(201).json({ success: true, invoice_id: result.insertId });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// PAYMENTS ROUTES
// ══════════════════════════════════════════════════════════════
app.get('/api/payments', authMiddleware, async (req, res) => {
  try {
    let sql = `SELECT p.*, i.invoice_type, i.description, i.due_date FROM payments p JOIN invoices i ON p.invoice_id=i.id WHERE 1=1`;
    const params = [];
    if (req.user.role !== 'admin') { sql += ' AND p.tenant_id=?'; params.push(req.user.id); }
    sql += ' ORDER BY p.created_at DESC';
    const [rows] = await pool.query(sql, params);
    res.json({ success: true, payments: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/payments', authMiddleware, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const { invoice_id, payment_method, amount, last4 } = req.body;
    const [inv] = await conn.query('SELECT * FROM invoices WHERE id=?', [invoice_id]);
    if (!inv.length) throw new Error('Invoice not found');
    const [result] = await conn.query(
      "INSERT INTO payments (invoice_id,tenant_id,amount,payment_method,transaction_id,last4,status,paid_at) VALUES (?,?,?,?,?,?,'completed',NOW())",
      [invoice_id, inv[0].tenant_id, amount, payment_method, `HV-${Date.now()}`, last4||null]
    );
    await conn.query("UPDATE invoices SET status='paid' WHERE id=?", [invoice_id]);
    await conn.commit();
    res.status(201).json({ success: true, payment_id: result.insertId, confirmation: `HV-PAY-${String(result.insertId).padStart(4,'0')}` });
  } catch (e) { await conn.rollback(); res.status(500).json({ success: false, message: e.message }); }
  finally { conn.release(); }
});

// ══════════════════════════════════════════════════════════════
// MAINTENANCE ROUTES
// ══════════════════════════════════════════════════════════════
app.get('/api/maintenance', authMiddleware, async (req, res) => {
  try {
    let sql = `SELECT m.*, u.unit_number FROM maintenance_requests m JOIN units u ON m.unit_id=u.id WHERE 1=1`;
    const params = [];
    if (req.user.role !== 'admin') { sql += ' AND m.tenant_id=?'; params.push(req.user.id); }
    sql += ' ORDER BY m.created_at DESC';
    const [rows] = await pool.query(sql, params);
    res.json({ success: true, requests: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/maintenance', authMiddleware, upload.array('photos', 5), async (req, res) => {
  try {
    const { category, priority, subject, description, access_perm, preferred_time } = req.body;
    const [lease] = await pool.query("SELECT unit_id FROM leases WHERE tenant_id=? AND status='active' LIMIT 1", [req.user.id]);
    if (!lease.length) return res.status(400).json({ success: false, message: 'No active lease found' });
    const [result] = await pool.query(
      'INSERT INTO maintenance_requests (tenant_id,unit_id,category,priority,subject,description,access_perm,preferred_time) VALUES (?,?,?,?,?,?,?,?)',
      [req.user.id, lease[0].unit_id, category, priority||'normal', subject, description, access_perm==='true'?1:0, preferred_time]
    );
    res.status(201).json({ success: true, request_id: result.insertId });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// DOCUMENTS ROUTES
// ══════════════════════════════════════════════════════════════
app.get('/api/documents', authMiddleware, async (req, res) => {
  try {
    let sql = 'SELECT * FROM documents WHERE 1=1';
    const params = [];
    if (req.user.role !== 'admin') { sql += ' AND owner_id=?'; params.push(req.user.id); }
    sql += ' ORDER BY uploaded_at DESC';
    const [rows] = await pool.query(sql, params);
    res.json({ success: true, documents: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/documents', authMiddleware, upload.single('file'), async (req, res) => {
  try {
    const { title, related_type } = req.body;
    const f = req.file;
    const [result] = await pool.query(
      'INSERT INTO documents (owner_id,related_type,title,filename,filepath,file_size,mime_type,uploaded_by) VALUES (?,?,?,?,?,?,?,?)',
      [req.user.id, related_type||'general', title, f.filename, `/uploads/${f.filename}`, f.size, f.mimetype, req.user.id]
    );
    res.status(201).json({ success: true, document_id: result.insertId });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// ADMIN ROUTES
// ══════════════════════════════════════════════════════════════
app.get('/api/admin/dashboard', authMiddleware, adminOnly, async (req, res) => {
  try {
    const [[units]]   = await pool.query("SELECT COUNT(*) c, SUM(status='available') avail, SUM(status='occupied') occ FROM units");
    const [[tenants]] = await pool.query("SELECT COUNT(*) c FROM users WHERE role='tenant' AND is_active=1");
    const [[pending]] = await pool.query("SELECT COUNT(*) c FROM invoices WHERE status='pending'");
    const [[revenue]] = await pool.query("SELECT COALESCE(SUM(amount),0) total FROM payments WHERE status='completed' AND MONTH(paid_at)=MONTH(NOW()) AND YEAR(paid_at)=YEAR(NOW())");
    const [[maint]]   = await pool.query("SELECT COUNT(*) c FROM maintenance_requests WHERE status IN ('open','scheduled')");
    const [[apps]]    = await pool.query("SELECT COUNT(*) c FROM applications WHERE status='submitted'");
    res.json({ success: true, stats: { total_units: units.c, available: units.avail, occupied: units.occ, active_tenants: tenants.c, pending_invoices: pending.c, monthly_revenue: revenue.total, open_maintenance: maint.c, new_applications: apps.c } });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/admin/tenants', authMiddleware, adminOnly, async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT u.*, l.unit_id, un.unit_number, l.monthly_rent, l.lease_end FROM users u LEFT JOIN leases l ON l.tenant_id=u.id AND l.status='active' LEFT JOIN units un ON l.unit_id=un.id WHERE u.role='tenant' ORDER BY u.created_at DESC`);
    res.json({ success: true, tenants: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ══════════════════════════════════════════════════════════════
// START SERVER
// ══════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('🏢 Harborview running on port ' + PORT));
module.exports = app;
