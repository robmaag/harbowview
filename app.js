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

app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date() }));

// AUTH
app.post('/api/auth/register', async (req, res) => {
  try {
    const { first_name, last_name, email, password, phone } = req.body;
    if (!first_name || !last_name || !email || !password) return res.status(400).json({ success: false, message: 'Required fields missing' });
    const [exists] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (exists.length) return res.status(409).json({ success: false, message: 'Email already registered' });
    const hash = await bcrypt.hash(password, 12);
    const [result] = await pool.query('INSERT INTO users (first_name, last_name, email, password_hash, phone) VALUES (?,?,?,?,?)', [first_name, last_name, email, hash, phone || null]);
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
    const [lease] = await pool.query("SELECT l.*, u.unit_number, u.building_name, u.floor FROM leases l JOIN units u ON l.unit_id=u.id WHERE l.tenant_id=? AND l.status='active' LIMIT 1", [req.user.id]);
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

// UNITS
app.get('/api/units', async (req, res) => {
  try {
    const { status, bedrooms, max_rent } = req.query;
    let sql = `SELECT u.*, (SELECT filepath FROM unit_photos WHERE unit_id=u.id AND is_primary=1 LIMIT 1) AS primary_photo, (SELECT COUNT(*) FROM unit_photos WHERE unit_id=u.id) AS photo_count FROM units u WHERE 1=1`;
    const params = [];
    if (status) { sql += ' AND u.status=?'; params.push(status); }
    if (bedrooms !== undefined && bedrooms !== '') { sql += ' AND u.bedrooms=?'; params.push(bedrooms); }
    if (max_rent) { sql += ' AND u.monthly_rent<=?'; params.push(max_rent); }
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
    const [reviews] = await pool.query('SELECT r.*, u.first_name, u.last_name FROM unit_reviews r JOIN users u ON r.tenant_id=u.id WHERE r.unit_id=? ORDER BY r.created_at DESC', [req.params.id]);
    res.json({ success: true, unit, photos, reviews });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/units/:id/photos', authMiddleware, adminOnly, upload.array('photos', 20), async (req, res) => {
  try {
    const unitId = req.params.id;
    const [existing] = await pool.query('SELECT COUNT(*) as cnt FROM unit_photos WHERE unit_id=?', [unitId]);
    const inserts = req.files.map((f, i) => [unitId, f.filename, `/uploads/${f.filename}`, req.body[`caption_${i}`] || null, i, existing[0].cnt === 0 && i === 0 ? 1 : 0]);
    await pool.query('INSERT INTO unit_photos (unit_id,filename,filepath,caption,sort_order,is_primary) VALUES ?', [inserts]);
    res.json({ success: true, message: `${req.files.length} photos uploaded` });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/units/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { unit_number, building_name, floor, bedrooms, bathrooms, sqft, monthly_rent, deposit, description, amenities, status } = req.body;
    await pool.query('UPDATE units SET unit_number=?,building_name=?,floor=?,bedrooms=?,bathrooms=?,sqft=?,monthly_rent=?,deposit=?,description=?,amenities=?,status=? WHERE id=?',
      [unit_number, building_name, floor, bedrooms, bathrooms, sqft, monthly_rent, deposit, description, JSON.stringify(amenities), status, req.params.id]);
    res.json({ success: true, message: 'Unit updated' });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// REVIEWS
app.get('/api/reviews', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT r.*, u.first_name, u.last_name, un.unit_number, un.building_name FROM unit_reviews r JOIN users u ON r.tenant_id=u.id JOIN units un ON r.unit_id=un.id ORDER BY r.created_at DESC');
    res.json({ success: true, reviews: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/reviews', authMiddleware, async (req, res) => {
  try {
    const { unit_id, rating, title, body } = req.body;
    const [result] = await pool.query('INSERT INTO unit_reviews (unit_id,tenant_id,rating,title,body) VALUES (?,?,?,?,?)', [unit_id, req.user.id, rating, title, body]);
    res.status(201).json({ success: true, review_id: result.insertId });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// TOURS
app.get('/api/tours', authMiddleware, async (req, res) => {
  try {
    let sql = `SELECT t.*, u.unit_number, u.building_name, usr.first_name, usr.last_name, usr.email FROM tour_requests t JOIN units u ON t.unit_id=u.id JOIN users usr ON t.tenant_id=usr.id WHERE 1=1`;
    const params = [];
    if (req.user.role !== 'admin') { sql += ' AND t.tenant_id=?'; params.push(req.user.id); }
    sql += ' ORDER BY t.preferred_date ASC';
    const [rows] = await pool.query(sql, params);
    res.json({ success: true, tours: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/tours', async (req, res) => {
  try {
    const { unit_id, tenant_id, name, email, phone, preferred_date, preferred_time } = req.body;
    const [result] = await pool.query('INSERT INTO tour_requests (unit_id,tenant_id,name,email,phone,preferred_date,preferred_time) VALUES (?,?,?,?,?,?,?)', [unit_id, tenant_id || null, name, email, phone, preferred_date, preferred_time]);
    res.status(201).json({ success: true, tour_id: result.insertId });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/tours/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { status, admin_notes } = req.body;
    await pool.query('UPDATE tour_requests SET status=?, admin_notes=? WHERE id=?', [status, admin_notes, req.params.id]);
    res.json({ success: true, message: 'Tour updated' });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// APPLICATIONS
app.post('/api/applications', async (req, res) => {
  try {
    const fields = ['unit_id','first_name','last_name','email','phone','dob','ssn_last4','current_address','desired_movein','num_occupants','pets','employment_status','employer_name','employer_address','employer_phone','supervisor_name','job_title','employment_start','annual_income','additional_income','prev_address1','prev_rent1','prev_duration1','prev_landlord1','prev_landlord_phone1','prev_reason1','prev_address2','prev_rent2','prev_duration2','prev_landlord2','prev_landlord_phone2','ever_evicted','ever_broken_lease','rental_notes','ref1_name','ref1_relationship','ref1_phone','ref1_email','ref2_name','ref2_relationship','ref2_phone','ref2_email','signature','signed_date'];
    const values = fields.map(f => req.body[f] ?? null);
    const [result] = await pool.query(`INSERT INTO applications (${fields.join(',')}) VALUES (${fields.map(() => '?').join(',')})`, values);
    res.status(201).json({ success: true, application_id: result.insertId, reference: `HV-${new Date().getFullYear()}-${String(result.insertId).padStart(4, '0')}` });
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

app.put('/api/applications/:id/status', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { status } = req.body;
    await pool.query('UPDATE applications SET status=?, reviewed_by=?, reviewed_at=NOW() WHERE id=?', [status, req.user.id, req.params.id]);
    res.json({ success: true, message: `Application ${status}` });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/applications/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { status, decision_notes } = req.body;
    await pool.query('UPDATE applications SET status=?, decision_notes=?, reviewed_by=?, reviewed_at=NOW() WHERE id=?', [status, decision_notes, req.user.id, req.params.id]);
    res.json({ success: true, message: 'Application updated' });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// LEASES
app.get('/api/leases', authMiddleware, async (req, res) => {
  try {
    let sql = `SELECT l.*, u.unit_number, u.building_name, u.floor, usr.first_name, usr.last_name FROM leases l JOIN units u ON l.unit_id=u.id JOIN users usr ON l.tenant_id=usr.id WHERE 1=1`;
    const params = [];
    if (req.user.role !== 'admin') { sql += ' AND l.tenant_id=?'; params.push(req.user.id); }
    const [rows] = await pool.query(sql, params);
    res.json({ success: true, leases: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/leases/generate', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { tenant_id, unit_id, start_date, end_date, monthly_rent, security_deposit, late_fee, grace_period_days, special_terms } = req.body;
    const [tenants] = await pool.query('SELECT * FROM users WHERE id=?', [tenant_id]);
    if (!tenants.length) throw new Error('Tenant not found');
    const tenant = tenants[0];
    const [units] = await pool.query('SELECT * FROM units WHERE id=?', [unit_id]);
    if (!units.length) throw new Error('Unit not found');
    const unit = units[0];
    const deposit = security_deposit || monthly_rent * 2;
    const startFormatted = new Date(start_date).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    const endFormatted = new Date(end_date).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    const leaseDoc = `CALIFORNIA RESIDENTIAL LEASE AGREEMENT\n\nLease ID: APE-${Date.now()}\nGenerated: ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}\n\nLANDLORD: A Phoenix Enterprises LLC\nAddress: Concord, CA 94520\n\nTENANT: ${tenant.first_name} ${tenant.last_name}\nEmail: ${tenant.email}\nPhone: ${tenant.phone || 'N/A'}\n\nUNIT: ${unit.unit_number}\nLEASE TERM: ${startFormatted} to ${endFormatted}\n\nMONTHLY RENT: $${parseFloat(monthly_rent).toFixed(2)}\nDUE DATE: 1st of each month\nGRACE PERIOD: ${grace_period_days || 5} days\nLATE FEE: $${late_fee || 50}.00\n\nSECURITY DEPOSIT: $${parseFloat(deposit).toFixed(2)}\n(Returned within 21 days of vacating per CA Civil Code 1950.5)\n\nCALIFORNIA DISCLOSURES:\n- Smoking prohibited per CA Government Code 7597\n- 24-hour notice required for entry per CA Civil Code 1954\n- Tenant Protection Act (AB 1482) may apply\n- Mold disclosure provided per CA Health & Safety Code 26147\n\nSPECIAL TERMS:\n${special_terms || 'None.'}\n\n[AWAITING TENANT E-SIGNATURE]`;
    const [result] = await pool.query(
      `INSERT INTO leases (unit_id, tenant_id, lease_start, lease_end, monthly_rent, security_deposit, status, lease_document, created_at) VALUES (?,?,?,?,?,?,'pending_signature',?,NOW())`,
      [unit_id, tenant_id, start_date, end_date, monthly_rent, deposit, leaseDoc]
    );
    await pool.query("UPDATE units SET status='reserved' WHERE id=?", [unit_id]);
    res.json({ success: true, lease_id: result.insertId, message: 'Lease generated! Tenant can now review and sign.' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/leases/:id', authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT l.*, u.unit_number FROM leases l JOIN units u ON l.unit_id=u.id WHERE l.id=?`, [req.params.id]);
    if (!rows.length) return res.status(404).json({ success: false, message: 'Lease not found' });
    if (req.user.role !== 'admin' && rows[0].tenant_id !== req.user.id) return res.status(403).json({ success: false, message: 'Unauthorized' });
    res.json({ success: true, lease: rows[0] });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/leases/:id/sign', authMiddleware, async (req, res) => {
  try {
    const { signature, agreed } = req.body;
    if (!agreed || !signature) return res.status(400).json({ success: false, message: 'Signature and agreement required' });
    const [rows] = await pool.query('SELECT * FROM leases WHERE id=?', [req.params.id]);
    if (!rows.length) return res.status(404).json({ success: false, message: 'Lease not found' });
    if (rows[0].tenant_id !== req.user.id) return res.status(403).json({ success: false, message: 'Unauthorized' });
    const signatureBlock = `\n\n--- DIGITALLY SIGNED ---\nTenant: ${signature}\nDate: ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}\nThis electronic signature is legally binding under California Civil Code and the ESIGN Act.`;
    await pool.query(`UPDATE leases SET status='active', signed_at=NOW(), tenant_signature=?, lease_document=CONCAT(COALESCE(lease_document,''), ?) WHERE id=?`, [signature, signatureBlock, req.params.id]);
    await pool.query("UPDATE units SET status='occupied' WHERE id=?", [rows[0].unit_id]);
    res.json({ success: true, message: 'Lease signed successfully! Welcome home.' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/leases', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { unit_id, tenant_id, lease_start, lease_end, monthly_rent, security_deposit, parking_fee, pet_fee, notes } = req.body;
    const [result] = await pool.query("INSERT INTO leases (unit_id,tenant_id,lease_start,lease_end,monthly_rent,security_deposit,parking_fee,pet_fee,status,notes) VALUES (?,?,?,?,?,?,?,?,'active',?)",
      [unit_id, tenant_id, lease_start, lease_end, monthly_rent, security_deposit, parking_fee || 0, pet_fee || 0, notes]);
    await pool.query("UPDATE units SET status='occupied' WHERE id=?", [unit_id]);
    res.status(201).json({ success: true, lease_id: result.insertId });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// INVOICES
app.get('/api/invoices', authMiddleware, async (req, res) => {
  try {
    let sql = `SELECT i.*, u.unit_number FROM invoices i JOIN leases l ON i.lease_id=l.id JOIN units u ON l.unit_id=u.id WHERE 1=1`;
    const params = [];
    if (req.user.role !== 'admin') { sql += ' AND i.tenant_id=?'; params.push(req.user.id); }
    if (req.query.status) { sql += ' AND i.status=?'; params.push(req.query.status); }
    if (req.query.type) { sql += ' AND i.invoice_type=?'; params.push(req.query.type); }
    sql += ' ORDER BY i.due_date DESC';
    const [rows] = await pool.query(sql, params);
    res.json({ success: true, invoices: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/invoices', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { tenant_id, lease_id, invoice_type, description, amount, due_date, period_start, period_end, meter_reading_start, meter_reading_end, utility_rate } = req.body;
    const [result] = await pool.query('INSERT INTO invoices (tenant_id,lease_id,invoice_type,description,amount,due_date,period_start,period_end,meter_reading_start,meter_reading_end,utility_rate) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
      [tenant_id, lease_id, invoice_type, description, amount, due_date, period_start, period_end, meter_reading_start || null, meter_reading_end || null, utility_rate || null]);
    res.status(201).json({ success: true, invoice_id: result.insertId });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/invoices/generate-monthly', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { month, year } = req.body;
    const [leases] = await pool.query("SELECT * FROM leases WHERE status='active'");
    const dueDate = `${year}-${String(month).padStart(2, '0')}-01`;
    let created = 0;
    for (const lease of leases) {
      const [dup] = await pool.query("SELECT id FROM invoices WHERE lease_id=? AND invoice_type='rent' AND due_date=?", [lease.id, dueDate]);
      if (!dup.length) {
        await pool.query("INSERT INTO invoices (tenant_id,lease_id,invoice_type,description,amount,due_date,period_start,period_end) VALUES (?,?,'rent',?,?,?,?)",
          [lease.tenant_id, lease.id, `Rent - ${month}/${year}`, lease.monthly_rent, dueDate, dueDate, `${year}-${String(month).padStart(2, '0')}-28`]);
        created++;
      }
    }
    res.json({ success: true, message: `${created} rent invoices generated` });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/invoices/generate-utility', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { tenant_id, lease_id, utility_type, amount, due_date, period_start, period_end, meter_reading_start, meter_reading_end, utility_rate, notes } = req.body;
    const utilityLabels = { gas_electric: 'Gas & Electric', water: 'Water', internet_tv: 'Internet/TV', garbage: 'Garbage Collection' };
    const label = utilityLabels[utility_type] || utility_type;
    const [result] = await pool.query('INSERT INTO invoices (tenant_id,lease_id,invoice_type,description,amount,due_date,period_start,period_end,meter_reading_start,meter_reading_end,utility_rate) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
      [tenant_id, lease_id, utility_type, `${label}${notes ? ' - ' + notes : ''}`, amount, due_date, period_start, period_end, meter_reading_start || null, meter_reading_end || null, utility_rate || null]);
    res.status(201).json({ success: true, invoice_id: result.insertId, message: `${label} bill created` });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// PAYMENTS
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
    const [result] = await conn.query("INSERT INTO payments (invoice_id,tenant_id,amount,payment_method,transaction_id,last4,status,paid_at) VALUES (?,?,?,?,?,?,'completed',NOW())",
      [invoice_id, inv[0].tenant_id, amount, payment_method, `HV-${Date.now()}`, last4 || null]);
    await conn.query("UPDATE invoices SET status='paid' WHERE id=?", [invoice_id]);
    await conn.commit();
    res.status(201).json({ success: true, payment_id: result.insertId, confirmation: `HV-PAY-${String(result.insertId).padStart(4, '0')}` });
  } catch (e) { await conn.rollback(); res.status(500).json({ success: false, message: e.message }); }
  finally { conn.release(); }
});

// MAINTENANCE
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
    const [result] = await pool.query('INSERT INTO maintenance_requests (tenant_id,unit_id,category,priority,subject,description,access_perm,preferred_time) VALUES (?,?,?,?,?,?,?,?)',
      [req.user.id, lease[0].unit_id, category, priority || 'normal', subject, description, access_perm === 'true' ? 1 : 0, preferred_time]);
    res.status(201).json({ success: true, request_id: result.insertId });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/maintenance/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { status, assigned_to, scheduled_at, resolution_notes } = req.body;
    await pool.query('UPDATE maintenance_requests SET status=?,assigned_to=?,scheduled_at=?,resolution_notes=? WHERE id=?', [status, assigned_to, scheduled_at, resolution_notes, req.params.id]);
    res.json({ success: true, message: 'Request updated' });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// MESSAGES
app.get('/api/messages', authMiddleware, async (req, res) => {
  try {
    let sql = `SELECT m.*, u.first_name, u.last_name, u.role FROM messages m JOIN users u ON m.sender_id=u.id WHERE 1=1`;
    const params = [];
    if (req.user.role !== 'admin') { sql += ' AND (m.sender_id=? OR m.recipient_id=?)'; params.push(req.user.id, req.user.id); }
    sql += ' ORDER BY m.created_at DESC LIMIT 100';
    const [rows] = await pool.query(sql, params);
    res.json({ success: true, messages: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/messages', authMiddleware, async (req, res) => {
  try {
    const { recipient_id, subject, body } = req.body;
    const [result] = await pool.query('INSERT INTO messages (sender_id,recipient_id,subject,body) VALUES (?,?,?,?)', [req.user.id, recipient_id, subject, body]);
    res.status(201).json({ success: true, message_id: result.insertId });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/messages/:id/read', authMiddleware, async (req, res) => {
  try {
    await pool.query('UPDATE messages SET is_read=1 WHERE id=? AND recipient_id=?', [req.params.id, req.user.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ANNOUNCEMENTS
app.get('/api/announcements', async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM announcements WHERE (expires_at IS NULL OR expires_at > NOW()) ORDER BY pinned DESC, created_at DESC");
    res.json({ success: true, announcements: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/announcements', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { title, body, audience, pinned, expires_at } = req.body;
    const [result] = await pool.query('INSERT INTO announcements (title,body,audience,pinned,expires_at,created_by,published_at) VALUES (?,?,?,?,?,?,NOW())',
      [title, body, audience || 'tenants', pinned ? 1 : 0, expires_at || null, req.user.id]);
    res.status(201).json({ success: true, announcement_id: result.insertId });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.delete('/api/announcements/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    await pool.query('DELETE FROM announcements WHERE id=?', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// PARKING
app.get('/api/parking', authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT p.*, u.first_name, u.last_name FROM parking_spots p LEFT JOIN users u ON p.tenant_id=u.id ORDER BY p.spot_number ASC`);
    res.json({ success: true, spots: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/parking', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { spot_number, spot_type, tenant_id, monthly_fee, notes } = req.body;
    const [result] = await pool.query('INSERT INTO parking_spots (spot_number,spot_type,tenant_id,monthly_fee,notes,status) VALUES (?,?,?,?,?,?)',
      [spot_number, spot_type || 'standard', tenant_id || null, monthly_fee || 0, notes, tenant_id ? 'occupied' : 'available']);
    res.status(201).json({ success: true, spot_id: result.insertId });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/parking/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { tenant_id, monthly_fee, notes, status } = req.body;
    await pool.query('UPDATE parking_spots SET tenant_id=?,monthly_fee=?,notes=?,status=? WHERE id=?', [tenant_id || null, monthly_fee, notes, status, req.params.id]);
    res.json({ success: true, message: 'Parking spot updated' });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// PACKAGES
app.get('/api/packages', authMiddleware, async (req, res) => {
  try {
    let sql = `SELECT p.*, u.first_name, u.last_name, u.email FROM packages p JOIN users u ON p.tenant_id=u.id WHERE 1=1`;
    const params = [];
    if (req.user.role !== 'admin') { sql += ' AND p.tenant_id=?'; params.push(req.user.id); }
    sql += ' ORDER BY p.received_at DESC';
    const [rows] = await pool.query(sql, params);
    res.json({ success: true, packages: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/packages', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { tenant_id, carrier, tracking_number, description, location } = req.body;
    const [result] = await pool.query('INSERT INTO packages (tenant_id,carrier,tracking_number,description,location,received_at) VALUES (?,?,?,?,?,NOW())',
      [tenant_id, carrier, tracking_number, description, location || 'Front Desk']);
    res.status(201).json({ success: true, package_id: result.insertId });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/packages/:id/pickup', authMiddleware, async (req, res) => {
  try {
    await pool.query("UPDATE packages SET status='picked_up', picked_up_at=NOW() WHERE id=?", [req.params.id]);
    res.json({ success: true, message: 'Package marked as picked up' });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// DOCUMENTS
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
    const [result] = await pool.query('INSERT INTO documents (owner_id,related_type,title,filename,filepath,file_size,mime_type,uploaded_by) VALUES (?,?,?,?,?,?,?,?)',
      [req.user.id, related_type || 'general', title, f.filename, `/uploads/${f.filename}`, f.size, f.mimetype, req.user.id]);
    res.status(201).json({ success: true, document_id: result.insertId });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/documents/all', authMiddleware, adminOnly, async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT d.*, u.first_name, u.last_name FROM documents d LEFT JOIN users u ON d.owner_id=u.id ORDER BY d.uploaded_at DESC`);
    res.json({ success: true, documents: rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ADMIN DASHBOARD
app.get('/api/admin/dashboard', authMiddleware, adminOnly, async (req, res) => {
  try {
    const [[units]]   = await pool.query("SELECT COUNT(*) total, SUM(status='available') available, SUM(status='occupied') occupied FROM units");
    const [[tenants]] = await pool.query("SELECT COUNT(*) total, SUM(is_active=1) active FROM users WHERE role='tenant'");
    const [[revenue]] = await pool.query("SELECT COALESCE(SUM(amount),0) collected_month FROM payments WHERE status='completed' AND MONTH(paid_at)=MONTH(NOW()) AND YEAR(paid_at)=YEAR(NOW())");
    const [[pending_amt]] = await pool.query("SELECT COALESCE(SUM(amount),0) pending_amount FROM invoices WHERE status IN ('pending','overdue')");
    const [[maint]]   = await pool.query("SELECT COUNT(*) open, SUM(priority='urgent') urgent, SUM(status='scheduled') scheduled FROM maintenance_requests WHERE status IN ('open','scheduled','in_progress')");
    const [[apps]]    = await pool.query("SELECT COUNT(*) c FROM applications WHERE status='submitted'");
    const [[msgs]]    = await pool.query("SELECT COUNT(*) c FROM messages WHERE is_read=0 AND recipient_id IN (SELECT id FROM users WHERE role='admin')");
    const [[pkgs]]    = await pool.query("SELECT COUNT(*) c FROM packages WHERE status='pending'");
    const [[tours]]   = await pool.query("SELECT COUNT(*) c FROM tour_requests WHERE status='pending'");
    const [recentPayments] = await pool.query(`SELECT p.*, u.first_name, u.last_name, un.unit_number, p.created_at as payment_date FROM payments p JOIN users u ON p.tenant_id=u.id LEFT JOIN leases l ON l.tenant_id=u.id AND l.status='active' LEFT JOIN units un ON l.unit_id=un.id WHERE p.status='completed' ORDER BY p.created_at DESC LIMIT 6`);
    const [overdueBills] = await pool.query(`SELECT i.*, u.first_name, u.last_name, un.unit_number FROM invoices i JOIN users u ON i.tenant_id=u.id LEFT JOIN leases l ON l.tenant_id=u.id AND l.status='active' LEFT JOIN units un ON l.unit_id=un.id WHERE i.status IN ('overdue','pending') ORDER BY i.due_date ASC LIMIT 5`);
    res.json({ success: true, stats: { units: { total: units.total, available: units.available, occupied: units.occupied }, tenants: { total: tenants.total, active: tenants.active }, financials: { collected_month: revenue.collected_month, pending_amount: pending_amt.pending_amount }, maintenance: { open: maint.open, urgent: maint.urgent || 0, scheduled: maint.scheduled || 0 }, new_applications: apps.c, unread_messages: msgs.c, pending_packages: pkgs.c, pending_tours: tours.c }, recentPayments, overdueBills });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/admin/tenants', authMiddleware, adminOnly, async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT u.*, l.unit_id, un.unit_number, un.building_name, l.monthly_rent, l.lease_end FROM users u LEFT JOIN leases l ON l.tenant_id=u.id AND l.status='active' LEFT JOIN units un ON l.unit_id=un.id WHERE u.role='tenant' ORDER BY u.created_at DESC`);
    res.json({ success: true, tenants: rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/admin/reports/revenue', authMiddleware, adminOnly, async (req, res) => {
  try {
    const [monthly] = await pool.query("SELECT DATE_FORMAT(paid_at,'%Y-%m') as month, SUM(amount) as total, COUNT(*) as count FROM payments WHERE status='completed' GROUP BY DATE_FORMAT(paid_at,'%Y-%m') ORDER BY month DESC LIMIT 12");
    const [by_type] = await pool.query("SELECT i.invoice_type, SUM(p.amount) as total FROM payments p JOIN invoices i ON p.invoice_id=i.id WHERE p.status='completed' GROUP BY i.invoice_type");
    const [occupancy] = await pool.query("SELECT status, COUNT(*) as count FROM units GROUP BY status");
    res.json({ success: true, monthly, by_type, occupancy });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// BACKGROUND CHECKS
pool.query(`CREATE TABLE IF NOT EXISTS background_checks (id INT AUTO_INCREMENT PRIMARY KEY, tenant_id INT NOT NULL, agency_used VARCHAR(100), credit_score INT DEFAULT NULL, overall_result ENUM('approved','conditional','denied','pending') DEFAULT 'pending', criminal_record ENUM('clear','minor','disqualifying') DEFAULT 'clear', eviction_history ENUM('none','dismissed','found') DEFAULT 'none', notes TEXT, visible_to_tenant BOOLEAN DEFAULT FALSE, completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, created_by INT, FOREIGN KEY (tenant_id) REFERENCES users(id), FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL)`).catch(e => console.error('BG table error:', e.message));

app.get('/api/background/all', authMiddleware, adminOnly, async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT b.*, u.first_name, u.last_name FROM background_checks b JOIN users u ON b.tenant_id=u.id ORDER BY b.completed_at DESC`);
    res.json({ success: true, reports: rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/background/my', authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT * FROM background_checks WHERE tenant_id=? AND visible_to_tenant=1 ORDER BY completed_at DESC`, [req.user.id]);
    res.json({ success: true, reports: rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/background', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { tenant_id, agency_used, credit_score, overall_result, criminal_record, eviction_history, notes, visible_to_tenant } = req.body;
    const [result] = await pool.query('INSERT INTO background_checks (tenant_id,agency_used,credit_score,overall_result,criminal_record,eviction_history,notes,visible_to_tenant,created_by) VALUES (?,?,?,?,?,?,?,?,?)',
      [tenant_id, agency_used, credit_score || null, overall_result, criminal_record, eviction_history, notes, visible_to_tenant === '1' ? 1 : 0, req.user.id]);
    res.status(201).json({ success: true, report_id: result.insertId });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// SMS
async function sendSMS(to, message) {
  try {
    const accountSid = process.env.TWILIO_ACCOUNT_SID;
    const authToken  = process.env.TWILIO_AUTH_TOKEN;
    const fromNumber = process.env.TWILIO_PHONE_NUMBER;
    if (!accountSid || !authToken || !fromNumber) { console.log('SMS skipped'); return null; }
    const credentials = Buffer.from(`${accountSid}:${authToken}`).toString('base64');
    const response = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Messages.json`, { method: 'POST', headers: { 'Authorization': `Basic ${credentials}`, 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ To: to, From: fromNumber, Body: message }).toString() });
    return await response.json();
  } catch (e) { console.error('SMS error:', e.message); return null; }
}

app.post('/api/sms/payment-confirmation', async (req, res) => {
  try {
    const { tenant_id, amount, confirmation } = req.body;
    const [user] = await pool.query('SELECT phone, first_name FROM users WHERE id=?', [tenant_id]);
    if (!user.length || !user[0].phone) return res.json({ success: false, message: 'No phone number on file' });
    await sendSMS(user[0].phone, `Hi ${user[0].first_name}! Your payment of $${amount} has been confirmed. Confirmation: ${confirmation}. Thank you!`);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/sms/rent-reminders', async (req, res) => {
  try {
    const [pending] = await pool.query(`SELECT i.id, i.amount, i.due_date, u.first_name, u.phone FROM invoices i JOIN users u ON i.tenant_id=u.id WHERE i.status='pending' AND i.invoice_type='rent' AND u.phone IS NOT NULL`);
    let sent = 0;
    for (const inv of pending) {
      await sendSMS(inv.phone, `Hi ${inv.first_name}! Reminder: Your rent of $${parseFloat(inv.amount).toFixed(2)} is due ${new Date(inv.due_date).toLocaleDateString()}. Pay online at your tenant portal.`);
      sent++;
    }
    res.json({ success: true, message: `${sent} SMS reminders sent` });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/sms/maintenance-update', async (req, res) => {
  try {
    const { request_id, status } = req.body;
    const [req_] = await pool.query(`SELECT m.subject, u.first_name, u.phone FROM maintenance_requests m JOIN users u ON m.tenant_id=u.id WHERE m.id=?`, [request_id]);
    if (!req_.length || !req_[0].phone) return res.json({ success: false, message: 'No phone on file' });
    const statusMsg = { scheduled: 'has been scheduled', in_progress: 'is now in progress', completed: 'has been completed' };
    await sendSMS(req_[0].phone, `Hi ${req_[0].first_name}! Your maintenance request "${req_[0].subject}" ${statusMsg[status] || 'has been updated'}.`);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/sms/send', async (req, res) => {
  try {
    const { tenant_id, message } = req.body;
    const [user] = await pool.query('SELECT phone, first_name FROM users WHERE id=?', [tenant_id]);
    if (!user.length || !user[0].phone) return res.json({ success: false, message: 'No phone number on file' });
    await sendSMS(user[0].phone, message);
    res.json({ success: true, message: 'SMS sent!' });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('🏢 Harborview running on port ' + PORT));
module.exports = app;
