// routes/invoices.js — Billing
const router = require('express').Router();
const db     = require('../database/db');
const { requireAuth, requireAdmin } = require('../middleware/auth');

// GET /api/invoices — tenant: own invoices; admin: all
router.get('/', requireAuth, async (req, res) => {
  try {
    let sql = `SELECT i.*, u.unit_number, u.building_name
               FROM invoices i
               JOIN leases l ON i.lease_id = l.id
               JOIN units u  ON l.unit_id  = u.id
               WHERE 1=1`;
    const params = [];
    if (req.user.role !== 'admin') {
      sql += ' AND i.tenant_id = ?';
      params.push(req.user.id);
    }
    if (req.query.status) { sql += ' AND i.status = ?'; params.push(req.query.status); }
    sql += ' ORDER BY i.due_date DESC';
    const [rows] = await db.query(sql, params);
    res.json({ success: true, invoices: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// POST /api/invoices — admin create invoice
router.post('/', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { tenant_id, lease_id, invoice_type, description, amount, due_date, period_start, period_end } = req.body;
    const [result] = await db.query(
      'INSERT INTO invoices (tenant_id,lease_id,invoice_type,description,amount,due_date,period_start,period_end) VALUES (?,?,?,?,?,?,?,?)',
      [tenant_id, lease_id, invoice_type, description, amount, due_date, period_start, period_end]
    );
    res.status(201).json({ success: true, invoice_id: result.insertId });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Bulk-generate monthly rent invoices for all active leases
router.post('/generate-monthly', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { month, year } = req.body; // e.g. month=4 year=2026
    const [leases] = await db.query(
      "SELECT * FROM leases WHERE status='active' AND lease_start <= CURDATE() AND lease_end >= CURDATE()"
    );
    const dueDate = `${year}-${String(month).padStart(2,'0')}-01`;
    let created = 0;
    for (const lease of leases) {
      // Avoid duplicates
      const [dup] = await db.query(
        "SELECT id FROM invoices WHERE lease_id=? AND invoice_type='rent' AND due_date=?",
        [lease.id, dueDate]
      );
      if (!dup.length) {
        await db.query(
          "INSERT INTO invoices (tenant_id,lease_id,invoice_type,description,amount,due_date,period_start,period_end) VALUES (?,?,'rent',?,?,?,?,?)",
          [lease.tenant_id, lease.id, `Rent – ${month}/${year}`, lease.monthly_rent, dueDate,
           dueDate, `${year}-${String(month).padStart(2,'0')}-${new Date(year,month,0).getDate()}`]
        );
        created++;
      }
    }
    res.json({ success: true, message: `${created} invoices generated` });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
