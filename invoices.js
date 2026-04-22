// routes/leases.js
const router = require('express').Router();
const db     = require('../database/db');
const { requireAuth, requireAdmin } = require('../middleware/auth');

router.get('/', requireAuth, async (req, res) => {
  try {
    let sql = `SELECT l.*, u.unit_number, u.building_name, u.floor,
               usr.first_name, usr.last_name, usr.email
               FROM leases l JOIN units u ON l.unit_id=u.id JOIN users usr ON l.tenant_id=usr.id
               WHERE 1=1`;
    const params = [];
    if (req.user.role !== 'admin') { sql += ' AND l.tenant_id=?'; params.push(req.user.id); }
    const [rows] = await db.query(sql, params);
    res.json({ success: true, leases: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post('/', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { unit_id, tenant_id, lease_start, lease_end, monthly_rent, security_deposit, parking_fee, pet_fee, notes } = req.body;
    const [result] = await db.query(
      'INSERT INTO leases (unit_id,tenant_id,lease_start,lease_end,monthly_rent,security_deposit,parking_fee,pet_fee,status,notes) VALUES (?,?,?,?,?,?,?,?,\'active\',?)',
      [unit_id, tenant_id, lease_start, lease_end, monthly_rent, security_deposit, parking_fee || 0, pet_fee || 0, notes]
    );
    await db.query("UPDATE units SET status='occupied' WHERE id=?", [unit_id]);
    res.status(201).json({ success: true, lease_id: result.insertId });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
