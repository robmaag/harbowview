// routes/applications.js — Rental applications
const router = require('express').Router();
const db     = require('../database/db');
const { requireAuth, requireAdmin } = require('../middleware/auth');

// POST /api/applications — public submit
router.post('/', async (req, res) => {
  try {
    const fields = [
      'unit_id','first_name','last_name','email','phone','dob','ssn_last4','current_address',
      'desired_movein','num_occupants','pets','employment_status','employer_name','employer_address',
      'employer_phone','supervisor_name','job_title','employment_start','annual_income','additional_income',
      'prev_address1','prev_rent1','prev_duration1','prev_landlord1','prev_landlord_phone1','prev_reason1',
      'prev_address2','prev_rent2','prev_duration2','prev_landlord2','prev_landlord_phone2',
      'ever_evicted','ever_broken_lease','rental_notes',
      'ref1_name','ref1_relationship','ref1_phone','ref1_email',
      'ref2_name','ref2_relationship','ref2_phone','ref2_email',
      'signature','signed_date'
    ];
    const values = fields.map(f => req.body[f] ?? null);
    const placeholders = fields.map(() => '?').join(',');
    const [result] = await db.query(
      `INSERT INTO applications (${fields.join(',')}) VALUES (${placeholders})`,
      values
    );
    res.status(201).json({ success: true, application_id: result.insertId,
      reference: `HV-${new Date().getFullYear()}-${String(result.insertId).padStart(4,'0')}`
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/applications — admin: all, tenant: own
router.get('/', requireAuth, async (req, res) => {
  try {
    let sql = 'SELECT a.*, u.unit_number FROM applications a LEFT JOIN units u ON a.unit_id=u.id';
    const params = [];
    if (req.user.role !== 'admin') {
      sql += ' WHERE a.email = ?';
      params.push(req.user.email);
    }
    sql += ' ORDER BY a.created_at DESC';
    const [rows] = await db.query(sql, params);
    res.json({ success: true, applications: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// PUT /api/applications/:id/status — admin decision
router.put('/:id/status', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { status, decision_notes } = req.body;
    await db.query(
      'UPDATE applications SET status=?, decision_notes=?, reviewed_by=?, reviewed_at=NOW() WHERE id=?',
      [status, decision_notes, req.user.id, req.params.id]
    );
    res.json({ success: true, message: 'Application updated' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
