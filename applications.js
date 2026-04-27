// routes/applications.js — Rental application management
const router = require('express').Router();
const db = require('../database/db');
const { requireAuth, requireAdmin } = require('../middleware/auth');

// GET /api/applications — get all applications (admin) or tenant's own
router.get('/', requireAuth, async (req, res) => {
  try {
    let sql = `SELECT a.*, u.unit_number 
               FROM applications a
               LEFT JOIN units u ON a.unit_id = u.id
               WHERE 1=1`;
    const params = [];
    if (req.user.role !== 'admin') {
      sql += ' AND a.user_id = ?';
      params.push(req.user.id);
    }
    sql += ' ORDER BY a.created_at DESC';
    const [rows] = await db.query(sql, params);
    res.json({ success: true, applications: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// POST /api/applications — submit a new application
router.post('/', requireAuth, async (req, res) => {
  try {
    const {
      unit_id, first_name, last_name, email, phone, date_of_birth,
      current_address, employer, annual_income, employment_status,
      move_in_date, lease_term, occupants, pets, pet_details,
      emergency_contact_name, emergency_contact_phone,
      previous_landlord, previous_landlord_phone, reason_for_moving,
      additional_notes
    } = req.body;

    const [result] = await db.query(
      `INSERT INTO applications (
        user_id, unit_id, first_name, last_name, email, phone, date_of_birth,
        current_address, employer, annual_income, employment_status,
        move_in_date, lease_term, occupants, pets, pet_details,
        emergency_contact_name, emergency_contact_phone,
        previous_landlord, previous_landlord_phone, reason_for_moving,
        additional_notes, status, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'submitted', NOW())`,
      [
        req.user.id, unit_id, first_name, last_name, email, phone, date_of_birth,
        current_address, employer, annual_income, employment_status,
        move_in_date, lease_term, occupants || 1, pets || false, pet_details,
        emergency_contact_name, emergency_contact_phone,
        previous_landlord, previous_landlord_phone, reason_for_moving,
        additional_notes
      ]
    );
    res.status(201).json({ success: true, application_id: result.insertId });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/applications/:id — get specific application
router.get('/:id', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT a.*, u.unit_number FROM applications a
       LEFT JOIN units u ON a.unit_id = u.id
       WHERE a.id = ?`, [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ success: false, message: 'Application not found' });
    if (req.user.role !== 'admin' && rows[0].user_id !== req.user.id) {
      return res.status(403).json({ success: false, message: 'Unauthorized' });
    }
    res.json({ success: true, application: rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// PUT /api/applications/:id/status — update application status (admin only)
router.put('/:id/status', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const validStatuses = ['submitted', 'reviewing', 'approved', 'denied', 'waitlist'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status' });
    }
    await db.query(
      'UPDATE applications SET status = ?, updated_at = NOW() WHERE id = ?',
      [status, req.params.id]
    );
    res.json({ success: true, message: `Application ${status} successfully` });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// DELETE /api/applications/:id — delete application (admin only)
router.delete('/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    await db.query('DELETE FROM applications WHERE id = ?', [req.params.id]);
    res.json({ success: true, message: 'Application deleted' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
