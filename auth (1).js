// routes/maintenance.js — Maintenance requests + photos
const router = require('express').Router();
const db     = require('../database/db');
const path   = require('path');
const fs     = require('fs');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const { requireAuth, requireAdmin } = require('../middleware/auth');

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, '..', 'uploads', 'maintenance');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname).toLowerCase()}`)
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

// GET /api/maintenance
router.get('/', requireAuth, async (req, res) => {
  try {
    let sql = `SELECT m.*, u.unit_number, u.building_name,
               usr.first_name, usr.last_name,
               (SELECT JSON_ARRAYAGG(filepath) FROM maintenance_photos WHERE request_id=m.id) AS photos
               FROM maintenance_requests m
               JOIN units u ON m.unit_id=u.id
               JOIN users usr ON m.tenant_id=usr.id
               WHERE 1=1`;
    const params = [];
    if (req.user.role !== 'admin') { sql += ' AND m.tenant_id=?'; params.push(req.user.id); }
    if (req.query.status) { sql += ' AND m.status=?'; params.push(req.query.status); }
    sql += ' ORDER BY m.created_at DESC';
    const [rows] = await db.query(sql, params);
    rows.forEach(r => { try { r.photos = JSON.parse(r.photos) || []; } catch { r.photos = []; } });
    res.json({ success: true, requests: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// POST /api/maintenance — submit new request (with optional photos)
router.post('/', requireAuth, upload.array('photos', 5), async (req, res) => {
  try {
    const { category, priority, subject, description, access_perm, preferred_time, unit_id } = req.body;

    // Get unit_id from active lease if not provided
    let resolvedUnitId = unit_id;
    if (!resolvedUnitId) {
      const [lease] = await db.query(
        "SELECT unit_id FROM leases WHERE tenant_id=? AND status='active' LIMIT 1", [req.user.id]
      );
      if (lease.length) resolvedUnitId = lease[0].unit_id;
    }
    if (!resolvedUnitId) return res.status(400).json({ success: false, message: 'No active lease found' });

    const [result] = await db.query(
      'INSERT INTO maintenance_requests (tenant_id,unit_id,category,priority,subject,description,access_perm,preferred_time) VALUES (?,?,?,?,?,?,?,?)',
      [req.user.id, resolvedUnitId, category, priority || 'normal', subject, description,
       access_perm === 'true' || access_perm === true ? 1 : 0, preferred_time]
    );

    // Save photos
    if (req.files?.length) {
      const photoInserts = req.files.map(f => [result.insertId, f.filename, `/uploads/maintenance/${f.filename}`, req.user.id]);
      await db.query('INSERT INTO maintenance_photos (request_id,filename,filepath,uploaded_by) VALUES ?', [photoInserts]);
    }

    res.status(201).json({ success: true, request_id: result.insertId });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// PUT /api/maintenance/:id — admin update status
router.put('/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { status, assigned_to, scheduled_at, resolution_notes } = req.body;
    const completed = status === 'completed' ? 'NOW()' : 'NULL';
    await db.query(
      `UPDATE maintenance_requests SET status=?,assigned_to=?,scheduled_at=?,resolution_notes=?,
       completed_at=${completed} WHERE id=?`,
      [status, assigned_to, scheduled_at, resolution_notes, req.params.id]
    );
    res.json({ success: true, message: 'Request updated' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
