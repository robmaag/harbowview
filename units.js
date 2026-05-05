'use strict';
// routes/units.js — APhoenix Enterprise LLC
// Complete replacement — adds POST, PUT, DELETE + photo upload
// Preserves existing GET /units and GET /units/:id exactly

const router  = require('express').Router();
// Smart path detection — works from root OR routes/ folder
const db = require(require('path').join(process.cwd(), 'database', 'db'));
const jwt     = require('jsonwebtoken');
const multer  = require('multer');
const path    = require('path');
const fs      = require('fs');

// ── Multer storage — saves to /app/uploads/units/ ────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(process.cwd(), 'uploads', 'units');
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const ext  = path.extname(file.originalname).toLowerCase();
    const name = `unit_${req.params.id || 'new'}_${Date.now()}${ext}`;
    cb(null, name);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const ok = /jpeg|jpg|png|webp|gif/.test(file.mimetype);
    cb(ok ? null : new Error('Only image files are allowed'), ok);
  }
});

// ── Auth middleware ───────────────────────────────────────────────
const requireAdmin = (req, res, next) => {
  const header = req.headers['authorization'];
  const token  = header && header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ success: false, message: 'Authentication required' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'admin' && decoded.role !== 'super_admin') {
      return res.status(403).json({ success: false, message: 'Admin access required' });
    }
    req.user = decoded;
    next();
  } catch {
    return res.status(403).json({ success: false, message: 'Invalid or expired token' });
  }
};

// ── Helper: parse amenities safely ───────────────────────────────
const parseAmenities = (raw) => {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  try { return JSON.parse(raw); } catch { return []; }
};

// ── GET /units — public listing ───────────────────────────────────
router.get('/', async (req, res) => {
  try {
    const { status, bedrooms, max_rent } = req.query;
    let where = 'WHERE 1=1';
    const params = [];
    if (status)    { where += ' AND u.status = ?';          params.push(status); }
    if (bedrooms)  { where += ' AND u.bedrooms = ?';        params.push(parseInt(bedrooms)); }
    if (max_rent)  { where += ' AND u.monthly_rent <= ?';   params.push(parseFloat(max_rent)); }

    const [units] = await db.query(`
      SELECT u.*,
        COUNT(p.id)                                   AS photo_count,
        MAX(CASE WHEN p.is_primary = 1 THEN p.filepath END) AS primary_photo
      FROM units u
      LEFT JOIN unit_photos p ON p.unit_id = u.id
      ${where}
      GROUP BY u.id
      ORDER BY u.unit_number ASC
    `, params);

    res.json({ units: units.map(u => ({ ...u, amenities: parseAmenities(u.amenities) })) });
  } catch (err) {
    console.error('[GET /units]', err);
    res.status(500).json({ error: err.message });
  }
});

// ── GET /units/:id — single unit with photos ──────────────────────
router.get('/:id', async (req, res) => {
  try {
    const [[unit]] = await db.query('SELECT * FROM units WHERE id = ?', [req.params.id]);
    if (!unit) return res.status(404).json({ error: 'Unit not found' });

    const [photos] = await db.query(
      'SELECT * FROM unit_photos WHERE unit_id = ? ORDER BY is_primary DESC, created_at ASC',
      [req.params.id]
    );

    res.json({ unit: { ...unit, amenities: parseAmenities(unit.amenities) }, photos });
  } catch (err) {
    console.error('[GET /units/:id]', err);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /units — create new unit ────────────────────────────────
router.post('/', requireAdmin, async (req, res) => {
  try {
    const {
      unit_number, floor, monthly_rent,
      bedrooms = 0, bathrooms = 1, sq_ft,
      status = 'available', description, amenities = []
    } = req.body;

    if (!unit_number || !monthly_rent) {
      return res.status(400).json({ success: false, error: 'unit_number and monthly_rent are required' });
    }

    // Check duplicate
    const [[existing]] = await db.query('SELECT id FROM units WHERE unit_number = ? LIMIT 1', [unit_number]);
    if (existing) {
      return res.status(409).json({ success: false, error: `Unit ${unit_number} already exists` });
    }

    const [result] = await db.query(
      `INSERT INTO units (unit_number, floor, monthly_rent, bedrooms, bathrooms, sq_ft, status, description, amenities)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        String(unit_number).trim(),
        floor ? parseInt(floor) : null,
        parseFloat(monthly_rent),
        parseInt(bedrooms),
        parseFloat(bathrooms),
        sq_ft ? parseInt(sq_ft) : null,
        status,
        description || null,
        JSON.stringify(Array.isArray(amenities) ? amenities : [])
      ]
    );

    console.log(`[POST /units] Unit ${unit_number} created id:${result.insertId}`);
    res.status(201).json({ success: true, id: result.insertId, message: `Unit ${unit_number} created` });
  } catch (err) {
    console.error('[POST /units]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── PUT /units/:id — update unit ─────────────────────────────────
router.put('/:id', requireAdmin, async (req, res) => {
  try {
    const allowed = ['unit_number','floor','monthly_rent','bedrooms','bathrooms','sq_ft','status','description','amenities'];
    const sets = [], params = [];
    for (const key of allowed) {
      if (req.body[key] !== undefined) {
        sets.push(`${key} = ?`);
        params.push(key === 'amenities' ? JSON.stringify(req.body[key]) : req.body[key]);
      }
    }
    if (!sets.length) return res.status(400).json({ error: 'No fields to update' });
    params.push(req.params.id);
    await db.query(`UPDATE units SET ${sets.join(', ')}, updated_at = NOW() WHERE id = ?`, params);
    res.json({ success: true, message: 'Unit updated' });
  } catch (err) {
    console.error('[PUT /units/:id]', err);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /units/:id/photos — upload photo ─────────────────────────
router.post('/:id/photos', requireAdmin, upload.single('photo'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'No image file provided' });

    // Check if this is first photo — make it primary
    const [[{ count }]] = await db.query('SELECT COUNT(*) AS count FROM unit_photos WHERE unit_id = ?', [req.params.id]);
    const isPrimary = count === 0 ? 1 : 0;

    const filepath = `/uploads/units/${req.file.filename}`;
    const [result] = await db.query(
      'INSERT INTO unit_photos (unit_id, filepath, is_primary, caption) VALUES (?, ?, ?, ?)',
      [req.params.id, filepath, isPrimary, req.body.caption || null]
    );

    res.status(201).json({
      success: true,
      photo: { id: result.insertId, filepath, is_primary: isPrimary }
    });
  } catch (err) {
    console.error('[POST /units/:id/photos]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── DELETE /units/:id/photos/:photoId — remove one photo ──────────
router.delete('/:id/photos/:photoId', requireAdmin, async (req, res) => {
  try {
    const [[photo]] = await db.query(
      'SELECT * FROM unit_photos WHERE id = ? AND unit_id = ?',
      [req.params.photoId, req.params.id]
    );
    if (!photo) return res.status(404).json({ error: 'Photo not found' });

    // Delete file from disk
    const fullPath = path.join(process.cwd(), photo.filepath);
    if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);

    await db.query('DELETE FROM unit_photos WHERE id = ?', [req.params.photoId]);

    // If deleted photo was primary, promote next photo
    if (photo.is_primary) {
      await db.query(
        'UPDATE unit_photos SET is_primary = 1 WHERE unit_id = ? ORDER BY created_at ASC LIMIT 1',
        [req.params.id]
      );
    }
    res.json({ success: true, message: 'Photo deleted' });
  } catch (err) {
    console.error('[DELETE /units/:id/photos/:photoId]', err);
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /units/:id — remove unit ──────────────────────────────
router.delete('/:id', requireAdmin, async (req, res) => {
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();

    const [[unit]] = await conn.query('SELECT * FROM units WHERE id = ?', [req.params.id]);
    if (!unit) { await conn.rollback(); return res.status(404).json({ error: 'Unit not found' }); }

    // Block if active lease exists
    const [[activeLease]] = await conn.query(
      "SELECT id FROM leases WHERE unit_id = ? AND status = 'active' LIMIT 1", [req.params.id]
    );
    if (activeLease) {
      await conn.rollback();
      return res.status(409).json({
        success: false,
        error: `Cannot delete Unit ${unit.unit_number} — it has an active lease. End the lease first.`
      });
    }

    // Delete photo files from disk
    const [photos] = await conn.query('SELECT filepath FROM unit_photos WHERE unit_id = ?', [req.params.id]);
    for (const p of photos) {
      const fp = path.join(process.cwd(), p.filepath);
      if (fs.existsSync(fp)) { try { fs.unlinkSync(fp); } catch {} }
    }

    await conn.query('DELETE FROM unit_photos WHERE unit_id = ?', [req.params.id]);
    await conn.query('DELETE FROM units WHERE id = ?', [req.params.id]);
    await conn.commit();

    console.log(`[DELETE /units/${req.params.id}] Unit ${unit.unit_number} deleted`);
    res.json({ success: true, message: `Unit ${unit.unit_number} deleted` });
  } catch (err) {
    await conn.rollback();
    console.error('[DELETE /units/:id]', err);
    res.status(500).json({ error: err.message });
  } finally {
    conn.release();
  }
});

module.exports = router;
