// routes/documents.js
const router = require('express').Router();
const db     = require('../database/db');
const path   = require('path');
const fs     = require('fs');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const { requireAuth, requireAdmin } = require('../middleware/auth');

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, '..', 'uploads', 'documents');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname).toLowerCase()}`)
});
const upload = multer({ storage, limits: { fileSize: 20 * 1024 * 1024, files: 1 } });

router.get('/', requireAuth, async (req, res) => {
  try {
    let sql = 'SELECT * FROM documents WHERE 1=1';
    const params = [];
    if (req.user.role !== 'admin') { sql += ' AND owner_id=?'; params.push(req.user.id); }
    sql += ' ORDER BY uploaded_at DESC';
    const [rows] = await db.query(sql, params);
    res.json({ success: true, documents: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post('/', requireAuth, upload.single('file'), async (req, res) => {
  try {
    const { title, related_type, related_id, owner_id } = req.body;
    const f = req.file;
    const ownerId = req.user.role === 'admin' && owner_id ? owner_id : req.user.id;
    const [result] = await db.query(
      'INSERT INTO documents (owner_id,related_type,related_id,title,filename,filepath,file_size,mime_type,uploaded_by) VALUES (?,?,?,?,?,?,?,?,?)',
      [ownerId, related_type || 'general', related_id || null, title, f.filename,
       `/uploads/documents/${f.filename}`, f.size, f.mimetype, req.user.id]
    );
    res.status(201).json({ success: true, document_id: result.insertId });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
