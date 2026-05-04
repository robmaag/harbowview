'use strict';
// routes/evaluations.js
// Tenant Evaluation API — APhoenix Enterprise LLC
// Plug into app.js the same way as your existing routes:
//   const evaluationsRouter = require('./routes/evaluations');
//   app.use('/api/evaluations', evaluationsRouter);

const router = require('express').Router();
// const db     = require('../database/db');
const mysql = require('mysql2/promise');
const db = mysql.createPool({
  host:     process.env.MYSQLHOST     || 'mysql.railway.internal',
  port:     parseInt(process.env.MYSQLPORT) || 3306,
  database: process.env.MYSQL_DATABASE || 'railway',
  user:     process.env.MYSQLUSER     || 'root',
  password: process.env.MYSQLPASSWORD || '',
  waitForConnections: true,
  connectionLimit: 5,
});
//const { requireAuth, requireAdmin } = require('../middleware/auth');
const { requireAuth, requireAdmin } = require('./auth');
const { computeEvaluation }         = require('../middleware/scorer');

// ── GET /api/evaluations — list all (admin) ────────────────────────
router.get('/', requireAdmin, async (req, res) => {
  try {
    const { status, search, page = 1, limit = 20 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    const params = [];
    let where = 'WHERE 1=1';

    if (status) { where += ' AND ae.status = ?';               params.push(status); }
    if (search) { where += ' AND (ae.full_name LIKE ? OR ae.email LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }

    const [rows]  = await db.query(
      `SELECT * FROM v_evaluation_summary ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      [...params, parseInt(limit), offset]
    );
    const [[{ total }]] = await db.query(
      `SELECT COUNT(*) AS total FROM applicant_evaluations ae ${where}`, params
    );

    res.json({ success: true, evaluations: rows, total, page: parseInt(page), limit: parseInt(limit) });
  } catch (err) {
    console.error('[GET /evaluations]', err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// ── GET /api/evaluations/stats — dashboard summary ─────────────────
router.get('/stats', requireAdmin, async (req, res) => {
  try {
    const [[counts]] = await db.query(`
      SELECT
        COUNT(*)                              AS total,
        SUM(status = 'qualified')             AS qualified,
        SUM(status = 'conditional')           AS conditional,
        SUM(status = 'not_qualified')         AS not_qualified,
        SUM(status IN ('pending','in_progress')) AS pending,
        ROUND(AVG(overall_score), 1)          AS avg_score
      FROM applicant_evaluations
    `);

    const [recent] = await db.query(`
      SELECT id, full_name, unit_type, status, overall_score, application_date
      FROM applicant_evaluations
      ORDER BY created_at DESC LIMIT 5
    `);

    res.json({ success: true, counts, recent });
  } catch (err) {
    console.error('[GET /evaluations/stats]', err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// ── GET /api/evaluations/:id — single full record ──────────────────
router.get('/:id', requireAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const [[applicant]] = await db.query('SELECT * FROM applicant_evaluations WHERE id = ?', [id]);
    if (!applicant) return res.status(404).json({ success: false, message: 'Evaluation not found' });

    const [[income]]     = await db.query('SELECT * FROM eval_income WHERE evaluation_id = ?', [id]);
    const [[credit]]     = await db.query('SELECT * FROM eval_credit WHERE evaluation_id = ?', [id]);
    const [[rental]]     = await db.query('SELECT * FROM eval_rental_history WHERE evaluation_id = ?', [id]);
    const [[background]] = await db.query('SELECT * FROM eval_background WHERE evaluation_id = ?', [id]);

    res.json({ success: true, applicant, income, credit, rental, background });
  } catch (err) {
    console.error('[GET /evaluations/:id]', err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// ── POST /api/evaluations — create new applicant record ────────────
router.post('/', requireAdmin, async (req, res) => {
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();

    const {
      full_name, email, phone, unit_type, monthly_rent,
      application_date, admin_notes
    } = req.body;

    if (!full_name || !email || !unit_type || !monthly_rent) {
      await conn.rollback();
      return res.status(400).json({ success: false, message: 'full_name, email, unit_type, monthly_rent are required' });
    }

    const [result] = await conn.query(
      `INSERT INTO applicant_evaluations
         (full_name, email, phone, unit_type, monthly_rent, application_date, admin_notes)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [full_name, email, phone || null, unit_type, monthly_rent,
       application_date || new Date().toISOString().split('T')[0],
       admin_notes || null]
    );

    await conn.query(
      `INSERT INTO eval_audit_log (evaluation_id, admin_user, action, ip_address)
       VALUES (?, ?, 'APPLICANT_CREATED', ?)`,
      [result.insertId, req.user?.username || req.user?.email || 'admin', req.ip]
    );

    await conn.commit();
    res.status(201).json({ success: true, id: result.insertId, message: 'Applicant created' });
  } catch (err) {
    await conn.rollback();
    console.error('[POST /evaluations]', err);
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ── PUT /api/evaluations/:id/evaluate — save all 4 sections + score ─
router.put('/:id/evaluate', requireAdmin, async (req, res) => {
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();

    const id = parseInt(req.params.id);
    const [[applicant]] = await conn.query(
      'SELECT * FROM applicant_evaluations WHERE id = ?', [id]
    );
    if (!applicant) {
      await conn.rollback();
      return res.status(404).json({ success: false, message: 'Applicant not found' });
    }

    const { income = {}, credit = {}, rental = {}, background = {} } = req.body;

    // Run scoring engine
    const ev = computeEvaluation({ applicant, income, credit, rental, background });

    // Upsert eval_income
    await conn.query(
      `INSERT INTO eval_income
         (evaluation_id, gross_monthly_income, income_source, verification_method, income_rent_ratio, section_score, passes)
       VALUES (?,?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE
         gross_monthly_income=VALUES(gross_monthly_income),
         income_source=VALUES(income_source),
         verification_method=VALUES(verification_method),
         income_rent_ratio=VALUES(income_rent_ratio),
         section_score=VALUES(section_score),
         passes=VALUES(passes)`,
      [id,
       income.gross_monthly_income || 0,
       income.income_source || null,
       income.verification_method || 'none',
       ev.sections.income.income_rent_ratio,
       ev.sections.income.score,
       ev.sections.income.score >= 15 ? 1 : 0]
    );

    // Upsert eval_credit
    await conn.query(
      `INSERT INTO eval_credit
         (evaluation_id, credit_score, bankruptcy, collections, section_score, passes)
       VALUES (?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE
         credit_score=VALUES(credit_score),
         bankruptcy=VALUES(bankruptcy),
         collections=VALUES(collections),
         section_score=VALUES(section_score),
         passes=VALUES(passes)`,
      [id,
       credit.credit_score || null,
       credit.bankruptcy || 'none',
       credit.collections || 'none',
       ev.sections.credit.score,
       ev.sections.credit.score >= 15 ? 1 : 0]
    );

    // Upsert eval_rental_history
    await conn.query(
      `INSERT INTO eval_rental_history
         (evaluation_id, rental_years, eviction, late_payments, landlord_ref, section_score, passes)
       VALUES (?,?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE
         rental_years=VALUES(rental_years),
         eviction=VALUES(eviction),
         late_payments=VALUES(late_payments),
         landlord_ref=VALUES(landlord_ref),
         section_score=VALUES(section_score),
         passes=VALUES(passes)`,
      [id,
       rental.rental_years || '0',
       rental.eviction || 'none',
       rental.late_payments || 'none',
       rental.landlord_ref || 'not_contacted',
       ev.sections.rental.score,
       ev.sections.rental.score >= 15 ? 1 : 0]
    );

    // Upsert eval_background
    await conn.query(
      `INSERT INTO eval_background
         (evaluation_id, criminal, id_verification, references_result, section_score, passes)
       VALUES (?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE
         criminal=VALUES(criminal),
         id_verification=VALUES(id_verification),
         references_result=VALUES(references_result),
         section_score=VALUES(section_score),
         passes=VALUES(passes)`,
      [id,
       background.criminal || 'not_reviewed',
       background.id_verification || 'pending',
       background.references_result || 'not_collected',
       ev.sections.background.score,
       ev.sections.background.score >= 15 ? 1 : 0]
    );

    // Update master record
    await conn.query(
      `UPDATE applicant_evaluations
       SET overall_score=?, status=?, hard_fails=?, updated_at=NOW()
       WHERE id=?`,
      [ev.overall_score, ev.status, JSON.stringify(ev.hard_fails), id]
    );

    // Audit
    await conn.query(
      `INSERT INTO eval_audit_log (evaluation_id, admin_user, action, detail, ip_address)
       VALUES (?,?,?,?,?)`,
      [id,
       req.user?.username || req.user?.email || 'admin',
       'EVALUATION_SAVED',
       `Score: ${ev.overall_score} | Status: ${ev.status}`,
       req.ip]
    );

    await conn.commit();
    res.json({ success: true, evaluation: ev, message: 'Evaluation saved' });
  } catch (err) {
    await conn.rollback();
    console.error('[PUT /evaluations/:id/evaluate]', err);
    res.status(500).json({ success: false, message: err.message });
  } finally {
    conn.release();
  }
});

// ── PATCH /api/evaluations/:id/notes ──────────────────────────────
router.patch('/:id/notes', requireAdmin, async (req, res) => {
  try {
    await db.query(
      'UPDATE applicant_evaluations SET admin_notes=? WHERE id=?',
      [req.body.admin_notes || null, req.params.id]
    );
    res.json({ success: true, message: 'Notes updated' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ── DELETE /api/evaluations/:id — hard delete ──────────────────────
router.delete('/:id', requireAdmin, async (req, res) => {
  try {
    await db.query('DELETE FROM applicant_evaluations WHERE id = ?', [req.params.id]);
    await db.query(
      `INSERT INTO eval_audit_log (evaluation_id, admin_user, action, ip_address) VALUES (?,?,?,?)`,
      [req.params.id, req.user?.username || 'admin', 'APPLICANT_DELETED', req.ip]
    );
    res.json({ success: true, message: 'Evaluation deleted' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
