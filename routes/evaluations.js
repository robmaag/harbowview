'use strict';
// routes/evaluations.js — APhoenix Enterprise LLC Tenant Evaluation API

const router = require('express').Router();
const mysql  = require('mysql2/promise');
const jwt    = require('jsonwebtoken');

// ── DB pool (uses same Railway env vars as rest of app) ────────────
const db = mysql.createPool({
  host:     process.env.MYSQLHOST     || 'mysql.railway.internal',
  port:     parseInt(process.env.MYSQLPORT) || 3306,
  database: process.env.MYSQL_DATABASE || 'railway',
  user:     process.env.MYSQLUSER     || 'root',
  password: process.env.MYSQLPASSWORD || '',
  waitForConnections: true,
  connectionLimit: 5,
});

// ── Auth middleware (self-contained — no external file dependency) ──
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

// ── Scoring engine (self-contained) ───────────────────────────────
function computeEvaluation({ applicant, income, credit, rental, background }) {
  const rent = parseFloat(applicant.monthly_rent) || 0;

  // Income (max 25)
  let iScore = 0; const iF = [];
  const inc = parseFloat(income.gross_monthly_income) || 0;
  const ratio = rent > 0 ? +(inc / rent).toFixed(2) : 0;
  if (ratio >= 3.0) iScore += 15; else if (ratio >= 2.5) iScore += 10; else if (ratio >= 2.0) iScore += 5; else iF.push('Income below 2x monthly rent');
  if (income.income_source) iScore += 4;
  if (income.verification_method && income.verification_method !== 'none') iScore += 6;

  // Credit (max 25)
  let cScore = 0; const cF = [];
  const cs = parseInt(credit.credit_score) || 0;
  if (cs >= 720) cScore += 15; else if (cs >= 680) cScore += 12; else if (cs >= 620) cScore += 8; else if (cs >= 580) cScore += 4; else if (cs > 0) cF.push('Credit score below 580');
  if (credit.bankruptcy === 'none') cScore += 5; else if (credit.bankruptcy === 'discharged') cScore += 3; else if (credit.bankruptcy === 'recent' || credit.bankruptcy === 'active') cF.push('Bankruptcy disqualifier');
  if (credit.collections === 'none') cScore += 5; else if (credit.collections === 'minor') cScore += 2; else cF.push('Significant unpaid collections');

  // Rental (max 25)
  let rScore = 0; const rF = [];
  if (rental.eviction === 'none') rScore += 8; else if (rental.eviction === 'old') rScore += 4; else rF.push('Eviction within 7 years');
  if (rental.late_payments === 'none') rScore += 7; else if (rental.late_payments === 'occasional') rScore += 3;
  rScore += ({ '0':0,'1':1,'2':3,'3':4,'5':5 }[rental.rental_years] || 0);
  if (rental.landlord_ref === 'strong') rScore += 5; else if (rental.landlord_ref === 'positive') rScore += 3; else if (rental.landlord_ref === 'negative') rF.push('Negative landlord reference');

  // Background (max 25)
  let bScore = 0; const bF = [];
  if (background.criminal === 'clear') bScore += 10; else if (background.criminal === 'minor_old') bScore += 7; else if (background.criminal === 'minor_recent') bScore += 3; else if (background.criminal === 'violent' || background.criminal === 'sex') bF.push('Criminal record disqualifier');
  if (background.id_verification === 'verified') bScore += 8; else if (background.id_verification === 'pending') bScore += 3; else bF.push('Cannot verify applicant identity');
  if (background.references_result === 'strong') bScore += 7; else if (background.references_result === 'one') bScore += 4;

  const total = Math.min(25,iScore) + Math.min(25,cScore) + Math.min(25,rScore) + Math.min(25,bScore);
  const hardFails = [...iF, ...cF, ...rF, ...bF];
  const status = hardFails.length > 0 ? 'not_qualified' : total >= 75 ? 'qualified' : total >= 55 ? 'conditional' : 'not_qualified';

  return {
    overall_score: total, status, hard_fails: hardFails,
    sections: {
      income:     { score: Math.min(25,iScore), income_rent_ratio: ratio },
      credit:     { score: Math.min(25,cScore) },
      rental:     { score: Math.min(25,rScore) },
      background: { score: Math.min(25,bScore) },
    },
  };
}

// ── GET /api/evaluations/stats ─────────────────────────────────────
router.get('/stats', requireAdmin, async (req, res) => {
  try {
    const [[counts]] = await db.query(`
      SELECT
        COUNT(*) AS total,
        SUM(status = 'qualified') AS qualified,
        SUM(status = 'conditional') AS conditional,
        SUM(status = 'not_qualified') AS not_qualified,
        SUM(status IN ('pending','in_progress')) AS pending,
        ROUND(AVG(overall_score), 1) AS avg_score
      FROM applicant_evaluations
    `);
    const [recent] = await db.query(`
      SELECT id, full_name, unit_type, status, overall_score, application_date
      FROM applicant_evaluations ORDER BY created_at DESC LIMIT 5
    `);
    res.json({ success: true, counts, recent });
  } catch (err) {
    console.error('[GET /evaluations/stats]', err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// ── GET /api/evaluations ───────────────────────────────────────────
router.get('/', requireAdmin, async (req, res) => {
  try {
    const { status, search, page = 1, limit = 20 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    const params = [];
    let where = 'WHERE 1=1';
    if (status) { where += ' AND status = ?'; params.push(status); }
    if (search) { where += ' AND (full_name LIKE ? OR email LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }
    const [rows] = await db.query(
      `SELECT * FROM applicant_evaluations ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      [...params, parseInt(limit), offset]
    );
    const [[{ total }]] = await db.query(`SELECT COUNT(*) AS total FROM applicant_evaluations ${where}`, params);
    res.json({ success: true, evaluations: rows, total, page: parseInt(page), limit: parseInt(limit) });
  } catch (err) {
    console.error('[GET /evaluations]', err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// ── GET /api/evaluations/:id ───────────────────────────────────────
router.get('/:id', requireAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const [[applicant]] = await db.query('SELECT * FROM applicant_evaluations WHERE id = ?', [id]);
    if (!applicant) return res.status(404).json({ success: false, message: 'Not found' });
    const [[income]]     = await db.query('SELECT * FROM eval_income WHERE evaluation_id = ?', [id]);
    const [[credit]]     = await db.query('SELECT * FROM eval_credit WHERE evaluation_id = ?', [id]);
    const [[rental]]     = await db.query('SELECT * FROM eval_rental_history WHERE evaluation_id = ?', [id]);
    const [[background]] = await db.query('SELECT * FROM eval_background WHERE evaluation_id = ?', [id]);
    res.json({ success: true, applicant, income, credit, rental, background });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ── POST /api/evaluations ──────────────────────────────────────────
router.post('/', requireAdmin, async (req, res) => {
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();
    const { full_name, email, phone, unit_type, monthly_rent, application_date, admin_notes } = req.body;
    if (!full_name || !email || !unit_type || !monthly_rent) {
      await conn.rollback();
      return res.status(400).json({ success: false, message: 'full_name, email, unit_type, monthly_rent required' });
    }
    const [result] = await conn.query(
      `INSERT INTO applicant_evaluations (full_name, email, phone, unit_type, monthly_rent, application_date, admin_notes)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [full_name, email, phone || null, unit_type, monthly_rent,
       application_date || new Date().toISOString().split('T')[0], admin_notes || null]
    );
    await conn.query(
      `INSERT INTO eval_audit_log (evaluation_id, admin_user, action, ip_address) VALUES (?,?,?,?)`,
      [result.insertId, req.user?.email || 'admin', 'APPLICANT_CREATED', req.ip]
    );
    await conn.commit();
    res.status(201).json({ success: true, id: result.insertId, message: 'Applicant created' });
  } catch (err) {
    await conn.rollback();
    res.status(500).json({ success: false, message: err.message });
  } finally { conn.release(); }
});

// ── PUT /api/evaluations/:id/evaluate ─────────────────────────────
router.put('/:id/evaluate', requireAdmin, async (req, res) => {
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();
    const id = parseInt(req.params.id);
    const [[applicant]] = await conn.query('SELECT * FROM applicant_evaluations WHERE id = ?', [id]);
    if (!applicant) { await conn.rollback(); return res.status(404).json({ success: false, message: 'Not found' }); }
    const { income = {}, credit = {}, rental = {}, background = {} } = req.body;
    const ev = computeEvaluation({ applicant, income, credit, rental, background });

    await conn.query(
      `INSERT INTO eval_income (evaluation_id, gross_monthly_income, income_source, verification_method, income_rent_ratio, section_score, passes)
       VALUES (?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE gross_monthly_income=VALUES(gross_monthly_income),
       income_source=VALUES(income_source), verification_method=VALUES(verification_method),
       income_rent_ratio=VALUES(income_rent_ratio), section_score=VALUES(section_score), passes=VALUES(passes)`,
      [id, income.gross_monthly_income||0, income.income_source||null, income.verification_method||'none',
       ev.sections.income.income_rent_ratio, ev.sections.income.score, ev.sections.income.score>=15?1:0]
    );
    await conn.query(
      `INSERT INTO eval_credit (evaluation_id, credit_score, bankruptcy, collections, section_score, passes)
       VALUES (?,?,?,?,?,?) ON DUPLICATE KEY UPDATE credit_score=VALUES(credit_score),
       bankruptcy=VALUES(bankruptcy), collections=VALUES(collections),
       section_score=VALUES(section_score), passes=VALUES(passes)`,
      [id, credit.credit_score||null, credit.bankruptcy||'none', credit.collections||'none',
       ev.sections.credit.score, ev.sections.credit.score>=15?1:0]
    );
    await conn.query(
      `INSERT INTO eval_rental_history (evaluation_id, rental_years, eviction, late_payments, landlord_ref, section_score, passes)
       VALUES (?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE rental_years=VALUES(rental_years),
       eviction=VALUES(eviction), late_payments=VALUES(late_payments), landlord_ref=VALUES(landlord_ref),
       section_score=VALUES(section_score), passes=VALUES(passes)`,
      [id, rental.rental_years||'0', rental.eviction||'none', rental.late_payments||'none',
       rental.landlord_ref||'not_contacted', ev.sections.rental.score, ev.sections.rental.score>=15?1:0]
    );
    await conn.query(
      `INSERT INTO eval_background (evaluation_id, criminal, id_verification, references_result, section_score, passes)
       VALUES (?,?,?,?,?,?) ON DUPLICATE KEY UPDATE criminal=VALUES(criminal),
       id_verification=VALUES(id_verification), references_result=VALUES(references_result),
       section_score=VALUES(section_score), passes=VALUES(passes)`,
      [id, background.criminal||'not_reviewed', background.id_verification||'pending',
       background.references_result||'not_collected', ev.sections.background.score, ev.sections.background.score>=15?1:0]
    );
    await conn.query(
      `UPDATE applicant_evaluations SET overall_score=?, status=?, hard_fails=?, updated_at=NOW() WHERE id=?`,
      [ev.overall_score, ev.status, JSON.stringify(ev.hard_fails), id]
    );
    await conn.query(
      `INSERT INTO eval_audit_log (evaluation_id, admin_user, action, detail, ip_address) VALUES (?,?,?,?,?)`,
      [id, req.user?.email||'admin', 'EVALUATION_SAVED', `Score:${ev.overall_score}|Status:${ev.status}`, req.ip]
    );
    await conn.commit();
    res.json({ success: true, evaluation: ev, message: 'Evaluation saved' });
  } catch (err) {
    await conn.rollback();
    res.status(500).json({ success: false, message: err.message });
  } finally { conn.release(); }
});

// ── PATCH /api/evaluations/:id/notes ──────────────────────────────
router.patch('/:id/notes', requireAdmin, async (req, res) => {
  try {
    await db.query('UPDATE applicant_evaluations SET admin_notes=? WHERE id=?', [req.body.admin_notes||null, req.params.id]);
    res.json({ success: true, message: 'Notes updated' });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// ── DELETE /api/evaluations/:id ────────────────────────────────────
router.delete('/:id', requireAdmin, async (req, res) => {
  try {
    await db.query('DELETE FROM applicant_evaluations WHERE id = ?', [req.params.id]);
    await db.query(`INSERT INTO eval_audit_log (evaluation_id, admin_user, action, ip_address) VALUES (?,?,?,?)`,
      [req.params.id, req.user?.email||'admin', 'APPLICANT_DELETED', req.ip]);
    res.json({ success: true, message: 'Deleted' });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

module.exports = router;
