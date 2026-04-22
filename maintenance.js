// routes/admin.js — Admin dashboard data
const router = require('express').Router();
const db     = require('../database/db');
const { requireAuth, requireAdmin } = require('../middleware/auth');

router.use(requireAuth, requireAdmin);

// GET /api/admin/dashboard — summary stats
router.get('/dashboard', async (req, res) => {
  try {
    const [[units]]   = await db.query("SELECT COUNT(*) c, SUM(status='available') avail, SUM(status='occupied') occ FROM units");
    const [[tenants]] = await db.query("SELECT COUNT(*) c FROM users WHERE role='tenant' AND is_active=1");
    const [[pending]] = await db.query("SELECT COUNT(*) c FROM invoices WHERE status='pending'");
    const [[revenue]] = await db.query("SELECT COALESCE(SUM(amount),0) total FROM payments WHERE status='completed' AND MONTH(paid_at)=MONTH(NOW()) AND YEAR(paid_at)=YEAR(NOW())");
    const [[openMaint]] = await db.query("SELECT COUNT(*) c FROM maintenance_requests WHERE status IN ('open','scheduled')");
    const [[newApps]]   = await db.query("SELECT COUNT(*) c FROM applications WHERE status='submitted'");
    res.json({ success: true, stats: {
      total_units: units.c, available: units.avail, occupied: units.occ,
      active_tenants: tenants.c, pending_invoices: pending.c,
      monthly_revenue: revenue.total, open_maintenance: openMaint.c, new_applications: newApps.c
    }});
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/admin/tenants
router.get('/tenants', async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT u.*, l.unit_id, un.unit_number, un.building_name, l.monthly_rent, l.lease_end
       FROM users u
       LEFT JOIN leases l ON l.tenant_id=u.id AND l.status='active'
       LEFT JOIN units un ON l.unit_id=un.id
       WHERE u.role='tenant' ORDER BY u.created_at DESC`
    );
    res.json({ success: true, tenants: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
