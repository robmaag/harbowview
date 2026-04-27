// routes/leases.js — Lease generation and e-signature system
const router = require('express').Router();
const db = require('../database/db');
const { requireAuth, requireAdmin } = require('../middleware/auth');

// GET /api/leases — get all leases (admin) or tenant's lease
router.get('/', requireAuth, async (req, res) => {
  try {
    let sql = `SELECT l.*, u.unit_number, u.monthly_rent as unit_rent,
               CONCAT(t.first_name, ' ', t.last_name) as tenant_name,
               t.email as tenant_email
               FROM leases l
               JOIN units u ON l.unit_id = u.id
               JOIN users t ON l.tenant_id = t.id
               WHERE 1=1`;
    const params = [];
    if (req.user.role !== 'admin') {
      sql += ' AND l.tenant_id = ?';
      params.push(req.user.id);
    }
    sql += ' ORDER BY l.created_at DESC';
    const [rows] = await db.query(sql, params);
    res.json({ success: true, leases: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// POST /api/leases/generate — Admin generates lease for approved applicant
router.post('/generate', requireAdmin, async (req, res) => {
  try {
    const {
      tenant_id, unit_id, start_date, end_date, monthly_rent,
      security_deposit, late_fee, grace_period_days,
      pet_allowed, pet_deposit, pet_monthly_fee,
      utilities_included, parking_included, parking_fee,
      special_terms
    } = req.body;

    // Get tenant info
    const [tenants] = await db.query('SELECT * FROM users WHERE id = ?', [tenant_id]);
    if (!tenants.length) throw new Error('Tenant not found');
    const tenant = tenants[0];

    // Get unit info
    const [units] = await db.query('SELECT * FROM units WHERE id = ?', [unit_id]);
    if (!units.length) throw new Error('Unit not found');
    const unit = units[0];

    // Generate lease content
    const leaseContent = generateLeaseContent({
      tenant, unit, start_date, end_date, monthly_rent,
      security_deposit, late_fee, grace_period_days,
      pet_allowed, pet_deposit, pet_monthly_fee,
      utilities_included, parking_included, parking_fee,
      special_terms,
      generated_date: new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })
    });

    // Save lease to database
    const [result] = await db.query(
      `INSERT INTO leases (tenant_id, unit_id, start_date, end_date, monthly_rent,
       security_deposit, status, lease_document, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'pending_signature', ?, NOW())`,
      [tenant_id, unit_id, start_date, end_date, monthly_rent,
       security_deposit || monthly_rent * 2, leaseContent]
    );

    // Update unit status
    await db.query("UPDATE units SET status = 'reserved' WHERE id = ?", [unit_id]);

    res.json({
      success: true,
      lease_id: result.insertId,
      message: 'Lease generated successfully. Tenant can now review and sign.'
    });

  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/leases/:id — Get specific lease with content
router.get('/:id', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT l.*, u.unit_number, u.address, u.city, u.state, u.zip,
       CONCAT(t.first_name, ' ', t.last_name) as tenant_name,
       t.email as tenant_email, t.phone as tenant_phone
       FROM leases l
       JOIN units u ON l.unit_id = u.id
       JOIN users t ON l.tenant_id = t.id
       WHERE l.id = ?`, [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ success: false, message: 'Lease not found' });
    
    const lease = rows[0];
    if (req.user.role !== 'admin' && lease.tenant_id !== req.user.id) {
      return res.status(403).json({ success: false, message: 'Unauthorized' });
    }
    
    res.json({ success: true, lease });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// POST /api/leases/:id/sign — Tenant signs the lease
router.post('/:id/sign', requireAuth, async (req, res) => {
  try {
    const { signature, agreed } = req.body;
    
    if (!agreed || !signature) {
      return res.status(400).json({ success: false, message: 'Signature and agreement required' });
    }

    const [rows] = await db.query('SELECT * FROM leases WHERE id = ?', [req.params.id]);
    if (!rows.length) return res.status(404).json({ success: false, message: 'Lease not found' });
    
    const lease = rows[0];
    if (lease.tenant_id !== req.user.id) {
      return res.status(403).json({ success: false, message: 'Unauthorized' });
    }
    if (lease.status === 'active') {
      return res.status(400).json({ success: false, message: 'Lease already signed' });
    }

    const signedAt = new Date().toISOString();
    const signatureBlock = `\n\n--- DIGITALLY SIGNED ---\nTenant: ${signature}\nDate: ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}\nTime: ${new Date().toLocaleTimeString()}\nIP Signature Record: ${signedAt}\nThis electronic signature is legally binding under California Civil Code and the Electronic Signatures in Global and National Commerce Act (ESIGN).`;

    await db.query(
      `UPDATE leases SET status = 'active', signed_at = NOW(), 
       tenant_signature = ?, lease_document = CONCAT(lease_document, ?)
       WHERE id = ?`,
      [signature, signatureBlock, req.params.id]
    );

    // Update unit to occupied
    await db.query("UPDATE units SET status = 'occupied' WHERE id = ?", [lease.unit_id]);

    res.json({ success: true, message: 'Lease signed successfully! Welcome home.' });

  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Helper: Generate California-compliant lease content
function generateLeaseContent(data) {
  const { tenant, unit, start_date, end_date, monthly_rent, security_deposit,
    late_fee, grace_period_days, pet_allowed, pet_deposit, pet_monthly_fee,
    utilities_included, parking_included, parking_fee, special_terms, generated_date } = data;

  const startFormatted = new Date(start_date).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  const endFormatted = new Date(end_date).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  const gracedays = grace_period_days || 5;
  const lateFeeAmt = late_fee || 50;
  const deposit = security_deposit || monthly_rent * 2;

  return `
CALIFORNIA RESIDENTIAL LEASE AGREEMENT

Generated: ${generated_date}
Lease ID: APE-${Date.now()}

================================================================================
PARTIES
================================================================================

LANDLORD: A Phoenix Enterprises LLC
Address: 100 Phoenix Plaza, Concord, CA 94520
Phone: (415) 555-0200
Email: hello@aphoenixenterprises.com

TENANT(S): ${tenant.first_name} ${tenant.last_name}
Email: ${tenant.email}
Phone: ${tenant.phone || 'N/A'}

================================================================================
PREMISES
================================================================================

Unit Number: ${unit.unit_number}
Property Address: ${unit.address || '100 Phoenix Plaza'}, Concord, CA 94520
Type: Residential Apartment

================================================================================
LEASE TERM
================================================================================

This lease begins on ${startFormatted} and ends on ${endFormatted}.
This is a fixed-term tenancy. At the end of the term, this lease will convert
to a month-to-month tenancy unless either party provides 30 days written notice.

================================================================================
RENT
================================================================================

1. MONTHLY RENT: $${parseFloat(monthly_rent).toFixed(2)} per month
2. DUE DATE: Rent is due on the 1st day of each month.
3. GRACE PERIOD: Rent is considered late after the ${gracedays}th day of the month.
4. LATE FEE: A late fee of $${lateFeeAmt}.00 will be charged for rent received
   after the grace period. (California Civil Code § 1671)
5. PAYMENT METHOD: Rent shall be paid via the A Phoenix Enterprises tenant portal
   at https://melodic-griffin-a29a8a.netlify.app or via PayPal to APhoenixEnterprise.
6. RETURNED CHECKS: A $25.00 fee will be charged for returned checks.

================================================================================
SECURITY DEPOSIT
================================================================================

Security Deposit Amount: $${parseFloat(deposit).toFixed(2)}
(Not to exceed 2 months' rent per California Civil Code § 1950.5)

The security deposit will be returned within 21 days after Tenant vacates,
minus any deductions for unpaid rent, cleaning, or damages beyond normal wear
and tear, along with an itemized statement. (California Civil Code § 1950.5)

================================================================================
UTILITIES & SERVICES
================================================================================

The following utilities are ${utilities_included ? 'INCLUDED' : 'NOT INCLUDED'} in rent:
${utilities_included ? '✓ Water, Sewer, Garbage' : '✗ Water, Sewer, Garbage — Tenant responsible'}
✗ Electricity — Tenant responsible
✗ Gas — Tenant responsible
✗ Internet/Cable — Tenant responsible

================================================================================
PARKING
================================================================================

${parking_included ? `Parking: ONE (1) parking space is included with this unit.` : 
`Parking: Not included. Additional parking available for $${parking_fee || 75}.00/month.`}

================================================================================
PETS
================================================================================

${pet_allowed ? 
`Pets are permitted with the following conditions:
- Pet Deposit: $${pet_deposit || 500}.00 (refundable)
- Monthly Pet Fee: $${pet_monthly_fee || 50}.00
- Maximum 2 pets. No aggressive breeds.
- Tenant is liable for all pet-related damages.` :
`NO PETS are permitted on the premises without prior written approval from Landlord.`}

================================================================================
OCCUPANCY
================================================================================

The premises shall be occupied only by the Tenant(s) named above.
No additional occupants without written approval from Landlord.
Subletting is not permitted without prior written consent.

================================================================================
MAINTENANCE & REPAIRS
================================================================================

Tenant shall:
- Keep the unit clean and sanitary
- Dispose of garbage properly
- Report any needed repairs promptly through the tenant portal
- Not make alterations without written consent
- Be responsible for damages caused by Tenant or guests

Landlord shall maintain the unit in habitable condition per California Civil Code § 1941.

================================================================================
ENTRY BY LANDLORD
================================================================================

Landlord shall provide at least 24 hours written notice before entering the unit,
except in cases of emergency. (California Civil Code § 1954)

================================================================================
NOISE & NUISANCE
================================================================================

Tenant agrees not to disturb neighbors. Quiet hours are 10:00 PM to 8:00 AM.
Violation may result in a 3-Day Notice to Cure or Quit.

================================================================================
SMOKING
================================================================================

SMOKING IS PROHIBITED in the unit, on balconies, and in all common areas
per California Government Code § 7597.

================================================================================
RENTERS INSURANCE
================================================================================

Tenant is strongly encouraged to obtain renters insurance. Landlord's insurance
does not cover Tenant's personal property.

================================================================================
MOLD DISCLOSURE
================================================================================

Tenant acknowledges receipt of the California Department of Health Services
consumer booklet on toxic mold. Tenant shall promptly report any moisture or
mold issues to Landlord. (California Health & Safety Code § 26147)

================================================================================
LEAD PAINT DISCLOSURE
================================================================================

${new Date().getFullYear() - 1978 > 0 ? 
'If the building was constructed before 1978, a lead-based paint disclosure has been provided separately as required by federal law (42 U.S.C. § 4852d).' :
'Building constructed after 1978. Lead paint disclosure not required.'}

================================================================================
RENT CONTROL NOTICE (AB 1482)
================================================================================

This unit ${unit.rent_controlled ? 'IS' : 'MAY BE'} subject to California AB 1482
(Tenant Protection Act of 2019). Under AB 1482, annual rent increases are limited
to 5% plus local CPI (max 10%). Tenant has just cause eviction protections after
12 months of tenancy.

================================================================================
TERMINATION
================================================================================

Either party may terminate this lease at the end of the term with 30 days
written notice. After 1 year of tenancy, Landlord must provide 60 days notice
and just cause for termination per California Civil Code § 1946.2.

================================================================================
DEFAULT
================================================================================

If Tenant fails to pay rent, Landlord may serve a 3-Day Notice to Pay Rent or Quit.
If Tenant violates any other term, Landlord may serve a 3-Day Notice to Cure or Quit.

================================================================================
SPECIAL TERMS & CONDITIONS
================================================================================

${special_terms || 'None.'}

================================================================================
ENTIRE AGREEMENT
================================================================================

This lease constitutes the entire agreement between the parties. Any modifications
must be in writing and signed by both parties. This agreement shall be governed
by the laws of the State of California.

================================================================================
SIGNATURES
================================================================================

By signing below, both parties agree to all terms of this Lease Agreement.

LANDLORD: A Phoenix Enterprises LLC

Signature: _________________________________ Date: _______________
Robert Maagdenberg, Authorized Agent

TENANT: ${tenant.first_name} ${tenant.last_name}

[AWAITING TENANT E-SIGNATURE]

By electronically signing this agreement, Tenant acknowledges reading,
understanding, and agreeing to all terms above. This electronic signature
is legally binding under California Civil Code and the ESIGN Act.
`;
}

module.exports = router;
