'use strict';
// middleware/scorer.js — Tenant qualification scoring engine
// Concord, CA — aligned with CA FEHA, AB 2819, AB 12 (2024)
// Each section max = 25 pts → total max = 100
// ≥75 = qualified | 55–74 = conditional | <55 = not_qualified
// Hard disqualifiers override score regardless of total.

function scoreIncome({ gross_monthly_income, income_source, verification_method, monthly_rent }) {
  let score = 0;
  const hardFail = [], criteria = [];
  const rent   = parseFloat(monthly_rent) || 0;
  const income = parseFloat(gross_monthly_income) || 0;
  const ratio  = rent > 0 ? +(income / rent).toFixed(2) : 0;

  if (ratio >= 3.0)      { score += 15; criteria.push({ pass: true,  text: `Income ratio ${ratio}x — strong (≥3.0x)` }); }
  else if (ratio >= 2.5) { score += 10; criteria.push({ pass: true,  text: `Income ratio ${ratio}x — meets 2.5x minimum` }); }
  else if (ratio >= 2.0) { score += 5;  criteria.push({ pass: false, text: `Income ratio ${ratio}x — below preferred 2.5x` }); }
  else {
    criteria.push({ pass: false, text: `Income ratio ${ratio}x — hard fail (min 2.0x)` });
    hardFail.push('Income below 2x monthly rent');
  }

  if (income_source) {
    score += 4;
    const label = income_source === 'section8' ? 'Section 8 voucher (CA FEHA protected)' : income_source;
    criteria.push({ pass: true, text: `Income source: ${label}` });
  } else {
    criteria.push({ pass: null, text: 'Income source not specified' });
  }

  if (verification_method && verification_method !== 'none') {
    score += 6;
    criteria.push({ pass: true, text: `Verified via: ${verification_method}` });
  } else {
    criteria.push({ pass: null, text: 'No income documentation provided' });
  }

  return { score: Math.min(25, score), hardFail, criteria, income_rent_ratio: ratio };
}

function scoreCredit({ credit_score, bankruptcy, collections }) {
  let score = 0;
  const hardFail = [], criteria = [];
  const cs = parseInt(credit_score) || 0;

  if (cs >= 720)       { score += 15; criteria.push({ pass: true,  text: `Credit score ${cs} — excellent` }); }
  else if (cs >= 680)  { score += 12; criteria.push({ pass: true,  text: `Credit score ${cs} — good` }); }
  else if (cs >= 620)  { score += 8;  criteria.push({ pass: true,  text: `Credit score ${cs} — acceptable` }); }
  else if (cs >= 580)  { score += 4;  criteria.push({ pass: false, text: `Credit score ${cs} — below preferred 620` }); }
  else if (cs > 0) {
    criteria.push({ pass: false, text: `Credit score ${cs} — hard fail (min 580)` });
    hardFail.push('Credit score below 580');
  }

  if (bankruptcy === 'none')            { score += 5; criteria.push({ pass: true,  text: 'No bankruptcy on record' }); }
  else if (bankruptcy === 'discharged') { score += 3; criteria.push({ pass: true,  text: 'Bankruptcy discharged >4 years ago' }); }
  else if (bankruptcy === 'recent')     { hardFail.push('Bankruptcy discharged <4 years'); criteria.push({ pass: false, text: 'Bankruptcy <4 years — hard fail' }); }
  else if (bankruptcy === 'active')     { hardFail.push('Active bankruptcy'); criteria.push({ pass: false, text: 'Active bankruptcy — hard fail' }); }

  if (collections === 'none')       { score += 5; criteria.push({ pass: true,  text: 'No collections' }); }
  else if (collections === 'minor') { score += 2; criteria.push({ pass: true,  text: 'Minor/paid collections' }); }
  else { hardFail.push('Significant unpaid collections'); criteria.push({ pass: false, text: 'Significant unpaid collections — hard fail' }); }

  return { score: Math.min(25, score), hardFail, criteria };
}

function scoreRentalHistory({ rental_years, eviction, late_payments, landlord_ref }) {
  let score = 0;
  const hardFail = [], criteria = [];

  if (eviction === 'none')     { score += 8; criteria.push({ pass: true,  text: 'No eviction history' }); }
  else if (eviction === 'old') { score += 4; criteria.push({ pass: true,  text: 'Eviction record >7 years ago (CA AB 2819 may seal)' }); }
  else { hardFail.push('Eviction within 7 years'); criteria.push({ pass: false, text: 'Eviction within 7 years — hard fail' }); }

  if (late_payments === 'none')            { score += 7; criteria.push({ pass: true,  text: 'No late payment history' }); }
  else if (late_payments === 'occasional') { score += 3; criteria.push({ pass: true,  text: '1–2 occasional late payments' }); }
  else { criteria.push({ pass: false, text: 'Pattern of late payments' }); }

  const yrs = { '0': 0, '1': 1, '2': 3, '3': 4, '5': 5 };
  score += yrs[rental_years] ?? 0;
  criteria.push({ pass: (yrs[rental_years] ?? 0) > 0, text: `Rental history: ${rental_years === '0' ? 'first-time renter' : rental_years + '+ years'}` });

  if (landlord_ref === 'strong')        { score += 5; criteria.push({ pass: true,  text: 'Strong positive landlord reference' }); }
  else if (landlord_ref === 'positive') { score += 3; criteria.push({ pass: true,  text: 'Positive landlord reference' }); }
  else if (landlord_ref === 'negative') { hardFail.push('Negative landlord reference'); criteria.push({ pass: false, text: 'Negative landlord reference' }); }
  else { criteria.push({ pass: null, text: `Landlord reference: ${landlord_ref || 'not contacted'}` }); }

  return { score: Math.min(25, score), hardFail, criteria };
}

function scoreBackground({ criminal, id_verification, references_result }) {
  let score = 0;
  const hardFail = [], criteria = [];

  if (criminal === 'clear')             { score += 10; criteria.push({ pass: true,  text: 'No criminal history' }); }
  else if (criminal === 'minor_old')    { score += 7;  criteria.push({ pass: true,  text: 'Minor offense >7 yrs ago — individualized assessment applied' }); }
  else if (criminal === 'minor_recent') { score += 3;  criteria.push({ pass: false, text: 'Minor offense, recent — CA FEHA individualized assessment required' }); }
  else if (criminal === 'violent' || criminal === 'sex') {
    hardFail.push(criminal === 'sex' ? 'Registered sex offender' : 'Violent/drug-related record');
    criteria.push({ pass: false, text: `${criminal === 'sex' ? 'Sex offense' : 'Violent/drug record'} — hard fail` });
  } else { criteria.push({ pass: null, text: 'Criminal check not yet reviewed' }); }

  if (id_verification === 'verified')       { score += 8; criteria.push({ pass: true,  text: 'Identity verified' }); }
  else if (id_verification === 'pending')   { score += 3; criteria.push({ pass: null,  text: 'Identity verification pending' }); }
  else { hardFail.push('Cannot verify applicant identity'); criteria.push({ pass: false, text: 'ID verification failed — hard fail' }); }

  if (references_result === 'strong')       { score += 7; criteria.push({ pass: true,  text: '2+ strong references' }); }
  else if (references_result === 'one')     { score += 4; criteria.push({ pass: true,  text: '1 reference provided' }); }
  else if (references_result === 'none')    { criteria.push({ pass: false, text: 'No references provided' }); }
  else { criteria.push({ pass: null, text: 'References not yet collected' }); }

  return { score: Math.min(25, score), hardFail, criteria };
}

function computeEvaluation({ applicant, income, credit, rental, background }) {
  const incomeR     = scoreIncome({ ...income, monthly_rent: applicant.monthly_rent });
  const creditR     = scoreCredit(credit);
  const rentalR     = scoreRentalHistory(rental);
  const backgroundR = scoreBackground(background);

  const total     = incomeR.score + creditR.score + rentalR.score + backgroundR.score;
  const hardFails = [...incomeR.hardFail, ...creditR.hardFail, ...rentalR.hardFail, ...backgroundR.hardFail];

  const status = hardFails.length > 0 ? 'not_qualified'
    : total >= 75 ? 'qualified'
    : total >= 55 ? 'conditional'
    : 'not_qualified';

  return {
    overall_score: total,
    status,
    hard_fails: hardFails,
    sections: {
      income:     { score: incomeR.score,     criteria: incomeR.criteria,     income_rent_ratio: incomeR.income_rent_ratio },
      credit:     { score: creditR.score,     criteria: creditR.criteria },
      rental:     { score: rentalR.score,     criteria: rentalR.criteria },
      background: { score: backgroundR.score, criteria: backgroundR.criteria },
    },
  };
}

module.exports = { computeEvaluation };
