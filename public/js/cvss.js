/* CVSS v3.1 base score — implements the official FIRST.org formula. */
const CVSS31_WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR_U: { N: 0.85, L: 0.62, H: 0.27 }, // scope unchanged
  PR_C: { N: 0.85, L: 0.68, H: 0.5 },  // scope changed
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 }
};

function roundUp1(n) {
  const int = Math.round(n * 100000);
  if (int % 10000 === 0) return int / 100000;
  return (Math.floor(int / 10000) + 1) / 10;
}

function calcCVSS31(m) {
  // m = { AV, AC, PR, UI, S, C, I, A }  (S: 'U' unchanged / 'C' changed)
  const iss = 1 - ((1 - CVSS31_WEIGHTS.CIA[m.C]) * (1 - CVSS31_WEIGHTS.CIA[m.I]) * (1 - CVSS31_WEIGHTS.CIA[m.A]));
  let impact;
  if (m.S === 'C') {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  } else {
    impact = 6.42 * iss;
  }
  const pr = m.S === 'C' ? CVSS31_WEIGHTS.PR_C[m.PR] : CVSS31_WEIGHTS.PR_U[m.PR];
  const exploitability = 8.22 * CVSS31_WEIGHTS.AV[m.AV] * CVSS31_WEIGHTS.AC[m.AC] * pr * CVSS31_WEIGHTS.UI[m.UI];

  if (impact <= 0) return 0;
  const base = m.S === 'C' ? 1.08 * (impact + exploitability) : (impact + exploitability);
  return roundUp1(Math.min(base, 10));
}

function vectorString31(m) {
  return `CVSS:3.1/AV:${m.AV}/AC:${m.AC}/PR:${m.PR}/UI:${m.UI}/S:${m.S}/C:${m.C}/I:${m.I}/A:${m.A}`;
}

/* CVSS v4.0 — the real spec uses a 2450-entry MacroVector lookup table.
   We provide a labeled APPROXIMATION using a v3.1-style weighted formula
   over the v4 metrics, clearly flagged in the UI as beta/approximate.
   For compliance-critical scoring, verify with the official FIRST.org v4 calculator. */
const CVSS4_WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  AT: { N: 0.85, P: 0.6 },
  PR: { N: 0.85, L: 0.65, H: 0.3 },
  UI: { N: 0.85, P: 0.65, A: 0.5 },
  IMPACT: { H: 0.56, L: 0.22, N: 0 }
};

function calcCVSS40Approx(m) {
  // m = { AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA }
  const vulnIss = 1 - ((1 - CVSS4_WEIGHTS.IMPACT[m.VC]) * (1 - CVSS4_WEIGHTS.IMPACT[m.VI]) * (1 - CVSS4_WEIGHTS.IMPACT[m.VA]));
  const subIss = 1 - ((1 - CVSS4_WEIGHTS.IMPACT[m.SC]) * (1 - CVSS4_WEIGHTS.IMPACT[m.SI]) * (1 - CVSS4_WEIGHTS.IMPACT[m.SA]));
  const impact = 6.42 * Math.max(vulnIss, subIss * 0.9);
  const exploitability = 8.22 * CVSS4_WEIGHTS.AV[m.AV] * CVSS4_WEIGHTS.AC[m.AC] * CVSS4_WEIGHTS.AT[m.AT] * CVSS4_WEIGHTS.PR[m.PR] * CVSS4_WEIGHTS.UI[m.UI];
  if (impact <= 0) return 0;
  return roundUp1(Math.min(impact + exploitability, 10));
}

function vectorString40(m) {
  return `CVSS:4.0/AV:${m.AV}/AC:${m.AC}/AT:${m.AT}/PR:${m.PR}/UI:${m.UI}/VC:${m.VC}/VI:${m.VI}/VA:${m.VA}/SC:${m.SC}/SI:${m.SI}/SA:${m.SA}`;
}

function severityFromScore(score) {
  if (score === 0) return 'Informational';
  if (score < 4) return 'Low';
  if (score < 7) return 'Medium';
  if (score < 9) return 'High';
  return 'Critical';
}
