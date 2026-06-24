# Healthcare Data Portfolio

**Hospital Readmission Risk & PHI Access-Audit Dashboard**

A one-page analytics + security project that bridges two of the most expensive risks a health system carries: avoidable 30-day readmissions and improper access to protected health information (PHI).

Built by **Elazar Ferrer** — Google Data Analytics & Google Cybersecurity certified.

🔗 **Live dashboard:** _(enable GitHub Pages — see the bottom of this file — then paste the link here)_

---

## What's in this repo

| File | What it shows |
|------|----------------|
| `index.html` | Interactive one-page dashboard (readmission analytics + PHI access audit) |
| `readmissions.csv` | 30-day readmission rates by condition vs. national benchmark |
| `readmissions_trend.csv` | 12-month Heart Failure readmission trend |
| `phi_access_logs.csv` | Synthetic access log with auto-flagged events |

## Panel 1 — Readmission Analytics
30-day readmission rates for six conditions, benchmarked against national averages. **Key insight:** Heart Failure runs 3.3 points above benchmark and is the single largest driver of excess readmissions — the highest-leverage target for discharge follow-up and medication reconciliation. Excess readmissions translate directly into CMS penalties under the Hospital Readmissions Reduction Program.

## Panel 2 — PHI Access Audit
A synthetic access log flagged with a simple rule: any access that is **after-hours OR outside the user's department** is routed for human review. 6 of 20 events flag — the highest-risk being after-hours cross-department access (e.g., an Emergency nurse opening an Oncology record at 3:47 AM). This mirrors the triage a HIPAA audit performs; each flagged event is a potential reportable breach to confirm against a documented business reason.

## Why it matters
Readmissions and PHI access are usually owned by different teams who rarely see the same dashboard. This project demonstrates (1) cleaning and benchmarking clinical operational data to surface one actionable insight, and (2) reviewing access logs with a security lens. The combination — analytics judgment plus privacy instinct — is what reduces both financial and compliance risk for a healthcare employer.

## Methodology
Mock dataset modeled on the CMS Hospital Readmissions Reduction Program structure plus a synthetic PHI access-log table. Flag logic: `IF(after_hours = "Yes" OR same_dept = "No") -> "REVIEW"`. Reproducible in Tableau Public or Looker Studio.

## View the live dashboard (GitHub Pages)
1. Go to this repo's **Settings -> Pages**.
2. Under "Build and deployment": Source = **Deploy from a branch**, Branch = **main** / **/ (root)**, then **Save**.
3. Wait ~1 minute, then visit `https://elazarf123.github.io/healthcare-data-portfolio/`.

---
*All data is illustrative/mock for portfolio demonstration. No real patient data is used.*
