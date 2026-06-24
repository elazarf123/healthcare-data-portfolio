# Healthcare Data Portfolio

**Hospital Readmission Risk & PHI Access-Audit Dashboard**

A one-page analytics + security project that bridges two of the most expensive risks a health system carries: avoidable 30-day readmissions and improper access to protected health information (PHI).

Built by **Elazar Ferrer** — Google Data Analytics & Google Cybersecurity certified.

🔗 **Live dashboard:** https://elazarf123.github.io/healthcare-data-portfolio/

---

## What's in this repo

| File | What it shows |
|------|----------------|
| `index.html` | Interactive one-page dashboard (readmission analytics + PHI access audit) |
| `readmissions.csv` | 30-day readmission rates by condition vs. real national benchmark |
| `readmissions_trend.csv` | 12-month Heart Failure readmission trend |
| `phi_access_logs.csv` | Synthetic access log with auto-flagged events |

## Panel 1 — Readmission Analytics
30-day readmission rates for six HRRP conditions, benchmarked against **real Medicare national rates**. **Key insight:** Heart Failure runs 2.0 points above the national benchmark (23.2%) and is the single largest driver of excess readmissions — the highest-leverage target for discharge follow-up and medication reconciliation. Excess readmissions translate directly into CMS penalties under the Hospital Readmissions Reduction Program.

## Panel 2 — PHI Access Audit
A synthetic access log flagged with a simple rule: any access that is **after-hours OR outside the user's department** is routed for human review. 6 of 20 events flag — the highest-risk being after-hours cross-department access (e.g., an Emergency nurse opening an Oncology record at 3:47 AM). This mirrors the triage a HIPAA audit performs; each flagged event is a potential reportable breach to confirm against a documented business reason.

## Why it matters
Readmissions and PHI access are usually owned by different teams who rarely see the same dashboard. This project demonstrates (1) cleaning and benchmarking clinical operational data against real national rates to surface one actionable insight, and (2) reviewing access logs with a security lens. The combination — analytics judgment plus privacy instinct — is what reduces both financial and compliance risk for a healthcare employer.

## Data sources & methodology
National benchmarks reflect **real Medicare 30-day readmission rates** from CMS Hospital Readmissions Reduction Program measures and AHRQ HCUP Statistical Brief #307 (Heart Failure 23.2%, Pneumonia 16.7%, Acute MI 14.8%). Hospital-level figures and the PHI access log are an illustrative sample for demonstration (no real patient data). Flag logic: `IF(after_hours = "Yes" OR same_dept = "No") -> "REVIEW"`. Reproducible in Tableau Public or Looker Studio.

---
*Hospital-level and access-log data are illustrative/mock; national benchmarks are real published rates. No real patient data is used.*
