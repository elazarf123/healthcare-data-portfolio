# Healthcare Data & Security Dashboards

Three interactive dashboards that pair a healthcare analytics question with a HIPAA or security lens: readmission risk with PHI access auditing, breach trends, and medical device security.

**Live site:** https://elazarf123.github.io/healthcare-data-portfolio/

## Results

**Sample output (illustrative).** The hospital-level figures and the PHI access log are mock data. National benchmarks and the public data feeds are real.

| Dashboard | What it shows | Data |
| :--- | :--- | :--- |
| [Readmission & PHI access audit](readmission-dashboard.html) | Sample hospital's heart-failure readmission rate (25.2%) vs the national benchmark (23.2%); **6 of 20** sample access events flagged for after-hours or cross-department access | Benchmarks: CMS HRRP, AHRQ HCUP. Hospital figures and access log: illustrative |
| [HIPAA breach intelligence](hipaa-breach-dashboard.html) | 2020–2025 breach-type trends, breaches by entity type, a risk scorecard for major 2025 breaches, NIST CSF control mapping | HHS/OCR breach portal and HIPAA Journal (entered manually) |
| [Medical device / IoMT security](device-security-dashboard.html) | FDA device recalls by risk class, device-category risk scorecard, medical-device CVEs | openFDA, NVD, CISA advisories, published industry figures |

At the last automated refresh (Aug 10, 2026) the pipeline pulled 100 FDA recalls, 85 medical-device CVEs, and 18,330 CMS HRRP rows ([`data/last_updated.json`](data/last_updated.json)).

## How it works

- [`index.html`](index.html) is the landing page that links the three dashboards; each dashboard is a single HTML file that uses Chart.js.
- [`scripts/update_data.py`](scripts/update_data.py) pulls openFDA device recalls, NVD medical-device CVEs, and CMS HRRP data (standard library only) and writes [`data/`](data/).
- A GitHub Actions workflow ([`.github/workflows/update-data.yml`](.github/workflows/update-data.yml)) runs it weekly and commits any changes. A failed source keeps its previous data, so a single outage never blanks a dashboard.
- PHI access flag rule: `after_hours = "Yes" OR same_dept = "No"` → `REVIEW`.
- HHS/OCR and CISA data are updated by hand: OCR has no public API, and CISA's site blocks GitHub's runner IPs.

## Tech stack

HTML · JavaScript (Chart.js) · Python 3 · GitHub Actions · GitHub Pages

## Run it

```bash
git clone https://github.com/elazarf123/healthcare-data-portfolio.git
cd healthcare-data-portfolio
python scripts/update_data.py      # optional: refresh data/ from the public APIs
python -m http.server 8000         # then open http://localhost:8000
```

## What I learned

- Public healthcare data is uneven: some sources have clean APIs (openFDA, NVD, CMS), and others need manual updates.
- A benchmark is only useful with a clear "so what": each panel ends with the one action the numbers point to.
- Automated refreshes need a fallback, so the pipeline keeps the last good data when a source fails.

## Roadmap

- Replace the illustrative hospital figures with a public hospital-level CMS data set
- Automate the HHS/OCR breach data if a machine-readable source becomes available

> Lab use only. No real patient data is used.
