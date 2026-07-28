#!/usr/bin/env python3
"""update_data.py - Refresh portfolio dashboard data from public healthcare sources.

Run by .github/workflows/update-data.yml on a weekly schedule (and on demand).
Standard library only, so the GitHub Action needs no pip install.

Sources
  - openFDA Device Recalls .. https://api.fda.gov/device/recall.json   (public API, no key)
  - NVD CVE API ............. https://services.nvd.nist.gov/rest/json/cves/2.0
  - CMS Provider Data (HRRP)  https://data.cms.gov/provider-data/api/1/datastore/query

Why NVD instead of CISA: CISA's ICS Medical Advisories RSS sits behind a WAF that
returns HTTP 403 to datacenter IP ranges, which is what GitHub Actions runners use.
A browser User-Agent and a fallback URL chain both still 403'd, confirming it is IP
reputation rather than the agent string. NVD explicitly supports automated access
and carries CVSS severity, so it is the better automated source.

Writes data/*.json. Any source that fails leaves its previous JSON untouched, so a
single outage never blanks the dashboards.
"""
from __future__ import annotations

import json
import os
import ssl
import time
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DATA.mkdir(exist_ok=True)

UA = {
    "User-Agent": "healthcare-data-portfolio/1.0 (+https://github.com/elazarf123)",
    "Accept": "application/json, text/xml;q=0.9, */*;q=0.8",
}
TIMEOUT = 60
CTX = ssl.create_default_context()


def get(url: str) -> bytes:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=CTX) as r:
        return r.read()


def get_json(url: str) -> dict:
    return json.loads(get(url).decode("utf-8", "replace"))


def write(name: str, payload) -> None:
    path = DATA / name
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"  wrote {path.relative_to(ROOT)}")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------- openFDA
def fetch_fda_recalls(limit: int = 100) -> int:
    """Recent medical-device recalls, plus counts by device class."""
    base = "https://api.fda.gov/device/recall.json"
    recalls = get_json(f"{base}?limit={limit}&sort=event_date_initiated:desc")

    rows = []
    for r in recalls.get("results", []):
        rows.append(
            {
                "firm": r.get("recalling_firm"),
                "product": (r.get("product_description") or "")[:220],
                "reason": (r.get("reason_for_recall") or "")[:220],
                "recall_class": r.get("openfda", {}).get("device_class") or r.get("res_event_number"),
                "date": r.get("event_date_initiated"),
                "status": r.get("recall_status"),
            }
        )

    by_class = Counter(
        (r.get("openfda", {}) or {}).get("device_class") or "Unspecified"
        for r in recalls.get("results", [])
    )

    write("fda_recalls.json", {"generated": now_iso(), "count": len(rows), "recalls": rows})
    write("fda_recall_classes.json", {"generated": now_iso(), "by_class": dict(by_class)})
    return len(rows)


# ---------------------------------------------------------------- NVD
MEDICAL_KEYWORDS = (
    "medical device",
    "infusion pump",
    "pacemaker",
    "patient monitor",
    "medical imaging",
)


def fetch_nvd_medical_cves(per_keyword: int = 50) -> int:
    """Medical-device CVEs from NVD across several keywords, de-duplicated.

    NVD rate-limits anonymous callers to roughly 5 requests per 30 seconds, so we
    pause between keywords. Set an NVD_API_KEY repo secret to raise that ceiling.
    """
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    seen, rows, severities = set(), [], Counter()
    per_keyword_counts = {}

    for idx, keyword in enumerate(MEDICAL_KEYWORDS):
        if idx:
            time.sleep(2 if api_key else 7)  # stay under the anonymous rate limit

        q = urllib.parse.urlencode(
            {"keywordSearch": keyword, "resultsPerPage": per_keyword, "startIndex": 0}
        )
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{q}"

        try:
            req = urllib.request.Request(url, headers=dict(UA, **({"apiKey": api_key} if api_key else {})))
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=CTX) as r:
                payload = json.loads(r.read().decode("utf-8", "replace"))
        except Exception as exc:
            print(f"    keyword {keyword!r} failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            per_keyword_counts[keyword] = 0
            continue

        found = 0
        for entry in payload.get("vulnerabilities", []):
            cve = entry.get("cve", {}) or {}
            cve_id = cve.get("id")
            if not cve_id or cve_id in seen:
                continue
            seen.add(cve_id)
            found += 1

            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            score, severity = None, "UNKNOWN"
            metrics = cve.get("metrics", {}) or {}
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    data = metrics[key][0].get("cvssData", {}) or {}
                    score = data.get("baseScore")
                    severity = data.get("baseSeverity") or metrics[key][0].get("baseSeverity") or "UNKNOWN"
                    break
            severities[severity] += 1

            rows.append(
                {
                    "id": cve_id,
                    "keyword": keyword,
                    "published": cve.get("published"),
                    "severity": severity,
                    "cvss": score,
                    "summary": desc[:280],
                    "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                }
            )
        per_keyword_counts[keyword] = found
        print(f"    {keyword}: {found} new")

    if not rows:
        raise RuntimeError("NVD returned no CVEs for any keyword")

    rows.sort(key=lambda r: (r["cvss"] is None, -(r["cvss"] or 0)))

    write(
        "nvd_medical_cves.json",
        {
            "generated": now_iso(),
            "source": "NVD CVE API 2.0",
            "keywords": list(MEDICAL_KEYWORDS),
            "per_keyword": per_keyword_counts,
            "count": len(rows),
            "by_severity": dict(severities),
            "cves": rows,
        },
    )
    return len(rows)


# ---------------------------------------------------------------- CMS
def fetch_cms_hrrp(page_size: int = 2000, max_pages: int = 25) -> int:
    """CMS Hospital Readmissions Reduction Program - full dataset, aggregated.

    Earlier versions pulled a single limit=500 page. Those rows come back ordered by
    facility_id, so they were roughly the first ~70 hospitals per measure alphabetically
    by state - a geographically biased slice, not a national figure. We now page through
    the whole dataset and store only a compact per-measure summary, so the number really
    is national and the repo does not carry a multi-megabyte JSON dump every week.
    """
    dataset_id = os.environ.get("CMS_HRRP_DATASET_ID", "").strip()

    if not dataset_id:
        catalog = get_json("https://data.cms.gov/provider-data/api/1/metastore/schemas/dataset/items")
        for ds in catalog:
            if "readmissions reduction" in (ds.get("title") or "").lower():
                dataset_id = ds.get("identifier", "")
                print(f"  matched CMS dataset: {ds.get('title')} ({dataset_id})")
                break

    if not dataset_id:
        raise RuntimeError("could not locate the HRRP dataset in the CMS catalog")

    base = f"https://data.cms.gov/provider-data/api/1/datastore/query/{dataset_id}/0"

    sums, counts, facilities = {}, {}, set()
    total_rows, offset, pages = 0, 0, 0
    start_date = end_date = None

    while pages < max_pages:
        payload = get_json(f"{base}?limit={page_size}&offset={offset}")
        rows = payload.get("results", [])
        if not rows:
            break

        for row in rows:
            measure = row.get("measure_name")
            if not measure:
                continue
            facilities.add(row.get("facility_id"))
            start_date = start_date or row.get("start_date")
            end_date = end_date or row.get("end_date")
            try:
                rate = float(row.get("expected_readmission_rate"))
            except (TypeError, ValueError):
                continue  # "N/A" / "Too Few to Report"
            sums[measure] = sums.get(measure, 0.0) + rate
            counts[measure] = counts.get(measure, 0) + 1

        total_rows += len(rows)
        offset += page_size
        pages += 1
        if len(rows) < page_size:
            break

    if not counts:
        raise RuntimeError("CMS returned no usable expected_readmission_rate values")

    national = {
        measure: {
            "expected_readmission_rate_mean": round(sums[measure] / counts[measure], 2),
            "hospitals": counts[measure],
        }
        for measure in sorted(counts)
    }

    write(
        "cms_hrrp_summary.json",
        {
            "generated": now_iso(),
            "dataset_id": dataset_id,
            "source": "CMS Provider Data Catalog - Hospital Readmissions Reduction Program",
            "scope": "national - all hospitals in the current CMS release",
            "measurement_period": {"start": start_date, "end": end_date},
            "rows_scanned": total_rows,
            "distinct_facilities": len(facilities),
            "by_measure": national,
        },
    )
    print(f"    scanned {total_rows} rows across {len(facilities)} facilities")
    return total_rows


# ---------------------------------------------------------------- main
def main() -> int:
    print("Refreshing portfolio source data...")
    counts, errors = {}, {}

    for label, key, fn in (
        ("openFDA device recalls", "fda_recalls", fetch_fda_recalls),
        ("NVD medical-device CVEs", "nvd_medical_cves", fetch_nvd_medical_cves),
        ("CMS HRRP readmissions", "cms_hrrp_rows", fetch_cms_hrrp),
    ):
        print(f"- {label}")
        try:
            counts[key] = fn()
            print(f"  ok ({counts[key]} records)")
        except Exception as exc:  # keep going; stale data beats no data
            errors[key] = f"{type(exc).__name__}: {exc}"
            print(f"  SKIPPED - {errors[key]}", file=sys.stderr)

    stamp = datetime.now(timezone.utc)
    write(
        "last_updated.json",
        {
            "updated": stamp.isoformat(timespec="seconds"),
            "updated_human": stamp.strftime("%b %d, %Y"),
            "counts": counts,
            "errors": errors,
            "sources": {
                "fda": "openFDA Device Recall API",
                "nvd": "NVD CVE API 2.0 (medical device keyword)",
                "cms": "CMS Provider Data Catalog (HRRP)",
                "hhs_ocr": "HHS OCR Breach Portal (manual CSV - no public API)",
                "cisa": "CISA ICS Medical Advisories (manual - WAF blocks datacenter IPs)",
            },
        },
    )

    if len(errors) == 3:
        print("All sources failed.", file=sys.stderr)
        return 1
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
