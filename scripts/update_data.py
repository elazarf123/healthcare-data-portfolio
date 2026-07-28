#!/usr/bin/env python3
"""update_data.py - Refresh portfolio dashboard data from public healthcare sources.

Run by .github/workflows/update-data.yml on a weekly schedule (and on demand).
Standard library only, so the GitHub Action needs no pip install.

Sources
  - openFDA Device Recalls .......... https://api.fda.gov/device/recall.json   (public API, no key)
  - CISA ICS Medical Advisories ..... CISA RSS feeds (WAF requires a browser-like UA)
  - CMS Provider Data (HRRP) ........ https://data.cms.gov/provider-data/api/1/datastore/query

Writes data/*.json. Any source that fails leaves its previous JSON untouched, so a
single outage never blanks the dashboards.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DATA.mkdir(exist_ok=True)

# CISA sits behind a WAF that rejects non-browser agents with HTTP 403, so send a
# realistic browser UA and Accept header on every request.
UA = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    ),
    "Accept": "application/rss+xml, application/xml, text/xml, application/json;q=0.9, */*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
TIMEOUT = 45
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


# ---------------------------------------------------------------- openFDA
def fetch_fda_recalls(limit: int = 100) -> int:
    """Recent medical-device recalls, plus counts by recall class."""
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


# ---------------------------------------------------------------- CISA
CISA_FEEDS = (
    "https://www.cisa.gov/cybersecurity-advisories/ics-medical-advisories.xml",
    "https://www.cisa.gov/news.xml",
    "https://www.cisa.gov/uscert/ics/advisories/advisories.xml",
)


def fetch_cisa_medical_advisories() -> int:
    """CISA ICS Medical Advisories RSS -> structured JSON.

    Tries each known feed URL in turn; CISA rotates these and fronts them with a WAF.
    """
    last_error = None
    root = None
    used = None

    for url in CISA_FEEDS:
        try:
            root = ElementTree.fromstring(get(url))
            used = url
            break
        except Exception as exc:
            last_error = f"{url} -> {type(exc).__name__}: {exc}"
            continue

    if root is None:
        raise RuntimeError(f"all CISA feeds failed; last: {last_error}")

    items = []
    for item in root.iter("item"):
        def txt(tag):
            el = item.find(tag)
            return (el.text or "").strip() if el is not None and el.text else ""

        title = txt("title")
        # the general feeds carry non-medical items too; keep the medical/ICS ones
        if "ics-medical" not in used and not re.search(r"medical|ICSMA", title, re.I):
            continue

        desc = re.sub(r"<[^>]+>", "", txt("description"))
        items.append(
            {
                "title": title,
                "link": txt("link"),
                "published": txt("pubDate"),
                "summary": desc[:280],
            }
        )

    write(
        "cisa_medical_advisories.json",
        {"generated": now_iso(), "source": used, "count": len(items), "advisories": items},
    )
    return len(items)


# ---------------------------------------------------------------- CMS
def fetch_cms_hrrp() -> int:
    """CMS Hospital Readmissions Reduction Program national/hospital rows.

    The Provider Data Catalog assigns each dataset a UUID that changes with releases,
    so we look it up by title first. Set CMS_HRRP_DATASET_ID to pin a specific one.
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

    url = (
        "https://data.cms.gov/provider-data/api/1/datastore/query/"
        f"{dataset_id}/0?limit=500&offset=0"
    )
    payload = get_json(url)
    rows = payload.get("results", [])
    write("cms_hrrp.json", {"generated": now_iso(), "dataset_id": dataset_id, "count": len(rows), "rows": rows})
    return len(rows)


# ---------------------------------------------------------------- helpers
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def main() -> int:
    print("Refreshing portfolio source data...")
    counts, errors = {}, {}

    for label, key, fn in (
        ("openFDA device recalls", "fda_recalls", fetch_fda_recalls),
        ("CISA ICS medical advisories", "cisa_advisories", fetch_cisa_medical_advisories),
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
                "cisa": "CISA ICS Medical Advisories",
                "cms": "CMS Provider Data Catalog (HRRP)",
                "hhs_ocr": "HHS OCR Breach Portal (manual CSV - no public API)",
            },
        },
    )

    if errors and len(errors) == 3:
        print("All sources failed.", file=sys.stderr)
        return 1
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
