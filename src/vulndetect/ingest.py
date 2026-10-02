"""
Phase 1 — Data foundation.

Responsibilities:
  1. Download CWE data (MITRE) and CVE data (NVD) into data/raw/.
  2. Parse both into a common in-memory record format.
  3. Clean + chunk the text into passages suitable for embedding.
  4. Write the chunks to data/processed/chunks.jsonl.

Run:
    python -m vulndetect.ingest --all
    python -m vulndetect.ingest --cwe-only        # skip NVD (NVD API is rate-limited / slow)
    python -m vulndetect.ingest --skip-download    # reuse files already in data/raw/

Notes:
  - CWE source: https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
    (a single XML file listing every CWE weakness with name + description)
  - CVE source: NVD API 2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0)
    Free tier is rate-limited (~5 req/30s without an API key), so we page
    politely and cache each page to data/raw/nvd/ so re-runs don't re-fetch.
  - Getting a labeled train/test set (Juliet / OWASP Benchmark / CVEfixes) is
    a SEPARATE step — see data/testset/README.md. Don't hand-label; pull one
    of those instead.
"""

from __future__ import annotations

import argparse
import json
import re
import time
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterator

import requests

ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = ROOT / "data" / "raw"
PROCESSED_DIR = ROOT / "data" / "processed"

CWE_XML_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CWE_ZIP_PATH = RAW_DIR / "cwec_latest.xml.zip"
CWE_XML_NAMESPACE = "{http://cwe.mitre.org/cwe-7}"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RAW_DIR = RAW_DIR / "nvd"
NVD_PAGE_SIZE = 2000  # NVD API 2.0 max results per page


@dataclass
class Record:
    """One CWE weakness or CVE vulnerability, before chunking."""
    source: str          # "cwe" | "cve"
    id: str               # e.g. "CWE-89" or "CVE-2023-12345"
    name: str
    text: str              # full description text used for chunking/embedding
    metadata: dict


@dataclass
class Chunk:
    chunk_id: str
    source: str
    ref_id: str
    name: str
    text: str
    metadata: dict



# Download


def download_cwe() -> Path:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    if CWE_ZIP_PATH.exists():
        print(f"[cwe] using cached {CWE_ZIP_PATH}")
        return CWE_ZIP_PATH

    print(f"[cwe] downloading {CWE_XML_ZIP_URL}")
    resp = requests.get(CWE_XML_ZIP_URL, timeout=60)
    resp.raise_for_status()
    CWE_ZIP_PATH.write_bytes(resp.content)
    print(f"[cwe] saved {CWE_ZIP_PATH} ({len(resp.content) / 1024:.0f} KB)")
    return CWE_ZIP_PATH


def download_nvd(max_pages: int | None = None, api_key: str | None = None) -> list[Path]:
    """
    Page through the NVD API and cache each page as raw JSON.
    Without an API key NVD allows ~5 requests per rolling 30s window, so we
    sleep between pages. Get a free key at https://nvd.nist.gov/developers/request-an-api-key
    to go much faster (set NVD_API_KEY env var or pass --nvd-api-key).
    """
    NVD_RAW_DIR.mkdir(parents=True, exist_ok=True)
    headers = {"apiKey": api_key} if api_key else {}
    sleep_s = 1.2 if api_key else 6.5

    saved: list[Path] = []
    start_index = 0
    page_num = 0
    while True:
        out_path = NVD_RAW_DIR / f"page_{start_index:07d}.json"
        if out_path.exists():
            print(f"[nvd] using cached {out_path}")
            data = json.loads(out_path.read_text())
        else:
            print(f"[nvd] fetching startIndex={start_index}")
            resp = requests.get(
                NVD_API_URL,
                params={"resultsPerPage": NVD_PAGE_SIZE, "startIndex": start_index},
                headers=headers,
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()
            out_path.write_text(json.dumps(data))
            time.sleep(sleep_s)

        saved.append(out_path)
        total = data.get("totalResults", 0)
        start_index += NVD_PAGE_SIZE
        page_num += 1

        if max_pages and page_num >= max_pages:
            break
        if start_index >= total:
            break

    print(f"[nvd] cached {len(saved)} page(s)")
    return saved



# Parse


def parse_cwe(zip_path: Path) -> Iterator[Record]:
    with zipfile.ZipFile(zip_path) as zf:
        xml_names = [n for n in zf.namelist() if n.endswith(".xml")]
        with zf.open(xml_names[0]) as f:
            tree = ET.parse(f)

    root = tree.getroot()
    ns = CWE_XML_NAMESPACE
    weaknesses = root.find(f"{ns}Weaknesses")
    if weaknesses is None:
        return

    for w in weaknesses.findall(f"{ns}Weakness"):
        cwe_id = f"CWE-{w.get('ID')}"
        name = w.get("Name", "")

        desc_parts = []
        desc_el = w.find(f"{ns}Description")
        if desc_el is not None and desc_el.text:
            desc_parts.append(desc_el.text.strip())

        ext_desc_el = w.find(f"{ns}Extended_Description")
        if ext_desc_el is not None:
            ext_text = "".join(ext_desc_el.itertext()).strip()
            if ext_text:
                desc_parts.append(ext_text)

        consequences = []
        cons_el = w.find(f"{ns}Common_Consequences")
        if cons_el is not None:
            for c in cons_el.findall(f"{ns}Consequence"):
                note_el = c.find(f"{ns}Note")
                if note_el is not None and note_el.text:
                    consequences.append(note_el.text.strip())

        text = "\n\n".join(desc_parts + consequences)
        if not text:
            continue

        yield Record(
            source="cwe",
            id=cwe_id,
            name=name,
            text=text,
            metadata={
                "abstraction": w.get("Abstraction"),
                "status": w.get("Status"),
            },
        )


def parse_nvd_pages(paths: list[Path]) -> Iterator[Record]:
    for p in paths:
        data = json.loads(p.read_text())
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue

            descriptions = cve.get("descriptions", [])
            en_desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
            if not en_desc:
                continue

            cwe_ids = []
            for weakness in cve.get("weaknesses", []):
                for d in weakness.get("description", []):
                    if d.get("value", "").startswith("CWE-"):
                        cwe_ids.append(d["value"])

            metrics = cve.get("metrics", {})
            cvss = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss = metrics[key][0]["cvssData"].get("baseScore")
                    break

            yield Record(
                source="cve",
                id=cve_id,
                name=cve_id,
                text=en_desc,
                metadata={"cwe_ids": cwe_ids, "cvss_base_score": cvss},
            )


# Clean + chunk


def clean_text(text: str) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"\[REF-\d+\]", "", text)  # strip CWE's inline reference markers
    return text.strip()


def chunk_record(record: Record, max_chars: int = 800, overlap: int = 100) -> list[Chunk]:
    """Simple char-window chunking. CWE/CVE entries are short (a paragraph or
    two) so most records become a single chunk; only long CWE entries with
    extended descriptions split into more than one."""
    text = clean_text(record.text)
    if not text:
        return []

    if len(text) <= max_chars:
        spans = [text]
    else:
        spans = []
        start = 0
        while start < len(text):
            end = min(start + max_chars, len(text))
            spans.append(text[start:end])
            if end == len(text):
                break
            start = end - overlap

    chunks = []
    for i, span in enumerate(spans):
        chunk_id = f"{record.id}-{i}" if len(spans) > 1 else record.id
        chunks.append(
            Chunk(
                chunk_id=chunk_id,
                source=record.source,
                ref_id=record.id,
                name=record.name,
                text=span,
                metadata=record.metadata,
            )
        )
    return chunks


# Pipeline



def run(cwe_only: bool, skip_download: bool, max_nvd_pages: int | None, nvd_api_key: str | None) -> None:
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    out_path = PROCESSED_DIR / "chunks.jsonl"

    records: list[Record] = []

    if skip_download:
        cwe_zip = CWE_ZIP_PATH
    else:
        cwe_zip = download_cwe()
    records.extend(parse_cwe(cwe_zip))
    print(f"[cwe] parsed {sum(1 for r in records if r.source == 'cwe')} weaknesses")

    if not cwe_only:
        if skip_download:
            nvd_pages = sorted(NVD_RAW_DIR.glob("page_*.json"))
        else:
            nvd_pages = download_nvd(max_pages=max_nvd_pages, api_key=nvd_api_key)
        cve_records = list(parse_nvd_pages(nvd_pages))
        records.extend(cve_records)
        print(f"[nvd] parsed {len(cve_records)} CVEs")

    with out_path.open("w") as f:
        n_chunks = 0
        for record in records:
            for chunk in chunk_record(record):
                f.write(json.dumps(asdict(chunk)) + "\n")
                n_chunks += 1

    print(f"[done] wrote {n_chunks} chunks -> {out_path}")


def main():
    parser = argparse.ArgumentParser(description="Ingest CWE/CVE data for vulndetect")
    parser.add_argument("--all", action="store_true", help="fetch CWE + NVD (default)")
    parser.add_argument("--cwe-only", action="store_true", help="skip NVD entirely (fastest, good for a first pass)")
    parser.add_argument("--skip-download", action="store_true", help="reuse whatever is already cached in data/raw/")
    parser.add_argument("--max-nvd-pages", type=int, default=None, help="cap NVD pages (2000 CVEs/page) for a quick test run")
    parser.add_argument("--nvd-api-key", type=str, default=None, help="NVD API key, speeds up rate limit from 6.5s/page to 1.2s/page")
    args = parser.parse_args()

    run(
        cwe_only=args.cwe_only,
        skip_download=args.skip_download,
        max_nvd_pages=args.max_nvd_pages,
        nvd_api_key=args.nvd_api_key,
    )


if __name__ == "__main__":
    main()
