#!/usr/bin/env python3
"""
phishing_scanner.py

A heuristic-based tool for scoring emails as legitimate or likely phishing.

This tool is defensive in nature: it parses .eml files and applies a set of
transparent, explainable heuristics (authentication results, domain/display
name spoofing, suspicious links, urgency language, dangerous attachments,
etc.) to produce a 0-100 risk score with a human-readable explanation.

It does NOT execute, click, or fetch any content from the emails it scans.

Usage:
    python phishing_scanner.py scan path/to/email.eml
    python phishing_scanner.py scan path/to/folder/ --json
    python phishing_scanner.py scan path/to/folder/ --csv report.csv

Requires only the Python standard library (3.9+).
"""

from __future__ import annotations

import argparse
import csv
import difflib
import html
import json
import re
import sys
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, getaddresses
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

__version__ = "1.0.0"

# =============================================================================
# email_parser: raw .eml bytes -> structured ParsedEmail
# =============================================================================

LINK_RE = re.compile(r'href\s*=\s*["\']?([^"\'\s>]+)', re.IGNORECASE)
ANCHOR_RE = re.compile(
    r'<a\b[^>]*href\s*=\s*["\']?([^"\'\s>]+)["\']?[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
TAG_STRIP_RE = re.compile(r"<[^>]+>")


@dataclass
class ParsedLink:
    href: str
    anchor_text: str = ""


@dataclass
class ParsedAttachment:
    filename: str
    content_type: str
    size: int


@dataclass
class ParsedEmail:
    subject: str = ""
    from_display: str = ""
    from_addr: str = ""
    reply_to_addr: str = ""
    return_path_addr: str = ""
    to_addrs: list = field(default_factory=list)
    date: str = ""
    text_body: str = ""
    html_body: str = ""
    links: list = field(default_factory=list)  # list[ParsedLink]
    attachments: list = field(default_factory=list)  # list[ParsedAttachment]
    auth_results_raw: str = ""
    received_spf: str = ""
    headers: dict = field(default_factory=dict)
    raw_path: Optional[str] = None


def _get_body_parts(msg) -> tuple[str, str]:
    """Return (plain_text_body, html_body) concatenated across all parts."""
    text_chunks = []
    html_chunks = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            if "attachment" in disp.lower():
                continue
            try:
                if content_type == "text/plain":
                    text_chunks.append(part.get_content())
                elif content_type == "text/html":
                    html_chunks.append(part.get_content())
            except Exception:
                payload = part.get_payload(decode=True) or b""
                decoded = payload.decode("utf-8", errors="replace")
                if content_type == "text/plain":
                    text_chunks.append(decoded)
                elif content_type == "text/html":
                    html_chunks.append(decoded)
    else:
        content_type = msg.get_content_type()
        try:
            content = msg.get_content()
        except Exception:
            payload = msg.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace")
        if content_type == "text/html":
            html_chunks.append(content)
        else:
            text_chunks.append(content)

    return "\n".join(text_chunks), "\n".join(html_chunks)


def _extract_links(html_body: str) -> list:
    links = []
    for match in ANCHOR_RE.finditer(html_body):
        href = html.unescape(match.group(1).strip())
        anchor_raw = match.group(2)
        anchor_text = html.unescape(TAG_STRIP_RE.sub("", anchor_raw)).strip()
        links.append(ParsedLink(href=href, anchor_text=anchor_text))

    seen_hrefs = {l.href for l in links}
    for match in LINK_RE.finditer(html_body):
        href = html.unescape(match.group(1).strip())
        if href not in seen_hrefs:
            links.append(ParsedLink(href=href, anchor_text=""))
            seen_hrefs.add(href)

    return links


def _extract_attachments(msg) -> list:
    attachments = []
    if not msg.is_multipart():
        return attachments
    for part in msg.walk():
        disp = str(part.get("Content-Disposition") or "")
        filename = part.get_filename()
        if "attachment" in disp.lower() or filename:
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                ParsedAttachment(
                    filename=filename or "(unnamed)",
                    content_type=part.get_content_type(),
                    size=len(payload),
                )
            )
    return attachments


def parse_eml_bytes(raw_bytes: bytes, raw_path: Optional[str] = None) -> ParsedEmail:
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    from_header = msg.get("From", "")
    from_display, from_addr = parseaddr(from_header)

    reply_to_header = msg.get("Reply-To", "")
    _, reply_to_addr = parseaddr(reply_to_header)

    return_path_header = msg.get("Return-Path", "")
    _, return_path_addr = parseaddr(return_path_header)

    to_addrs = [addr for _, addr in getaddresses([msg.get("To", "")]) if addr]

    text_body, html_body = _get_body_parts(msg)
    links = _extract_links(html_body) if html_body else []
    attachments = _extract_attachments(msg)

    headers = {k: v for k, v in msg.items()}

    return ParsedEmail(
        subject=msg.get("Subject", "") or "",
        from_display=from_display or "",
        from_addr=(from_addr or "").lower(),
        reply_to_addr=(reply_to_addr or "").lower(),
        return_path_addr=(return_path_addr or "").lower(),
        to_addrs=[a.lower() for a in to_addrs],
        date=msg.get("Date", "") or "",
        text_body=text_body or "",
        html_body=html_body or "",
        links=links,
        attachments=attachments,
        auth_results_raw=msg.get("Authentication-Results", "") or "",
        received_spf=msg.get("Received-SPF", "") or "",
        headers=headers,
        raw_path=raw_path,
    )


def parse_eml_file(path: str) -> ParsedEmail:
    with open(path, "rb") as f:
        raw = f.read()
    return parse_eml_bytes(raw, raw_path=path)


# =============================================================================
# heuristics: individual, explainable detection checks
# =============================================================================

@dataclass
class Finding:
    check: str
    points: int
    severity: str  # "info" | "low" | "medium" | "high" | "critical"
    reason: str


FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "icloud.com", "mail.com", "protonmail.com", "gmx.com", "zoho.com",
    "yandex.com", "live.com", "msn.com",
}

COMMONLY_SPOOFED_BRANDS = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com"],
    "netflix": ["netflix.com"],
    "bank of america": ["bankofamerica.com"],
    "wells fargo": ["wellsfargo.com"],
    "chase": ["chase.com"],
    "irs": ["irs.gov"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "usps": ["usps.com"],
    "linkedin": ["linkedin.com"],
    "facebook": ["facebook.com", "fb.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "office 365": ["microsoft.com", "office.com"],
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorte.st", "tiny.cc", "rb.gy", "s.id",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "link", "work", "gq", "tk", "ml",
    "cf", "ga", "loan", "win", "review", "country", "kim", "party", "science",
}

URGENCY_PHRASES = [
    r"\bverify your account\b", r"\bsuspend(ed)?\b.{0,20}\baccount\b",
    r"\bact now\b", r"\bimmediate(ly)? action\b", r"\burgent\b",
    r"\bwithin 24 hours\b", r"\byour account (will be|has been) (locked|closed|limited)\b",
    r"\bclick (here|below) immediately\b", r"\bconfirm your (identity|password|details)\b",
    r"\bunusual (activity|sign[- ]?in)\b", r"\bupdate your (billing|payment) (info|information|details)\b",
    r"\bfailure to (respond|comply|act)\b", r"\blegal action\b", r"\baccount (will be )?terminated\b",
    r"\bwinner\b", r"\byou('| ha)ve won\b", r"\bclaim your (prize|reward|refund)\b",
    r"\blimited time\b", r"\bfinal notice\b", r"\bpayment (failed|declined)\b",
]

CREDENTIAL_HARVEST_PHRASES = [
    r"\benter your (password|ssn|social security)\b",
    r"\bconfirm your (password|credit card|card number)\b",
    r"\bre-?enter your (login|credentials)\b",
    r"\bupdate your payment method\b",
    r"\bverify your (identity|billing)\b",
]

GENERIC_GREETINGS = [
    r"^dear (customer|user|valued customer|member|sir/madam|sir or madam)\b",
    r"^dear account holder\b",
    r"^hello,?\s*$",
]

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js", ".jse",
    ".wsf", ".hta", ".msi", ".jar", ".ps1", ".lnk", ".reg", ".dll", ".vbe",
    ".cpl", ".msc",
}

ARCHIVE_OR_DOC_EXT = {".zip", ".rar", ".7z", ".doc", ".docm", ".xls", ".xlsm", ".pdf"}


def _domain_of(addr_or_url: str) -> str:
    if "@" in addr_or_url:
        return addr_or_url.split("@")[-1].lower().strip()
    parsed = urlparse(addr_or_url if "//" in addr_or_url else f"//{addr_or_url}")
    return (parsed.hostname or "").lower()


def _registrable_domain(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _looks_like_ip(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))


def _is_lookalike(domain: str, legit_domains: list) -> bool:
    reg = _registrable_domain(domain)
    for legit in legit_domains:
        if reg == legit:
            return False
        ratio = difflib.SequenceMatcher(None, reg, legit).ratio()
        if ratio >= 0.75:
            return True
        normalized = reg.replace("0", "o").replace("1", "l").replace("rn", "m")
        if normalized == legit:
            return True
    return False


def check_authentication(email: ParsedEmail) -> list:
    findings = []
    auth = email.auth_results_raw.lower()
    spf_hdr = email.received_spf.lower()

    if not auth and not spf_hdr:
        findings.append(Finding(
            "authentication", 8, "medium",
            "No Authentication-Results or Received-SPF header found "
            "(cannot verify SPF/DKIM/DMARC)."
        ))
        return findings

    if "spf=fail" in auth or "fail" in spf_hdr:
        findings.append(Finding("authentication", 20, "high", "SPF check failed."))
    elif "spf=softfail" in auth:
        findings.append(Finding("authentication", 10, "medium", "SPF check soft-failed."))

    if "dkim=fail" in auth:
        findings.append(Finding("authentication", 15, "high", "DKIM signature verification failed."))

    if "dmarc=fail" in auth:
        findings.append(Finding("authentication", 20, "high", "DMARC alignment check failed."))

    if not findings and ("pass" in auth or "pass" in spf_hdr):
        findings.append(Finding("authentication", -5, "info", "SPF/DKIM/DMARC checks passed."))

    return findings


def check_sender_spoofing(email: ParsedEmail) -> list:
    findings = []
    display = email.from_display.lower().strip()
    from_domain = _domain_of(email.from_addr)

    if not from_domain:
        return findings

    reg_domain = _registrable_domain(from_domain)

    for brand, legit_domains in COMMONLY_SPOOFED_BRANDS.items():
        if brand in display:
            if reg_domain in legit_domains:
                continue
            if _is_lookalike(from_domain, legit_domains):
                findings.append(Finding(
                    "sender_spoofing", 30, "critical",
                    f"Display name references '{brand.title()}' but sending domain "
                    f"'{from_domain}' is a lookalike of the legitimate domain "
                    f"({'/'.join(legit_domains)})."
                ))
            else:
                findings.append(Finding(
                    "sender_spoofing", 25, "high",
                    f"Display name references '{brand.title()}' but sending domain "
                    f"'{from_domain}' does not match the legitimate domain "
                    f"({'/'.join(legit_domains)})."
                ))

    if reg_domain in FREE_MAIL_DOMAINS:
        for brand in COMMONLY_SPOOFED_BRANDS:
            if brand in display:
                findings.append(Finding(
                    "sender_spoofing", 20, "high",
                    f"Claims to be from '{brand.title()}' but was sent from a free "
                    f"email provider ({from_domain})."
                ))
                break

    return findings


def check_reply_to_mismatch(email: ParsedEmail) -> list:
    findings = []
    if not email.reply_to_addr:
        return findings
    from_domain = _registrable_domain(_domain_of(email.from_addr))
    reply_domain = _registrable_domain(_domain_of(email.reply_to_addr))
    if from_domain and reply_domain and from_domain != reply_domain:
        findings.append(Finding(
            "reply_to_mismatch", 15, "medium",
            f"Reply-To domain '{reply_domain}' differs from From domain "
            f"'{from_domain}' - replies would go somewhere other than the "
            f"apparent sender."
        ))
    return findings


def check_links(email: ParsedEmail) -> list:
    findings = []
    for link in email.links:
        href = link.href.strip()
        if href.startswith(("mailto:", "#", "tel:")):
            continue
        parsed = urlparse(href if "//" in href else f"//{href}")
        host = (parsed.hostname or "").lower()
        if not host:
            continue

        anchor_domain_match = re.search(
            r"([a-z0-9-]+\.)+[a-z]{2,}", link.anchor_text.lower()
        )
        if anchor_domain_match:
            anchor_domain = _registrable_domain(anchor_domain_match.group(0))
            actual_domain = _registrable_domain(host)
            if anchor_domain != actual_domain:
                findings.append(Finding(
                    "link_mismatch", 25, "high",
                    f"Link text displays '{anchor_domain}' but actually points to "
                    f"'{host}'."
                ))

        if _looks_like_ip(host):
            findings.append(Finding(
                "link_ip_address", 20, "high",
                f"Link points directly to an IP address ({host}) instead of a domain name."
            ))

        reg = _registrable_domain(host)
        if reg in URL_SHORTENERS:
            findings.append(Finding(
                "link_shortener", 10, "medium",
                f"Link uses a URL shortener ({reg}), which can hide the true destination."
            ))

        tld = host.split(".")[-1] if "." in host else ""
        if tld in SUSPICIOUS_TLDS:
            findings.append(Finding(
                "link_suspicious_tld", 8, "low",
                f"Link uses a TLD often associated with spam/phishing ('.{tld}')."
            ))

        for brand, legit_domains in COMMONLY_SPOOFED_BRANDS.items():
            if _is_lookalike(host, legit_domains) and reg not in legit_domains:
                findings.append(Finding(
                    "link_brand_lookalike", 25, "high",
                    f"Link domain '{host}' looks like a lookalike of "
                    f"{'/'.join(legit_domains)}."
                ))
                break

    return findings


def check_urgency_language(email: ParsedEmail) -> list:
    findings = []
    body = f"{email.subject}\n{email.text_body}\n{email.html_body}".lower()
    matched = set()
    for pattern in URGENCY_PHRASES:
        if re.search(pattern, body):
            matched.add(pattern)
    if matched:
        count = len(matched)
        points = min(5 * count, 20)
        findings.append(Finding(
            "urgency_language", points, "medium" if count < 3 else "high",
            f"Contains {count} urgency/pressure phrase(s) commonly used in phishing "
            f"(e.g. threats of account suspension, deadlines, 'act now')."
        ))
    return findings


def check_credential_harvesting_language(email: ParsedEmail) -> list:
    findings = []
    body = f"{email.text_body}\n{email.html_body}".lower()
    for pattern in CREDENTIAL_HARVEST_PHRASES:
        if re.search(pattern, body):
            findings.append(Finding(
                "credential_harvesting_language", 15, "high",
                "Body text asks the recipient to re-enter credentials, card "
                "details, or personal identifiers."
            ))
            break
    return findings


def check_generic_greeting(email: ParsedEmail) -> list:
    findings = []
    body = email.text_body.strip().lower() or re.sub(r"<[^>]+>", "", email.html_body).strip().lower()
    first_line = body.splitlines()[0] if body else ""
    for pattern in GENERIC_GREETINGS:
        if re.search(pattern, first_line):
            findings.append(Finding(
                "generic_greeting", 5, "low",
                "Uses a generic greeting instead of the recipient's name, "
                "common in mass-sent phishing."
            ))
            break
    return findings


def check_attachments(email: ParsedEmail) -> list:
    findings = []
    for att in email.attachments:
        name = att.filename.lower()
        parts = name.split(".")
        exts = ["." + p for p in parts[1:]] if len(parts) > 1 else []

        if exts and exts[-1] in DANGEROUS_EXTENSIONS:
            findings.append(Finding(
                "dangerous_attachment", 30, "critical",
                f"Attachment '{att.filename}' has an executable/script extension "
                f"({exts[-1]})."
            ))
        if len(exts) >= 2 and exts[-2] in ARCHIVE_OR_DOC_EXT and exts[-1] in DANGEROUS_EXTENSIONS:
            findings.append(Finding(
                "double_extension_attachment", 15, "high",
                f"Attachment '{att.filename}' uses a double extension trick to "
                f"disguise an executable as a document."
            ))
    return findings


def check_subject_flags(email: ParsedEmail) -> list:
    findings = []
    subject = email.subject.lower()
    flags = ["re:", "fwd:"]
    if any(subject.startswith(f) for f in flags) and not email.headers.get("In-Reply-To") and not email.headers.get("References"):
        findings.append(Finding(
            "fake_reply_subject", 8, "low",
            "Subject starts with 'Re:'/'Fwd:' but there are no In-Reply-To/"
            "References headers, suggesting a fabricated reply thread."
        ))
    return findings


def check_missing_to_header(email: ParsedEmail) -> list:
    findings = []
    if not email.to_addrs:
        findings.append(Finding(
            "missing_to_header", 5, "low",
            "No visible 'To' recipient (often indicates a BCC mass-mailing)."
        ))
    return findings


ALL_CHECKS = [
    check_authentication,
    check_sender_spoofing,
    check_reply_to_mismatch,
    check_links,
    check_urgency_language,
    check_credential_harvesting_language,
    check_generic_greeting,
    check_attachments,
    check_subject_flags,
    check_missing_to_header,
]


# =============================================================================
# scorer: aggregate findings into a 0-100 score + verdict
# =============================================================================

@dataclass
class ScanResult:
    email: ParsedEmail
    findings: list  # list[Finding]
    score: int
    verdict: str

    def summary_line(self) -> str:
        src = self.email.raw_path or "(in-memory)"
        return f"[{self.verdict:^11}] score={self.score:>3}  {src}  subject={self.email.subject!r}"


def _verdict_for_score(score: int) -> str:
    if score >= 70:
        return "PHISHING"
    if score >= 35:
        return "SUSPICIOUS"
    if score >= 15:
        return "LOW RISK"
    return "LIKELY SAFE"


def score_email(email: ParsedEmail) -> ScanResult:
    findings: list = []
    for check_fn in ALL_CHECKS:
        try:
            findings.extend(check_fn(email))
        except Exception as exc:
            findings.append(Finding(
                check_fn.__name__, 0, "info",
                f"Check raised an internal error and was skipped: {exc}"
            ))

    raw_score = sum(f.points for f in findings)
    score = max(0, min(100, raw_score))
    verdict = _verdict_for_score(score)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (severity_order.get(f.severity, 5), -f.points))

    return ScanResult(email=email, findings=findings, score=score, verdict=verdict)


# =============================================================================
# CLI
# =============================================================================

def _iter_eml_paths(target: Path):
    if target.is_file():
        yield target
    elif target.is_dir():
        yield from sorted(target.rglob("*.eml"))
    else:
        raise FileNotFoundError(f"No such file or directory: {target}")


def _result_to_dict(result: ScanResult) -> dict:
    return {
        "path": result.email.raw_path,
        "subject": result.email.subject,
        "from_display": result.email.from_display,
        "from_addr": result.email.from_addr,
        "score": result.score,
        "verdict": result.verdict,
        "findings": [
            {
                "check": f.check,
                "points": f.points,
                "severity": f.severity,
                "reason": f.reason,
            }
            for f in result.findings
        ],
    }


def _print_human(result: ScanResult, verbose: bool = True) -> None:
    print(result.summary_line())
    if verbose:
        for f in result.findings:
            sign = "+" if f.points >= 0 else ""
            print(f"    [{f.severity:<8}] {sign}{f.points:>3}  {f.reason}")
    print()


def _write_csv(results: list, out_path: str) -> None:
    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["path", "subject", "from", "score", "verdict", "top_reasons"])
        for r in results:
            top_reasons = "; ".join(f.reason for f in r.findings[:3])
            writer.writerow([
                r.email.raw_path, r.email.subject, r.email.from_addr,
                r.score, r.verdict, top_reasons,
            ])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="phishing_scanner",
        description="Heuristically score .eml files as legitimate or phishing.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan one .eml file or a directory of .eml files")
    scan_p.add_argument("target", help="Path to a .eml file or a directory containing .eml files")
    scan_p.add_argument("--json", action="store_true", help="Output JSON instead of human-readable text")
    scan_p.add_argument("--csv", metavar="OUT.csv", help="Write a CSV summary report to this path")
    scan_p.add_argument("--quiet", action="store_true", help="Only print the summary line per email, not each finding")
    scan_p.add_argument("--min-score", type=int, default=0, help="Only show results with score >= this value")

    args = parser.parse_args(argv)

    if args.command == "scan":
        target = Path(args.target)
        try:
            paths = list(_iter_eml_paths(target))
        except FileNotFoundError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

        if not paths:
            print(f"No .eml files found under {target}", file=sys.stderr)
            return 1

        results = []
        for p in paths:
            try:
                parsed = parse_eml_file(str(p))
                result = score_email(parsed)
                results.append(result)
            except Exception as e:
                print(f"Failed to parse {p}: {e}", file=sys.stderr)

        results = [r for r in results if r.score >= args.min_score]
        results.sort(key=lambda r: -r.score)

        if args.json:
            print(json.dumps([_result_to_dict(r) for r in results], indent=2))
        else:
            for r in results:
                _print_human(r, verbose=not args.quiet)

        if args.csv:
            _write_csv(results, args.csv)
            print(f"CSV report written to {args.csv}", file=sys.stderr)

        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
