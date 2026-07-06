#!/usr/bin/env python3
"""
Build a Rule -> Events mapping table for this detection/hunting rules repo.

The repo stores rules as Markdown (.md) files that embed KQL queries inside
fenced ```KQL code blocks (there are no JSON rule files). The "events" a rule
operates on are therefore derived directly from the KQL:

  1. The KQL TABLE NAME(S) referenced (the data source), and
  2. The specific event filter VALUES pulled from `ActionType`,
     `OperationName` and `Operation` predicates (both `==` and `in (...)`).

Output: RULE-EVENTS-MAPPING.md at the repo root (and printed to stdout).

Re-runnable and deterministic. Does NOT commit anything.
"""

import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))

# Files to skip (pure templates / trivial docs, not actual rules)
SKIP_FILES = {
    "DetectionTemplate.md",
}

# Curated list of known Defender/Sentinel/Entra/Office table names.
KNOWN_TABLES = {
    # Defender for Endpoint / XDR device tables
    "DeviceEvents", "DeviceProcessEvents", "DeviceNetworkEvents",
    "DeviceFileEvents", "DeviceRegistryEvents", "DeviceLogonEvents",
    "DeviceImageLoadEvents", "DeviceInfo", "DeviceNetworkInfo",
    "DeviceFileCertificateInfo", "DeviceTvmSoftwareInventory",
    "DeviceTvmSoftwareVulnerabilities", "DeviceTvmSoftwareVulnerabilitiesKB",
    "DeviceTvmSecureConfigurationAssessment",
    "DeviceTvmSecureConfigurationAssessmentKB",
    "DeviceTvmInfoGathering", "DeviceTvmInfoGatheringKB",
    "DeviceTvmSoftwareEvidenceBeta", "DeviceTvmBrowserExtensions",
    "DeviceTvmBrowserExtensionsKB", "DeviceTvmCertificateInfo",
    "DeviceTvmHardwareFirmware", "DeviceBaselineComplianceProfiles",
    "DeviceBaselineComplianceAssessment", "DeviceBaselineComplianceAssessmentKB",
    # Email / Defender for Office 365
    "EmailEvents", "EmailAttachmentInfo", "EmailUrlInfo",
    "EmailPostDeliveryEvents", "UrlClickEvents",
    # Cloud apps / MDA
    "CloudAppEvents", "AADSpnSignInEventsBeta",
    # Identity (MDI)
    "IdentityLogonEvents", "IdentityDirectoryEvents", "IdentityQueryEvents",
    "IdentityInfo",
    # Alerts
    "AlertInfo", "AlertEvidence",
    # Entra ID / Azure AD (Sentinel)
    "AuditLogs", "SigninLogs", "AADNonInteractiveUserSignInLogs",
    "AADServicePrincipalSignInLogs", "AADManagedIdentitySignInLogs",
    "AADProvisioningLogs", "AADUserRiskEvents", "AADRiskyUsers",
    "AADRiskyServicePrincipals", "AADServicePrincipalRiskEvents",
    "AADDomainServicesAccountLogon", "AADDomainServicesAccountManagement",
    # Azure / Sentinel infra
    "AzureActivity", "AzureDiagnostics", "AzureMetrics",
    "SecurityEvent", "SecurityAlert", "SecurityIncident",
    "Syslog", "CommonSecurityLog", "Heartbeat", "Event",
    "SigninLogs", "OfficeActivity", "Perf", "W3CIISLog",
    "DnsEvents", "DnsInventory", "WindowsFirewall",
    "ThreatIntelligenceIndicator", "ThreatIntelIndicators",
    "Anomalies", "Watchlist",
    # Sentinel network / other
    "VMConnection", "WireData", "ProtectionStatus",
    "ConfigurationChange", "ConfigurationData", "UpdateSummary",
    "SecurityBaseline", "SecurityBaselineSummary",
    "InformationProtectionLogs_CL", "SecurityRegulatoryCompliance",
    "MicrosoftGraphActivityLogs", "NetworkAccessTraffic",
    "BehaviorAnalytics", "IdentityInfo", "UserAccessAnalytics",
    "UserPeerAnalytics", "AADManagedIdentitySignInLogs",
    "NetworkSessions", "CloudAppEvents",
    # Exposure management
    "ExposureGraphNodes", "ExposureGraphEdges",
    # Additional first-party tables observed in this repo
    "GraphAPIAuditEvents", "CloudAuditEvents", "OAuthAppInfo",
    "AADSignInEventsBeta", "LAQueryLogs", "CloudProcessEvents",
    # Special sources
    "externaldata",
}

# Table names are case-sensitive in KQL; build a lookup for validation.
KNOWN_TABLES_SET = set(KNOWN_TABLES)

# Tokens that are KQL operators/functions, not tables — never treat as a table
# even if they appear at a statement start.
NON_TABLE_TOKENS = {
    "let", "union", "join", "where", "project", "extend", "summarize",
    "order", "sort", "take", "top", "limit", "distinct", "count", "mv-expand",
    "mvexpand", "parse", "evaluate", "invoke", "render", "print", "range",
    "search", "find", "datatable", "materialize", "toscalar", "make-series",
    "make_series", "on", "kind", "as", "by", "and", "or", "not", "has",
    "contains", "startswith", "endswith", "in", "if", "case", "iff",
    # `Update` is a KQL operator context (e.g. `| project ... Update`), not a
    # data-source table in these AuditLogs queries — never treat it as a table.
    "Update", "update",
}

# Regexes -------------------------------------------------------------------

# KQL fenced code blocks (case-insensitive language tag KQL/kql)
FENCE_RE = re.compile(r"```[ \t]*[kK][qQ][lL][ \t]*\r?\n(.*?)```", re.DOTALL)

# A statement-start table reference: start of the KQL text, or after a
# newline (optionally preceded by 'union', 'join (', 'find in (').
# We capture an identifier that is then followed (on the same logical line,
# eventually) by a pipe, or is a known table, or preceded by union/join.
IDENT = r"[A-Za-z_][A-Za-z0-9_]*"

# `let X = TableName ...` sources
LET_SOURCE_RE = re.compile(
    r"\blet\s+" + IDENT + r"\s*=\s*(" + IDENT + r")\b"
)

# union / join sources: `union T1, T2`, `union (T)`, `join (T | ...)`,
# `join kind=inner T`, `find in (T1, T2)`
UNION_RE = re.compile(r"\bunion\b([^\|\n]+)", re.IGNORECASE)
JOIN_RE = re.compile(r"\bjoin\b(?:\s+kind\s*=\s*\w+)?\s*(?:\(\s*)?(" + IDENT + r")")
FIND_IN_RE = re.compile(r"\bfind\b.*?\bin\s*\(([^)]*)\)", re.IGNORECASE | re.DOTALL)

# ActionType / OperationName / Operation filters
FILTER_EQ_RE = re.compile(
    r"\b(?:ActionType|OperationName|Operation)\s*==\s*(['\"])(.*?)\1"
)
FILTER_IN_RE = re.compile(
    r"\b(?:ActionType|OperationName|Operation)\s*(?:!)?in~?\s*\(([^)]*)\)",
    re.IGNORECASE,
)
STRING_LIT_RE = re.compile(r"(['\"])(.*?)\1")


def extract_kql_blocks(text):
    return FENCE_RE.findall(text)


def strip_comments(kql):
    # Remove // line comments to avoid false positives
    return re.sub(r"//[^\n]*", "", kql)


def find_tables(kql):
    tables = set()
    cleaned = strip_comments(kql)

    # Names introduced by `let NAME = ...` are query-local aliases, NOT tables.
    let_names = set(re.findall(r"\blet\s+(" + IDENT + r")\s*=", cleaned))

    # 1) Known tables appearing anywhere as a whole word (catches the source
    #    line plus inline `union DeviceEvents, DeviceInfo` and mid-query joins).
    for t in KNOWN_TABLES_SET:
        if re.search(r"(?<![A-Za-z0-9_])" + re.escape(t) + r"(?![A-Za-z0-9_])", cleaned):
            tables.add(t)

    # 2) Generic heuristic for UNKNOWN source tables: a PascalCase identifier
    #    that begins a statement (first non-blank line of the query, or the
    #    line immediately after a `;` statement terminator) and is either alone
    #    on its line or immediately piped (`Table` / `Table | where ...`).
    #    Requiring a statement boundary avoids the last column of a multi-line
    #    `project`/`summarize` clause (those follow a trailing comma), and
    #    excluding `let` aliases avoids counting local subqueries as tables.
    prev_end = None  # last char of previous non-blank logical line
    first_data_seen = False
    for raw in cleaned.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = re.match(r"^\(?\s*(" + IDENT + r")\b(.*)$", line)
        at_stmt_start = (prev_end is None) or (prev_end == ";")
        if m:
            tok = m.group(1)
            rest = m.group(2).strip()
            if (at_stmt_start
                    and tok not in NON_TABLE_TOKENS
                    and tok not in let_names
                    and tok not in KNOWN_TABLES_SET
                    and tok[0].isupper()
                    and (rest == "" or rest.startswith("|"))):
                tables.add(tok)
        prev_end = line[-1]

    return tables


def find_filters(kql):
    filters = set()
    cleaned = strip_comments(kql)
    for m in FILTER_EQ_RE.finditer(cleaned):
        val = m.group(2).strip()
        if val:
            filters.add(val)
    for m in FILTER_IN_RE.finditer(cleaned):
        inner = m.group(1)
        for sm in STRING_LIT_RE.finditer(inner):
            val = sm.group(2).strip()
            if val:
                filters.add(val)
    return filters


def get_title(text):
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("# "):
            return s[2:].strip()
    return None


def main():
    rows = []
    no_table = []
    total = 0

    for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
        # prune .git
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for fn in sorted(filenames):
            if not fn.endswith(".md"):
                continue
            if fn in SKIP_FILES:
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, REPO_ROOT)

            with open(full, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()

            blocks = extract_kql_blocks(text)
            if not blocks:
                # Not a rule (no KQL) — skip README/community/index docs.
                continue

            total += 1

            tables = set()
            filters = set()
            for b in blocks:
                tables |= find_tables(b)
                filters |= find_filters(b)

            category = rel.split(os.sep)[0] if os.sep in rel else "(root)"

            if not tables:
                no_table.append(rel)

            rows.append({
                "rule": rel.replace(os.sep, "/"),
                "category": category,
                "tables": ", ".join(sorted(tables)),
                "filters": ", ".join(sorted(filters)),
            })

    # Sort by category then rule
    rows.sort(key=lambda r: (r["category"].lower(), r["rule"].lower()))

    # Build markdown
    lines = []
    lines.append("# Rule to Events Mapping\n")
    lines.append(
        "This table maps every detection/hunting rule in this repository to the "
        "**events** it operates on. Because rules here are authored as KQL inside "
        "Markdown (`.md`) files — there are no JSON rule definitions — the events "
        "are derived directly from each rule's KQL:\n"
    )
    lines.append(
        "- **Tables / Data Sources**: the distinct KQL table names the query reads "
        "from (e.g. `DeviceProcessEvents`, `EmailEvents`, `AuditLogs`, "
        "`externaldata` for MISP feeds). Detected from statement-start references, "
        "`union`/`join` sources, `let` sources, and a curated known-tables list.\n"
        "- **Event Filters**: the specific event values selected within those "
        "tables via `ActionType == \"...\"`, `OperationName == \"...\"`, "
        "`Operation == \"...\"`, and their `in (...)` list forms. Blank when the "
        "rule does not filter on a specific event type.\n"
    )
    lines.append(
        "Generated deterministically by `build_rule_events_mapping.py`. "
        f"Rules processed: **{total}**.\n"
    )
    lines.append("| Rule | Category | Tables / Data Sources | Event Filters |")
    lines.append("| --- | --- | --- | --- |")
    for r in rows:
        rule = r["rule"].replace("|", "\\|")
        cat = r["category"].replace("|", "\\|")
        tbl = r["tables"].replace("|", "\\|") or "—"
        flt = r["filters"].replace("|", "\\|")
        lines.append(f"| {rule} | {cat} | {tbl} | {flt} |")

    output = "\n".join(lines) + "\n"

    out_path = os.path.join(REPO_ROOT, "RULE-EVENTS-MAPPING.md")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(output)

    # Print to stdout
    print(output)
    print("=" * 70, file=sys.stderr)
    print(f"Total rules processed (files with >=1 KQL block): {total}", file=sys.stderr)
    print(f"Rules with NO detectable table: {len(no_table)}", file=sys.stderr)
    for p in no_table:
        print(f"  - {p}", file=sys.stderr)


if __name__ == "__main__":
    main()
