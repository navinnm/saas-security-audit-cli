#!/usr/bin/env python3
"""Export the plugin scanner's rules to rules.json for the npm CLI.

The Claude Code plugin's scripts/scan.py is the single source of truth. This script
imports it, converts every regex from Python to JavaScript syntax, and writes
rules.json so both scanners stay identical.

Usage: python3 scripts/sync-rules.py --plugin ../saas-security-audit/scripts/scan.py
"""
import argparse
import importlib.util
import json
import re
from pathlib import Path


def js_regex(rx):
    source, flags = rx.pattern, ""
    if source.startswith("(?i)"):
        source = source[4:]
    if rx.flags & re.IGNORECASE:
        flags += "i"
    if "(?i)" in source or "(?s)" in source or "(?m)" in source or "(?x)" in source:
        raise ValueError(f"inline flag inside pattern is not portable: {rx.pattern[:80]}")
    if "\\Z" in source or "\\A" in source:
        raise ValueError(f"\\A/\\Z anchors are not portable: {rx.pattern[:80]}")
    source = source.replace("(?P<", "(?<")
    source = re.sub(r"\(\?P=(\w+)\)", r"\\k<\1>", source)
    return {"source": source, "flags": flags}


def load(path):
    spec = importlib.util.spec_from_file_location("plugin_scan", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def export(m):
    return {
        "generated_from": "saas-security-audit plugin scripts/scan.py",
        "version": m.VERSION,
        "schema_version": m.SCHEMA_VERSION,
        "controls": m.CONTROLS,
        "severity_rank": m.SEVERITY_RANK,
        "skip_dirs": sorted(m.SKIP_DIRS),
        "code_exts": sorted(m.CODE_EXTS),
        "config_exts": sorted(m.CONFIG_EXTS),
        "sql_exts": sorted(m.SQL_EXTS),
        "doc_exts": sorted(m.DOC_EXTS),
        "config_names": sorted(m.CONFIG_NAMES),
        "lockfiles": sorted(m.LOCKFILES),
        "manifests": m.MANIFESTS,
        "lock_for": {k: sorted(v) for k, v in m.LOCK_FOR.items()},
        "dep_tools": {k: [{"command": c, "binary": b, "network": n} for c, b, n in v] for k, v in m.DEP_TOOLS.items()},
        "general_tools": [{"command": c, "binary": b, "network": n} for c, b, n in m.GENERAL_TOOLS],
        "max_bytes": m.MAX_BYTES,
        "max_line": m.MAX_LINE,
        "max_signal_locations": m.MAX_SIGNAL_LOCATIONS,
        "comment_prefixes": list(m.COMMENT_PREFIXES),
        "rules": [{
            "id": r.rid, "title": r.title, "severity": r.severity, "confidence": r.confidence,
            "controls": list(r.controls), "scope": sorted(r.scope), "skip_comments": r.skip_comments,
            "guidance": r.guidance,
            "patterns": [dict(js_regex(rx), exts=sorted(exts) if exts else None) for rx, exts in r.patterns],
        } for r in m.RULES],
        "secret_formats": [dict(js_regex(rx), title=t, severity=s, groups=sorted(rx.groupindex))
                           for t, rx, s in m.SECRET_FORMATS],
        "regex": {name.lower(): js_regex(getattr(m, name)) for name in (
            "QUOTED_CRED_RE", "ENV_CRED_RE", "BEARER_RE", "PLACEHOLDER_RE", "LOCAL_HOST_RE", "SUPPRESS_RE",
            "TEST_PATH_RE", "EXAMPLE_ENV_RE", "WEBHOOK_ROUTE_RE", "WEBHOOK_VERIFY_RE", "WEBHOOK_IDEMPOTENCY_RE",
            "CREATE_TABLE_RE", "ENABLE_RLS_RE", "DROP_TABLE_RE", "POLICY_RE", "DRIZZLE_TABLE_RE", "DRIZZLE_RLS_RE",
            "PRISMA_MODEL_RE", "TENANT_FIELD_RE", "PRISMA_GLOBAL_MODELS")},
        "control_signals": {str(k): js_regex(v) for k, v in m.CONTROL_SIGNALS.items()},
        "security_packages": {k: {"control": c, "role": r} for k, (c, r) in m.SECURITY_PACKAGES.items()},
        "rule_titles": m.RULE_TITLES,
        "secret_guidance": m.SECRET_GUIDANCE,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--plugin", required=True, help="Path to the plugin's scripts/scan.py")
    parser.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "rules.json"))
    args = parser.parse_args()
    data = export(load(args.plugin))
    Path(args.out).write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {args.out}: {len(data['rules'])} rules, {len(data['secret_formats'])} secret formats, "
          f"{len(data['control_signals'])} control signals")


if __name__ == "__main__":
    main()
