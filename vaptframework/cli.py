"""Command-line entrypoint for the VAPT Framework.

Usage:
    python -m vaptframework.cli run    --config config/vahanspace.yaml
    python -m vaptframework.cli report --config config/vahanspace.yaml
    python -m vaptframework.cli scope-check --config config/vahanspace.yaml --url https://host/
    python -m vaptframework.cli stop   --config config/vahanspace.yaml   # engage kill switch
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .core.config import build_scanners, load_run_config
from .core.engine import Engine
from .reporting.report import ReportMeta, build_html, build_markdown
from .reporting.xlsx_writer import write_findings
from .testplan.loader import group_by_module, load_test_cases


def _coverage(plan_path: str):
    if not plan_path or not os.path.exists(plan_path):
        return None
    groups = group_by_module(load_test_cases(plan_path))
    return [
        {"module": m, "planned": len(cs), "automated": sum(1 for c in cs if c.is_automated)}
        for m, cs in sorted(groups.items())
    ]


def cmd_run(args):
    rc = load_run_config(args.config)
    scanners = build_scanners(rc.suites)
    report = Engine(rc.context).run(scanners)
    os.makedirs(rc.report_dir, exist_ok=True)
    summary = report.summary()

    print(json.dumps(summary, indent=2))

    with open(os.path.join(rc.report_dir, "run_summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    with open(os.path.join(rc.report_dir, "findings.json"), "w", encoding="utf-8") as fh:
        fh.write(report.register.to_json())

    meta = ReportMeta(
        application=rc.meta.get("application", "VahanSpace"),
        engagement=rc.meta.get("engagement", ""),
        environment=rc.context.scope.scope.environment,
        tester=rc.meta.get("tester", ""),
        authorized_by=rc.context.authorization.authorized_by,
        scope_note=rc.meta.get("scope_note", ""),
        testing_mode=rc.meta.get("testing_mode", "Static + guarded DAST"),
    )
    coverage = _coverage(args.plan)
    md = build_markdown(meta, summary, report.register, coverage)
    html_out = build_html(meta, summary, report.register, coverage)
    with open(os.path.join(rc.report_dir, "VAPT_Report.md"), "w", encoding="utf-8") as fh:
        fh.write(md)
    with open(os.path.join(rc.report_dir, "VAPT_Report.html"), "w", encoding="utf-8") as fh:
        fh.write(html_out)

    if args.plan and os.path.exists(args.plan):
        try:
            out_xlsx = args.plan if args.write_plan else os.path.join(rc.report_dir, os.path.basename(args.plan))
            write_findings(args.plan, report.register, out_path=out_xlsx)
            print(f"[+] Wrote findings into workbook: {out_xlsx}")
        except Exception as exc:  # noqa: BLE001
            print(f"[!] Could not update workbook: {exc}", file=sys.stderr)

    print(f"[+] Reports written to {rc.report_dir}/")
    return 0


def cmd_scope_check(args):
    rc = load_run_config(args.config)
    ok = rc.context.scope.is_in_scope(args.url)
    print(f"{'IN SCOPE' if ok else 'OUT OF SCOPE'}: {args.url}")
    return 0 if ok else 2


def cmd_stop(args):
    rc = load_run_config(args.config)
    ks = rc.context.throttle.kill_switch
    ks.engage("stopped via CLI")
    print(f"[+] Kill switch engaged: {ks.stop_file}")
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="vaptframework", description="Guardrailed VAPT automation framework")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="run enabled scanner suites and generate reports")
    r.add_argument("--config", required=True)
    r.add_argument("--plan", default="testplan/VahanSpace_VAPT_Automation_Test_Plan.xlsx",
                   help="path to the test plan xlsx (for coverage + write-back)")
    r.add_argument("--write-plan", action="store_true", help="write findings back into the original plan file")
    r.set_defaults(func=cmd_run)

    s = sub.add_parser("scope-check", help="check whether a URL is in scope")
    s.add_argument("--config", required=True)
    s.add_argument("--url", required=True)
    s.set_defaults(func=cmd_scope_check)

    k = sub.add_parser("stop", help="engage the kill switch to halt active testing")
    k.add_argument("--config", required=True)
    k.set_defaults(func=cmd_stop)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
