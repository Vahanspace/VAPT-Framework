"""Write findings back into the VAPT test plan workbook.

Populates the 'Vulnerability Register' sheet and refreshes the severity roll-up on the
'Dashboard' sheet, keeping the analyst worksheet and automation in sync. Existing sheets and
formatting are preserved; only data cells are written.
"""
from __future__ import annotations

import openpyxl

from ..core.findings import FindingsRegister
from ..core.severity import Severity

REGISTER_SHEET = "Vulnerability Register"
DASHBOARD_SHEET = "Dashboard"

# Vulnerability Register headers (row 1):
# Finding ID | Test ID | Title | Platform | Module | Severity | CVSS | Status |
# Description | Evidence | Remediation | Owner | Target Date | Retest Result
_REGISTER_COLS = ["finding_id", "test_id", "title", "platform", "module", "severity",
                  "cvss", "status", "description", "evidence_ref", "remediation"]


def write_findings(path: str, register: FindingsRegister, out_path: str | None = None) -> str:
    wb = openpyxl.load_workbook(path)
    out_path = out_path or path

    if REGISTER_SHEET in wb.sheetnames:
        ws = wb[REGISTER_SHEET]
        # clear existing data rows (keep header)
        if ws.max_row > 1:
            ws.delete_rows(2, ws.max_row - 1)
        r = 2
        for f in register:
            row = {
                "finding_id": f.finding_id, "test_id": f.test_id or "", "title": f.title,
                "platform": f.platform, "module": f.module, "severity": f.severity.label,
                "cvss": f.cvss or "", "status": f.status, "description": f.description[:900],
                "evidence_ref": f"{f.location} ({f.source})", "remediation": f.remediation,
            }
            for c, key in enumerate(_REGISTER_COLS, start=1):
                ws.cell(row=r, column=c, value=row[key])
            r += 1

    if DASHBOARD_SHEET in wb.sheetnames:
        ws = wb[DASHBOARD_SHEET]
        counts = register.counts_by_severity()
        # Column E (5), rows 5..9 = Critical, High, Medium, Low, Informational; row 10 = Total Open
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL]
        for i, sev in enumerate(order):
            ws.cell(row=5 + i, column=5, value=counts.get(sev.label, 0))
        ws.cell(row=10, column=5, value=register.open_count())

    wb.save(out_path)
    return out_path
