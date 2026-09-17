import os

import pytest

from vaptframework.testplan.loader import load_test_cases, group_by_module, TEST_CASE_SHEET

PLAN = os.path.join(os.path.dirname(__file__), "..", "testplan", "VahanSpace_VAPT_Automation_Test_Plan.xlsx")
PLAN = os.path.abspath(PLAN)


@pytest.mark.skipif(not os.path.exists(PLAN), reason="test plan xlsx not present")
def test_loads_all_planned_cases():
    cases = load_test_cases(PLAN)
    assert len(cases) >= 280
    ids = {c.test_id for c in cases}
    assert "VAPT-001" in ids


@pytest.mark.skipif(not os.path.exists(PLAN), reason="test plan xlsx not present")
def test_case_fields_populated():
    cases = load_test_cases(PLAN)
    first = next(c for c in cases if c.test_id == "VAPT-001")
    assert first.module == "Authentication"
    assert first.severity
    assert first.row >= 2
    assert first.is_automated in (True, False)


@pytest.mark.skipif(not os.path.exists(PLAN), reason="test plan xlsx not present")
def test_group_by_module_covers_expected_modules():
    groups = group_by_module(load_test_cases(PLAN))
    for module in ["Authentication", "Authorization & BOLA", "API Security", "Android", "iOS"]:
        assert module in groups
        assert len(groups[module]) > 0


def test_missing_sheet_raises(tmp_path):
    import openpyxl

    p = os.path.join(tmp_path, "empty.xlsx")
    wb = openpyxl.Workbook()
    wb.save(p)
    with pytest.raises(KeyError):
        load_test_cases(p, sheet=TEST_CASE_SHEET)
