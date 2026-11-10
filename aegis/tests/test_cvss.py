"""CVSS v3.1 base-score calculator tests (published reference anchors)."""

import pytest

from aegis.analysis import cvss


def test_known_anchors():
    assert cvss.base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss.base_score("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert cvss.base_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N") == 3.1


def test_severity_bands():
    assert cvss.severity_band(9.8) == "Critical"
    assert cvss.severity_band(7.0) == "High"
    assert cvss.severity_band(4.0) == "Medium"
    assert cvss.severity_band(0.1) == "Low"
    assert cvss.severity_band(0.0) == "None"


def test_missing_metric_raises():
    with pytest.raises(ValueError):
        cvss.base_score("AV:N/AC:L")
