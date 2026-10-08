import sys
import os

# Make src/ importable from the tests/ folder
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect_iam_changes import (
    check_root_activity,
    check_sensitive_iam_change,
    check_off_hours_iam_change,
    check_new_action_for_identity,
    check_failed_then_successful_login,
)


# --- CT-001: Root Account Activity ---

def test_ct001_fires_on_root_activity():
    detail = {
        "userIdentity": {"type": "Root"},
        "eventName": "ListUsers",
        "eventTime": "2026-09-19T14:00:00Z",
        "sourceIPAddress": "1.2.3.4",
    }
    finding = check_root_activity(detail)
    assert finding is not None
    assert finding["rule_id"] == "CT-001"


def test_ct001_does_not_fire_on_iam_user():
    detail = {
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/someone"},
        "eventName": "ListUsers",
        "eventTime": "2026-09-19T14:00:00Z",
    }
    finding = check_root_activity(detail)
    assert finding is None


# --- CT-002: Sensitive IAM Changes ---

def test_ct002_fires_on_create_user():
    detail = {
        "eventName": "CreateUser",
        "eventTime": "2026-09-19T14:00:00Z",
        "userIdentity": {"arn": "arn:aws:iam::123:root"},
        "sourceIPAddress": "1.2.3.4",
    }
    finding = check_sensitive_iam_change(detail)
    assert finding is not None
    assert finding["rule_id"] == "CT-002"
    assert finding["severity"] == "MEDIUM"


def test_ct002_does_not_fire_on_read_only_action():
    detail = {
        "eventName": "GetPolicy",
        "eventTime": "2026-09-19T14:00:00Z",
        "userIdentity": {"arn": "arn:aws:iam::123:root"},
    }
    finding = check_sensitive_iam_change(detail)
    assert finding is None


# --- CT-003: Failed -> Successful Login correlation ---

def test_ct003_fires_on_two_failures_then_success():
    events = [
        {
            "userIdentity": {"userName": "alice"},
            "eventTime": "2026-09-19T15:06:30Z",
            "responseElements": {"ConsoleLogin": "Failure"},
        },
        {
            "userIdentity": {"userName": "alice"},
            "eventTime": "2026-09-19T15:06:39Z",
            "responseElements": {"ConsoleLogin": "Failure"},
        },
        {
            "userIdentity": {"userName": "alice"},
            "eventTime": "2026-09-19T15:09:05Z",
            "responseElements": {"ConsoleLogin": "Success"},
        },
    ]
    findings = check_failed_then_successful_login(events)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "CT-003"
    assert findings[0]["failed_attempts"] == 2


def test_ct003_does_not_fire_on_single_failure_then_success():
    events = [
        {
            "userIdentity": {"userName": "alice"},
            "eventTime": "2026-09-19T15:06:30Z",
            "responseElements": {"ConsoleLogin": "Failure"},
        },
        {
            "userIdentity": {"userName": "alice"},
            "eventTime": "2026-09-19T15:06:45Z",
            "responseElements": {"ConsoleLogin": "Success"},
        },
    ]
    findings = check_failed_then_successful_login(events)
    assert len(findings) == 0


def test_ct003_does_not_fire_when_success_is_outside_window():
    events = [
        {
            "userIdentity": {"userName": "alice"},
            "eventTime": "2026-09-19T15:00:00Z",
            "responseElements": {"ConsoleLogin": "Failure"},
        },
        {
            "userIdentity": {"userName": "alice"},
            "eventTime": "2026-09-19T15:01:00Z",
            "responseElements": {"ConsoleLogin": "Failure"},
        },
        {
            "userIdentity": {"userName": "alice"},
            "eventTime": "2026-09-19T15:30:00Z",  # 29 minutes later, past the 15-minute window
            "responseElements": {"ConsoleLogin": "Success"},
        },
    ]
    findings = check_failed_then_successful_login(events)
    assert len(findings) == 0


# --- CT-004: Off-Hours IAM Changes ---

def test_ct004_fires_outside_business_hours():
    # A Saturday, well outside business hours regardless of time
    detail = {
        "eventName": "CreateUser",
        "eventTime": "2026-09-19T03:00:00Z",  # very early UTC, and a Saturday in Chicago too
        "userIdentity": {"arn": "arn:aws:iam::123:root"},
        "sourceIPAddress": "1.2.3.4",
    }
    finding = check_off_hours_iam_change(detail)
    assert finding is not None
    assert finding["rule_id"] == "CT-004"


def test_ct004_does_not_fire_during_business_hours():
    # A Tuesday at 15:00 UTC = 10:00 AM Central -- inside business hours
    detail = {
        "eventName": "CreateUser",
        "eventTime": "2026-09-15T15:00:00Z",
        "userIdentity": {"arn": "arn:aws:iam::123:root"},
    }
    finding = check_off_hours_iam_change(detail)
    assert finding is None


def test_ct004_does_not_fire_on_non_sensitive_action():
    detail = {
        "eventName": "GetPolicy",
        "eventTime": "2026-09-19T03:00:00Z",  # off-hours time, but not a sensitive action
        "userIdentity": {"arn": "arn:aws:iam::123:root"},
    }
    finding = check_off_hours_iam_change(detail)
    assert finding is None


# --- CT-005: Behavioral Baseline (new action for identity) ---

def test_ct005_does_not_fire_on_first_run():
    baseline = {}
    detail = {
        "eventName": "DescribeTrails",
        "eventTime": "2026-09-19T14:00:00Z",
        "userIdentity": {"arn": "arn:aws:iam::123:user/tool"},
    }
    finding = check_new_action_for_identity(detail, baseline, is_first_run=True)
    assert finding is None
    # But the action should still be recorded into the baseline
    assert "DescribeTrails" in baseline["arn:aws:iam::123:user/tool"]


def test_ct005_fires_on_genuinely_new_action():
    baseline = {"arn:aws:iam::123:user/tool": {"LookupEvents"}}
    detail = {
        "eventName": "DescribeTrails",
        "eventTime": "2026-09-19T14:00:00Z",
        "userIdentity": {"arn": "arn:aws:iam::123:user/tool"},
    }
    finding = check_new_action_for_identity(detail, baseline, is_first_run=False)
    assert finding is not None
    assert finding["rule_id"] == "CT-005"


def test_ct005_does_not_fire_on_known_action():
    baseline = {"arn:aws:iam::123:user/tool": {"LookupEvents", "DescribeTrails"}}
    detail = {
        "eventName": "DescribeTrails",
        "eventTime": "2026-09-19T14:00:00Z",
        "userIdentity": {"arn": "arn:aws:iam::123:user/tool"},
    }
    finding = check_new_action_for_identity(detail, baseline, is_first_run=False)
    assert finding is None