import boto3
import json
import os
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

# --- CT-001 ---

def check_root_activity(detail):
    if detail.get("userIdentity", {}).get("type") == "Root":
        return {
            "rule_id": "CT-001",
            "severity": "HIGH",
            "event_name": detail.get("eventName"),
            "event_time": detail.get("eventTime"),
            "source_ip": detail.get("sourceIPAddress"),
            "recommendation": "Investigate this root account action. Root should rarely, if ever, be used for day-to-day operations."
        }
    return None

# --- CT-002 ---

SENSITIVE_IAM_ACTIONS = {
    "CreateUser", "DeleteUser", "CreateAccessKey",
    "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy",
}

IAM_ACTION_SEVERITY = {
    "CreateUser": "MEDIUM", "DeleteUser": "MEDIUM", "CreateAccessKey": "MEDIUM",
    "AttachUserPolicy": "HIGH", "AttachRolePolicy": "HIGH", "PutUserPolicy": "HIGH",
}

IAM_ACTION_RECOMMENDATIONS = {
    "CreateUser": "Confirm this new user was expected and follows least-privilege provisioning.",
    "DeleteUser": "Confirm this user deletion was intentional and not a sign of account compromise cleanup.",
    "CreateAccessKey": "Confirm this new access key was requested by the user and not created on their behalf without knowledge.",
    "AttachUserPolicy": "Review the attached policy for excessive permissions (e.g. wildcard actions/resources).",
    "AttachRolePolicy": "Review the attached policy for excessive permissions (e.g. wildcard actions/resources).",
    "PutUserPolicy": "Review the inline policy content directly, since PutUserPolicy embeds the full document in the event.",
}

def check_sensitive_iam_change(detail):
    event_name = detail.get("eventName")
    if event_name in SENSITIVE_IAM_ACTIONS:
        return {
            "rule_id": "CT-002",
            "severity": IAM_ACTION_SEVERITY[event_name],
            "event_name": event_name,
            "event_time": detail.get("eventTime"),
            "source_ip": detail.get("sourceIPAddress"),
            "actor": detail.get("userIdentity", {}).get("arn"),
            "recommendation": IAM_ACTION_RECOMMENDATIONS[event_name]
        }
    return None

# --- CT-003 ---

CORRELATION_WINDOW_MINUTES = 15
FAILURE_THRESHOLD = 2

def check_failed_then_successful_login(login_events):
    """login_events: list of parsed CloudTrailEvent dicts, ConsoleLogin only, sorted oldest -> newest."""
    findings = []
    failures_by_user = {}

    for detail in login_events:
        user_key = detail.get("userIdentity", {}).get("userName")
        event_time = datetime.fromisoformat(detail["eventTime"].replace("Z", "+00:00"))
        is_success = detail.get("responseElements", {}).get("ConsoleLogin") == "Success"

        if not is_success:
            failures_by_user.setdefault(user_key, []).append(event_time)
            continue

        recent_failures = [
            t for t in failures_by_user.get(user_key, [])
            if event_time - t <= timedelta(minutes=CORRELATION_WINDOW_MINUTES)
        ]

        if len(recent_failures) >= FAILURE_THRESHOLD:
            findings.append({
                "rule_id": "CT-003",
                "severity": "MEDIUM",
                "actor": user_key,
                "event_time": detail.get("eventTime"),
                "failed_attempts": len(recent_failures),
                "source_ip": detail.get("sourceIPAddress"),
                "recommendation": "Multiple failed logins were followed by a success for this identity. Confirm this was the legitimate user and not a successful brute-force or credential-stuffing attempt."
            })

        failures_by_user[user_key] = []

    return findings


def fetch_console_logins_from_cw_logs(logs_client, log_group, minutes_back=30):
    """Pull ConsoleLogin events directly from CloudWatch Logs, with full pagination,
    since lookup_events has proven unreliable for this specific event type."""
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=minutes_back)

    all_events = []
    next_token = None

    while True:
        kwargs = {
            "logGroupName": log_group,
            "startTime": int(start_time.timestamp() * 1000),
            "endTime": int(end_time.timestamp() * 1000),
        }
        if next_token:
            kwargs["nextToken"] = next_token

        response = logs_client.filter_log_events(**kwargs)
        all_events.extend(response.get("events", []))

        next_token = response.get("nextToken")
        if not next_token:
            break

    login_events = []
    for event in all_events:
        detail = json.loads(event["message"])
        if detail.get("eventName") == "ConsoleLogin":
            login_events.append(detail)

    return login_events

# --- CT-004 ---

BUSINESS_HOURS_START = 9
BUSINESS_HOURS_END = 18
BUSINESS_TIMEZONE = "America/Chicago"
BUSINESS_DAYS = {0, 1, 2, 3, 4}

def is_off_hours(utc_dt, business_start=BUSINESS_HOURS_START, business_end=BUSINESS_HOURS_END,
                  tz_name=BUSINESS_TIMEZONE, business_days=None):
    if business_days is None:
        business_days = BUSINESS_DAYS
    local_dt = utc_dt.astimezone(ZoneInfo(tz_name))
    if local_dt.weekday() not in business_days:
        return True
    return not (business_start <= local_dt.hour < business_end)


def check_off_hours_iam_change(detail):
    event_name = detail.get("eventName")
    if event_name not in SENSITIVE_IAM_ACTIONS:
        return None

    event_time_str = detail.get("eventTime")
    if not event_time_str:
        return None

    utc_dt = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))

    if is_off_hours(utc_dt):
        return {
            "rule_id": "CT-004",
            "severity": "MEDIUM",
            "event_name": event_name,
            "event_time": event_time_str,
            "actor": detail.get("userIdentity", {}).get("arn"),
            "source_ip": detail.get("sourceIPAddress"),
            "recommendation": f"This sensitive IAM change occurred outside configured business hours ({BUSINESS_HOURS_START}:00-{BUSINESS_HOURS_END}:00 {BUSINESS_TIMEZONE}). Confirm this was expected, planned maintenance, or a legitimate after-hours action."
        }
    return None

# --- CT-005 (Phase 6: Behavioral Baseline, V2) ---

BASELINE_FILE = "baseline.json"

def load_baseline(path=BASELINE_FILE):
    if os.path.exists(path):
        with open(path, "r") as f:
            data = json.load(f)
        return {identity: set(actions) for identity, actions in data.items()}
    return {}


def save_baseline(baseline, path=BASELINE_FILE):
    serializable = {identity: sorted(actions) for identity, actions in baseline.items()}
    with open(path, "w") as f:
        json.dump(serializable, f, indent=2)


def check_new_action_for_identity(detail, baseline, is_first_run):
    identity = detail.get("userIdentity", {}).get("arn") or detail.get("userIdentity", {}).get("userName")
    action = detail.get("eventName")

    if not identity or not action:
        return None

    known_actions = baseline.setdefault(identity, set())

    is_new = action not in known_actions
    known_actions.add(action)

    if is_new and not is_first_run:
        return {
            "rule_id": "CT-005",
            "severity": "LOW",
            "event_name": action,
            "event_time": detail.get("eventTime"),
            "actor": identity,
            "source_ip": detail.get("sourceIPAddress"),
            "recommendation": f"This is the first time '{identity}' has been observed calling '{action}'. This deviates from the observed baseline and may warrant investigation, but is not confirmation of malicious activity."
        }
    return None


# --- Main ---

def main():
    session = boto3.Session(profile_name="cloudtrail-detector", region_name="us-east-1")
    cloudtrail_client = session.client("cloudtrail")

    response = cloudtrail_client.lookup_events(MaxResults=50)
    events = response.get("Events", [])
    all_details = [json.loads(e["CloudTrailEvent"]) for e in events]

    is_first_run = not os.path.exists(BASELINE_FILE)
    baseline = load_baseline()

    if is_first_run:
        print("No baseline.json found — this run will build the initial baseline. No CT-005 findings will be generated this run.\n")

    findings = []

    for detail in all_details:
        root_finding = check_root_activity(detail)
        if root_finding:
            findings.append(root_finding)

        iam_finding = check_sensitive_iam_change(detail)
        if iam_finding:
            findings.append(iam_finding)

        off_hours_finding = check_off_hours_iam_change(detail)
        if off_hours_finding:
            findings.append(off_hours_finding)

        baseline_finding = check_new_action_for_identity(detail, baseline, is_first_run)
        if baseline_finding:
            findings.append(baseline_finding)

    save_baseline(baseline)

    logs_client = session.client("logs", region_name="us-east-2")
    login_events = fetch_console_logins_from_cw_logs(
        logs_client,
        log_group="/aws/cloudtrail/cloudgoat-trail",
        minutes_back=30
    )
    login_events.sort(key=lambda d: d["eventTime"])
    findings.extend(check_failed_then_successful_login(login_events))

    print(f"Scanned {len(events)} general events + {len(login_events)} login events, found {len(findings)} findings\n")

    for f in findings:
        print(json.dumps(f, indent=2))
        print("-" * 60)


if __name__ == "__main__":
    main()