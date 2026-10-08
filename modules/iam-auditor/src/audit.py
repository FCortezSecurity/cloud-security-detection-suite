import boto3
import botocore
import csv
import io
import json
import os
import sys
import time
from datetime import datetime, timezone


def get_iam_client():
    session = boto3.Session(profile_name="security-auditor")
    return session.client("iam")


def get_users(iam_client):
    """Return all IAM users, following pagination (list_users caps at 100/page)."""
    users = []
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        users.extend(page["Users"])
    return users


def get_attached_policies(iam_client, username):
    response = iam_client.list_attached_user_policies(UserName=username)
    return response["AttachedPolicies"]


def check_admin_access(iam_client, username):
    policies = get_attached_policies(iam_client, username)
    for policy in policies:
        if policy["PolicyName"] == "AdministratorAccess":
            return {
                "check_id": "IAM-001",
                "severity": "HIGH",
                "user": username,
                "title": "AdministratorAccess attached",
                "recommendation": "Review whether full administrative access is required."
            }
    return None


def get_access_keys(iam_client, username):
    response = iam_client.list_access_keys(UserName=username)
    return response["AccessKeyMetadata"]


def check_old_access_keys(iam_client, username, threshold_days=90):
    findings = []
    keys = get_access_keys(iam_client, username)

    for key in keys:
        if key["Status"] != "Active":
            continue

        age_days = (datetime.now(timezone.utc) - key["CreateDate"]).days

        if age_days > threshold_days:
            findings.append({
                "check_id": "IAM-002",
                "severity": "MEDIUM",
                "user": username,
                "title": f"Access key is {age_days} days old",
                "recommendation": "Rotate or remove stale credentials."
            })

    return findings


def check_multiple_active_keys(iam_client, username):
    keys = get_access_keys(iam_client, username)
    active_keys = [k for k in keys if k["Status"] == "Active"]

    if len(active_keys) > 1:
        return {
            "check_id": "IAM-003",
            "severity": "LOW",
            "user": username,
            "title": f"User has {len(active_keys)} active access keys",
            "recommendation": "Reduce to a single active access key where possible."
        }
    return None


def get_credential_report(iam_client):
    iam_client.generate_credential_report()

    response = None
    for _ in range(10):
        try:
            response = iam_client.get_credential_report()
            break
        except iam_client.exceptions.CredentialReportNotReadyException:
            time.sleep(2)

    if response is None:
        raise RuntimeError("Credential report was not ready after multiple attempts.")

    csv_data = response["Content"].decode("utf-8")
    reader = csv.DictReader(io.StringIO(csv_data))
    return list(reader)


def check_password_age(credential_report, username, threshold_days=90):
    for row in credential_report:
        if row["user"] != username:
            continue

        if row["password_enabled"] != "true":
            return None

        last_changed = row["password_last_changed"]
        if last_changed in ("N/A", "not_supported", ""):
            return None

        changed_date = datetime.strptime(last_changed.split("+")[0].strip(), "%Y-%m-%d %H:%M:%S")
        changed_date = changed_date.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - changed_date).days

        if age_days > threshold_days:
            return {
                "check_id": "IAM-004",
                "severity": "MEDIUM",
                "user": username,
                "title": f"Console password is {age_days} days old",
                "recommendation": "Enforce a password rotation policy or require MFA-backed re-authentication."
            }
    return None


def check_wildcard_permissions(iam_client, username):
    findings = []

    # --- Inline policies ---
    inline_policy_names = iam_client.list_user_policies(UserName=username)["PolicyNames"]
    for policy_name in inline_policy_names:
        doc = iam_client.get_user_policy(UserName=username, PolicyName=policy_name)["PolicyDocument"]
        if _has_wildcard_statement(doc):
            findings.append(_wildcard_finding(username, f"Inline policy '{policy_name}'"))

    # --- Managed policies ---
    attached = iam_client.list_attached_user_policies(UserName=username)["AttachedPolicies"]
    for policy in attached:
        policy_arn = policy["PolicyArn"]
        default_version_id = iam_client.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
        doc = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=default_version_id
        )["PolicyVersion"]["Document"]
        if _has_wildcard_statement(doc):
            findings.append(_wildcard_finding(username, f"Managed policy '{policy['PolicyName']}'"))

    return findings


def _has_wildcard_statement(policy_document):
    statements = policy_document["Statement"]
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        resources = statement.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        if "*" in actions and "*" in resources:
            return True

    return False


def _wildcard_finding(username, source):
    return {
        "check_id": "IAM-005",
        "severity": "HIGH",
        "user": username,
        "title": f"{source} grants wildcard permissions (Action: *, Resource: *)",
        "recommendation": "Scope this policy down to only the specific actions and resources required."
    }


def run_all_checks(iam_client, credential_report):
    users = get_users(iam_client)
    findings = []

    for user in users:
        username = user["UserName"]

        admin_finding = check_admin_access(iam_client, username)
        if admin_finding:
            findings.append(admin_finding)

        findings.extend(check_old_access_keys(iam_client, username))

        multi_key_finding = check_multiple_active_keys(iam_client, username)
        if multi_key_finding:
            findings.append(multi_key_finding)

        password_finding = check_password_age(credential_report, username)
        if password_finding:
            findings.append(password_finding)

        findings.extend(check_wildcard_permissions(iam_client, username))

    return findings


def build_human_report(findings):
    lines = []
    lines.append("AWS IAM Security Audit")
    lines.append("======================")

    if not findings:
        lines.append("No findings.")
    else:
        for f in findings:
            lines.append(f"[{f['severity']}] {f['check_id']}")
            lines.append(f"User: {f['user']}")
            lines.append(f"Issue: {f['title']}")
            lines.append(f"Recommendation: {f['recommendation']}")
            lines.append("-" * 40)

    lines.append(f"\nTotal findings: {len(findings)}")
    return "\n".join(lines)


def build_json_report(findings):
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        severity_counts[f["severity"]] += 1

    report = {
        "summary": {
            "high": severity_counts["HIGH"],
            "medium": severity_counts["MEDIUM"],
            "low": severity_counts["LOW"],
            "total": len(findings)
        },
        "findings": findings
    }

    return json.dumps(report, indent=2)


def save_report(content, filename):
    os.makedirs("reports", exist_ok=True)
    path = os.path.join("reports", filename)
    with open(path, "w") as f:
        f.write(content)
    return path


def main():
    try:
        iam = get_iam_client()
        credential_report = get_credential_report(iam)
        findings = run_all_checks(iam, credential_report)
    except botocore.exceptions.ProfileNotFound:
        print("Error: AWS profile 'security-auditor' was not found.")
        print("Run 'aws configure --profile security-auditor' to set it up.")
        sys.exit(1)
    except botocore.exceptions.NoCredentialsError:
        print("Error: No credentials found for the 'security-auditor' profile.")
        sys.exit(1)
    except botocore.exceptions.ClientError as e:
        print(f"AWS API error: {e}")
        print("Check that the security-auditor profile has the required read-only IAM permissions.")
        sys.exit(1)

    use_json = "--json" in sys.argv

    if use_json:
        report_text = build_json_report(findings)
        print(report_text)
        saved_path = save_report(report_text, "audit.json")
    else:
        report_text = build_human_report(findings)
        print(report_text)
        saved_path = save_report(report_text, "audit.txt")

    print(f"\nReport saved to {saved_path}")


if __name__ == "__main__":
    main()