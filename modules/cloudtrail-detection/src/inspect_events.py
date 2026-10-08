import boto3
import json

session = boto3.Session(profile_name="cloudtrail-detector", region_name="us-east-1")
client = session.client("cloudtrail")

response = client.lookup_events(MaxResults=20)
events = response.get("Events", [])

findings = []

for event in events:
    detail = json.loads(event["CloudTrailEvent"])

    if detail.get("userIdentity", {}).get("type") == "Root":
        finding = {
            "rule_id": "CT-001",
            "severity": "HIGH",
            "event_name": detail.get("eventName"),
            "event_time": detail.get("eventTime"),
            "source_ip": detail.get("sourceIPAddress"),
            "recommendation": "Investigate this root account action. Root should rarely, if ever, be used for day-to-day operations."
        }
        findings.append(finding)

print(f"Scanned {len(events)} events, found {len(findings)} root-activity findings\n")

for f in findings:
    print(json.dumps(f, indent=2))
    print("-" * 60)