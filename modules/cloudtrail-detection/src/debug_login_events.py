import boto3
import json
from datetime import datetime, timedelta, timezone

session = boto3.Session(profile_name="cloudtrail-detector", region_name="us-east-1")
logs_client = session.client("logs", region_name="us-east-2")

end_time = datetime.now(timezone.utc)
start_time = end_time - timedelta(hours=20)

print("Querying from", start_time, "to", end_time)

all_events = []
next_token = None

while True:
    kwargs = {
        "logGroupName": "/aws/cloudtrail/cloudgoat-trail",
        "startTime": int(start_time.timestamp() * 1000),
        "endTime": int(end_time.timestamp() * 1000),
    }
    if next_token:
        kwargs["nextToken"] = next_token

    response = logs_client.filter_log_events(**kwargs)
    batch = response.get("events", [])
    all_events.extend(batch)

    next_token = response.get("nextToken")
    if not next_token:
        break

print(f"Total events across all pages: {len(all_events)}")

console_logins = []
for e in all_events:
    detail = json.loads(e["message"])
    if detail.get("eventName") == "ConsoleLogin":
        console_logins.append(detail)

print(f"ConsoleLogin events found: {len(console_logins)}")
for d in sorted(console_logins, key=lambda x: x["eventTime"]):
    ui = d.get("userIdentity", {})
    print(d["eventTime"], "| userName:", ui.get("userName"), "| success:", d.get("responseElements"))