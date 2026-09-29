from collections import defaultdict
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET

from Evtx.Evtx import Evtx


EVTX_FILE = Path(
    "data/raw/evtx-attack-samples/"
    "Credential Access/kerberos_pwd_spray_4771.evtx"
)

NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def parse_events():
    events = []

    with Evtx(str(EVTX_FILE)) as log:
        for record in log.records():
            root = ET.fromstring(record.xml())

            event_id = root.findtext(
                "e:System/e:EventID",
                namespaces=NS,
            )

            if event_id != "4771":
                continue

            created = root.find(
                "e:System/e:TimeCreated",
                namespaces=NS,
            )

            timestamp = (
                created.attrib.get("SystemTime", "")
                if created is not None
                else ""
            )

            computer = root.findtext(
                "e:System/e:Computer",
                namespaces=NS,
            )

            data = {
                item.attrib.get("Name"): item.text or ""
                for item in root.findall(
                    "e:EventData/e:Data",
                    namespaces=NS,
                )
            }

            data["_EventID"] = event_id
            data["_Timestamp"] = timestamp
            data["_ComputerName"] = computer or ""

            events.append(data)

    return events


def test_ctshield_018_multiple_accounts_same_source():
    events = parse_events()

    grouped = defaultdict(list)

    for event in events:
        ip_address = event.get("IpAddress", "")

        if ip_address:
            grouped[ip_address].append(event)

    matching_groups = []

    for ip_address, group in grouped.items():
        accounts = {
            event.get("TargetUserName")
            for event in group
            if event.get("TargetUserName")
        }

        timestamps = [
            datetime.fromisoformat(event["_Timestamp"])
            for event in group
            if event.get("_Timestamp")
        ]

        if len(accounts) < 2 or not timestamps:
            continue

        time_span = max(timestamps) - min(timestamps)

        if time_span.total_seconds() <= 300:
            matching_groups.append(
                (ip_address, accounts, time_span)
            )

    assert len(matching_groups) == 1

    ip_address, accounts, time_span = matching_groups[0]

    assert ip_address == "172.16.66.1"

    assert {
        "Administrator",
        "backdoor",
    } <= accounts

    assert time_span.total_seconds() <= 300

    print(
        "CTSHIELD-018 matched one source address against "
        f"{len(accounts)} target accounts within {time_span}."
    )
