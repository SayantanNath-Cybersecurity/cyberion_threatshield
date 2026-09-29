from datetime import datetime, timedelta
from pathlib import Path
import xml.etree.ElementTree as ET

from Evtx.Evtx import Evtx


EVTX_FILE = Path(
    "data/raw/evtx-attack-samples/"
    "Privilege Escalation/"
    "Runas_4624_4648_Webshell_CreateProcessAsUserA.evtx"
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

            if event_id not in {"4624", "4648"}:
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

            data = {
                item.attrib.get("Name"): item.text or ""
                for item in root.findall(
                    "e:EventData/e:Data",
                    namespaces=NS,
                )
            }

            data["_EventID"] = event_id
            data["_Timestamp"] = timestamp

            events.append(data)

    return events


def test_ctshield_020_iis_explicit_credentials_followed_by_successful_logon():
    events = parse_events()

    explicit_credentials = [
        event
        for event in events
        if event.get("_EventID") == "4648"
        and event.get("ProcessName", "")
        .lower()
        .endswith("\\w3wp.exe")
    ]

    successful_logons = [
        event
        for event in events
        if event.get("_EventID") == "4624"
        and event.get("LogonType") == "3"
        and event.get("ProcessName", "")
        .lower()
        .endswith("\\w3wp.exe")
    ]

    matches = []

    for credential_event in explicit_credentials:
        credential_time = datetime.fromisoformat(
            credential_event["_Timestamp"]
        )

        for logon_event in successful_logons:
            logon_time = datetime.fromisoformat(
                logon_event["_Timestamp"]
            )

            if logon_time < credential_time:
                continue

            if logon_time - credential_time > timedelta(minutes=1):
                continue

            if (
                credential_event.get("SubjectUserName")
                != logon_event.get("SubjectUserName")
            ):
                continue

            if (
                credential_event.get("TargetUserName")
                != logon_event.get("TargetUserName")
            ):
                continue

            matches.append(
                (credential_event, logon_event)
            )

    assert len(matches) == 1

    credential_event, logon_event = matches[0]

    assert credential_event.get("SubjectUserName") == "svc01"
    assert credential_event.get("TargetUserName") == "IEUser"

    assert logon_event.get("SubjectUserName") == "svc01"
    assert logon_event.get("TargetUserName") == "IEUser"

    elapsed = (
        datetime.fromisoformat(logon_event["_Timestamp"])
        - datetime.fromisoformat(credential_event["_Timestamp"])
    )

    assert elapsed.total_seconds() <= 60

    print(
        "CTSHIELD-020 matched IIS explicit credential use "
        f"followed by successful logon after {elapsed}."
    )
