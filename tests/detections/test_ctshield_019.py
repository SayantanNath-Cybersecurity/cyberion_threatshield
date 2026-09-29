from datetime import datetime, timedelta
from pathlib import Path
import xml.etree.ElementTree as ET

from Evtx.Evtx import Evtx


EVTX_FILE = Path(
    "data/raw/evtx-attack-samples/"
    "Lateral Movement/LM_WMI_4624_4688_TargetHost.evtx"
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

            if event_id not in {"4624", "4688"}:
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


def test_ctshield_019_network_logon_followed_by_wmi_provider_host():
    events = parse_events()

    network_logons = [
        event
        for event in events
        if event.get("_EventID") == "4624"
        and event.get("LogonType") == "3"
    ]

    wmi_processes = [
        event
        for event in events
        if event.get("_EventID") == "4688"
        and event.get("NewProcessName", "")
        .lower()
        .endswith("\\wmiprvse.exe")
    ]

    matches = []

    for logon in network_logons:
        logon_time = datetime.fromisoformat(
            logon["_Timestamp"]
        )

        for process in wmi_processes:
            if process.get("_ComputerName") != logon.get(
                "_ComputerName"
            ):
                continue

            process_time = datetime.fromisoformat(
                process["_Timestamp"]
            )

            if process_time < logon_time:
                continue

            if process_time - logon_time > timedelta(minutes=5):
                continue

            matches.append((logon, process))

    assert len(matches) >= 1

    logon, process = matches[0]

    assert logon.get("LogonType") == "3"

    assert process.get(
        "NewProcessName",
        ""
    ).lower().endswith("\\wmiprvse.exe")

    assert (
        process.get("_ComputerName")
        == logon.get("_ComputerName")
    )

    elapsed = (
        datetime.fromisoformat(process["_Timestamp"])
        - datetime.fromisoformat(logon["_Timestamp"])
    )

    assert elapsed.total_seconds() <= 300

    print(
        "CTSHIELD-019 matched a network logon followed by "
        f"WmiPrvSE.exe on the same host after {elapsed}."
    )
