from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
from pathlib import Path


EVTX_FILE = Path(
    "data/raw/evtx-attack-samples/"
    "Lateral Movement/LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx"
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
                namespaces=NS
            )

            if event_id != "1":
                continue

            data = {
                item.attrib.get("Name"): item.text or ""
                for item in root.findall(
                    "e:EventData/e:Data",
                    namespaces=NS
                )
            }

            events.append(data)

    return events


def test_ctshield_016_matches_powershell_remoting_child_process():
    events = parse_events()

    matches = [
        event
        for event in events
        if event.get("ParentImage", "")
        .lower()
        .endswith("\\wsmprovhost.exe")
    ]

    assert len(matches) == 1

    assert (
        matches[0].get("Image", "")
        .lower()
        .endswith("\\hostname.exe")
    )

    print(
        "CTSHIELD-016 matched "
        f"{len(matches)} PowerShell Remoting child process event(s)."
    )


def test_ctshield_016_tuning_removes_hostname_noise():
    events = parse_events()

    initial_matches = [
        event
        for event in events
        if event.get("ParentImage", "")
        .lower()
        .endswith("\\wsmprovhost.exe")
    ]

    tuned_matches = [
        event
        for event in initial_matches
        if not event.get("Image", "")
        .lower()
        .endswith("\\hostname.exe")
    ]

    assert len(initial_matches) == 1
    assert len(tuned_matches) == 0

    print(
        "CTSHIELD-016 tuning reduced "
        f"{len(initial_matches)} observed match to "
        f"{len(tuned_matches)} after excluding HOSTNAME.EXE."
    )
