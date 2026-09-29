from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
from pathlib import Path


EVTX_FILE = Path(
    "data/raw/evtx-attack-samples/"
    "Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx"
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

            data = {
                item.attrib.get("Name"): item.text or ""
                for item in root.findall(
                    "e:EventData/e:Data",
                    namespaces=NS
                )
            }

            data["_EventID"] = event_id
            events.append(data)

    return events


def is_chrome_interactive_auth(event):
    return (
        event.get("LogonType") == "2"
        and event.get("LogonProcessName", "").strip() == "Chrome"
        and event.get("ProcessName", "")
        .lower()
        .endswith("\\chrome.exe")
    )


def test_ctshield_017_initial_rule_matches_authentication_activity():
    events = parse_events()

    matches = [
        event
        for event in events
        if is_chrome_interactive_auth(event)
    ]

    assert len(matches) == 3

    event_ids = [event.get("_EventID") for event in matches]

    assert event_ids.count("4625") == 1
    assert event_ids.count("4624") == 2

    print(
        "CTSHIELD-017 initial logic matched "
        f"{len(matches)} Chrome interactive authentication event(s)."
    )


def test_ctshield_017_tuned_rule_keeps_only_failed_authentication():
    events = parse_events()

    initial_matches = [
        event
        for event in events
        if is_chrome_interactive_auth(event)
    ]

    tuned_matches = [
        event
        for event in initial_matches
        if event.get("_EventID") == "4625"
    ]

    assert len(initial_matches) == 3
    assert len(tuned_matches) == 1

    assert tuned_matches[0].get("TargetUserName") == "IEUser"

    print(
        "CTSHIELD-017 tuning reduced "
        f"{len(initial_matches)} initial matches to "
        f"{len(tuned_matches)} failed-authentication match."
    )
