from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET


EVTX_PATH = (
    "data/raw/evtx-attack-samples/"
    "Execution/temp_scheduled_task_4698_4699.evtx"
)

EXPECTED_EVENT_ID = "4698"

HIDDEN_INDICATOR = "<Hidden>true</Hidden>"
LOCALSYSTEM_INDICATOR = "<UserId>S-1-5-18</UserId>"

NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def test_ctshield_012_matches_hidden_scheduled_task_creation():
    matches = []

    with Evtx(EVTX_PATH) as log:
        for record in log.records():
            root = ET.fromstring(record.xml())

            event_id = root.findtext(
                "e:System/e:EventID",
                namespaces=NS
            )

            if event_id != EXPECTED_EVENT_ID:
                continue

            data = {
                item.attrib.get("Name"): item.text
                for item in root.findall(
                    "e:EventData/e:Data",
                    namespaces=NS
                )
            }

            task_content = data.get("TaskContent") or ""

            if (
                HIDDEN_INDICATOR in task_content
                and LOCALSYSTEM_INDICATOR in task_content
            ):
                matches.append(data)

    assert matches, (
        "CTSHIELD-012 did not match the expected "
        "hidden LocalSystem scheduled task creation event."
    )

    print(
        f"CTSHIELD-012 matched "
        f"{len(matches)} hidden LocalSystem "
        f"scheduled task creation event(s)."
    )
