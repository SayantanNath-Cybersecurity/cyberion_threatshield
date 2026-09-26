from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET


EVTX_PATH = (
    "data/raw/evtx-attack-samples/"
    "Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx"
)

EXPECTED_EVENT_ID = "4625"
EXPECTED_LOGON_TYPE = "2"

NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def test_ctshield_006_matches_failed_interactive_logon():
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

            if data.get("LogonType") == EXPECTED_LOGON_TYPE:
                matches.append(data)

    assert matches, (
        "CTSHIELD-006 did not match the expected "
        "failed interactive logon event."
    )

    print(
        f"CTSHIELD-006 matched "
        f"{len(matches)} failed interactive logon event(s)."
    )
