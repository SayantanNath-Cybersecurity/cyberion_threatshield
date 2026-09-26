from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET


EVTX_PATH = (
    "data/raw/evtx-attack-samples/"
    "Lateral Movement/LM_WMI_4624_4688_TargetHost.evtx"
)

EXPECTED_EVENT_ID = "4624"
EXPECTED_LOGON_TYPE = "3"
EXPECTED_TARGET_USER = "Administrator"

NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def test_ctshield_005_matches_network_logon_to_administrator():
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

            if (
                data.get("LogonType") == EXPECTED_LOGON_TYPE
                and data.get("TargetUserName") == EXPECTED_TARGET_USER
            ):
                matches.append(data)

    assert matches, (
        "CTSHIELD-005 did not match the expected "
        "Administrator network logon event."
    )

    print(
        f"CTSHIELD-005 matched "
        f"{len(matches)} Administrator network logon event(s)."
    )
