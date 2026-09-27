from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET


EVTX_PATH = (
    "data/raw/evtx-attack-samples/"
    "Defense Evasion/DE_Fake_ComputerAccount_4720.evtx"
)

EXPECTED_EVENT_ID = "4720"
EXPECTED_TARGET_USER = "$"
EXPECTED_SAM_ACCOUNT = "$"

NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def test_ctshield_014_matches_computer_account_creation():
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
                data.get("TargetUserName") == EXPECTED_TARGET_USER
                and data.get("SamAccountName") == EXPECTED_SAM_ACCOUNT
            ):
                matches.append(data)

    assert matches, (
        "CTSHIELD-014 did not match the expected "
        "computer account creation events."
    )

    print(
        f"CTSHIELD-014 matched "
        f"{len(matches)} computer account creation event(s)."
    )
