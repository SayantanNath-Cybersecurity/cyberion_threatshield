from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET


EVTX_PATH = (
    "data/raw/evtx-attack-samples/"
    "Lateral Movement/LM_WMIC_4648_rpcss.evtx"
)

EXPECTED_EVENT_ID = "4648"
EXPECTED_PROCESS = r"C:\Windows\System32\wbem\WMIC.exe"
EXPECTED_TARGET_USER = "administrator"

NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def test_ctshield_004_matches_wmic_explicit_credential_use():
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

            process_name = data.get("ProcessName")
            target_user = data.get("TargetUserName")

            if (
                process_name == EXPECTED_PROCESS
                and target_user == EXPECTED_TARGET_USER
            ):
                matches.append(data)

    assert matches, (
        "CTSHIELD-004 did not match the expected "
        "WMIC explicit credential use event."
    )

    print(
        f"CTSHIELD-004 matched "
        f"{len(matches)} WMIC explicit credential use event(s)."
    )
