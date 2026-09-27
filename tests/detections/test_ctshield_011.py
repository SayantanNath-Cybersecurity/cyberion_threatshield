from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET


EVTX_PATH = (
    "data/raw/evtx-attack-samples/"
    "Command and Control/DE_RDP_Tunnel_5156.evtx"
)

EXPECTED_EVENT_ID = "5156"
APPLICATION_INDICATOR = r"\plink.exe"

NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def test_ctshield_011_matches_plink_network_connections():
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

            application = data.get("Application") or ""

            if application.lower().endswith(
                APPLICATION_INDICATOR.lower()
            ):
                matches.append(data)

    assert matches, (
        "CTSHIELD-011 did not match the expected "
        "plink.exe network connection events."
    )

    print(
        f"CTSHIELD-011 matched "
        f"{len(matches)} plink.exe network connection event(s)."
    )
