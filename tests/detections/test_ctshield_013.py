from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET


EVTX_PATH = (
    "data/raw/evtx-attack-samples/"
    "Lateral Movement/LM_Remote_Service02_7045.evtx"
)

EXPECTED_EVENT_ID = "7045"

SUSPICIOUS_IMAGE_PATHS = {
    "cmd.exe",
    "calc.exe",
}

NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def test_ctshield_013_matches_suspicious_service_creation():
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

            image_path = (data.get("ImagePath") or "").strip()

            if image_path.lower() in {
                value.lower()
                for value in SUSPICIOUS_IMAGE_PATHS
            }:
                matches.append(data)

    assert matches, (
        "CTSHIELD-013 did not match the expected "
        "suspicious service creation events."
    )

    print(
        f"CTSHIELD-013 matched "
        f"{len(matches)} suspicious service creation event(s)."
    )
