from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET


EVTX_PATH = (
    "data/raw/evtx-attack-samples/"
    "Credential Access/CA_DCSync_4662.evtx"
)

EXPECTED_EVENT_ID = "4662"
EXPECTED_OBJECT_SERVER = "DS"
EXPECTED_ACCESS_MASK = "0x00000100"

REPLICATION_GUIDS = {
    "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",
    "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}",
}

NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def test_ctshield_007_matches_dcsync_directory_replication_access():
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

            properties = data.get("Properties") or ""

            has_replication_guid = any(
                guid in properties
                for guid in REPLICATION_GUIDS
            )

            if (
                data.get("ObjectServer") == EXPECTED_OBJECT_SERVER
                and data.get("AccessMask") == EXPECTED_ACCESS_MASK
                and has_replication_guid
            ):
                matches.append(data)

    assert matches, (
        "CTSHIELD-007 did not match the expected "
        "DCSync directory replication access events."
    )

    print(
        f"CTSHIELD-007 matched "
        f"{len(matches)} DCSync directory replication "
        f"access event(s)."
    )
