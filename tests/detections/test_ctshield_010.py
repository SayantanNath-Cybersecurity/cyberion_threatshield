from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET


EVTX_PATH = (
    "data/raw/evtx-attack-samples/"
    "Credential Access/CA_chrome_firefox_opera_4663.evtx"
)

EXPECTED_EVENT_ID = "4663"
EXPECTED_OBJECT_TYPE = "File"

BROWSER_PATH_INDICATORS = (
    "\\Opera Software\\Opera Stable\\Login Data",
    "\\Mozilla\\Firefox\\Profiles\\",
    "\\Google\\Chrome\\User Data\\",
)

NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def test_ctshield_010_matches_browser_credential_store_access():
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

            object_name = data.get("ObjectName") or ""

            if (
                data.get("ObjectType") == EXPECTED_OBJECT_TYPE
                and any(
                    indicator in object_name
                    for indicator in BROWSER_PATH_INDICATORS
                )
            ):
                matches.append(data)

    assert matches, (
        "CTSHIELD-010 did not match the expected "
        "browser credential-store access events."
    )

    print(
        f"CTSHIELD-010 matched "
        f"{len(matches)} browser credential-store "
        f"access event(s)."
    )
