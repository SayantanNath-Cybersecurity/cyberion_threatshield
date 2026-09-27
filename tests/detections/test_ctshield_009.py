from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET


EVTX_PATH = (
    "data/raw/evtx-attack-samples/"
    "Defense Evasion/"
    "DE_KernelDebug_and_TestSigning_ON_Security_4826.evtx"
)

EXPECTED_EVENT_ID = "4826"
EXPECTED_TEST_SIGNING = "%%1842"

NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def test_ctshield_009_matches_test_signing_enabled():
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

            if data.get("TestSigning") == EXPECTED_TEST_SIGNING:
                matches.append(data)

    assert matches, (
        "CTSHIELD-009 did not match the expected "
        "test-signing-enabled event."
    )

    print(
        f"CTSHIELD-009 matched "
        f"{len(matches)} test-signing-enabled event(s)."
    )
