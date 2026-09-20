from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET


EVTX_PATH = (
    "data/raw/evtx-attack-samples/"
    "Defense Evasion/DE_1102_security_log_cleared.evtx"
)

EXPECTED_EVENT_ID = "1102"

NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def test_ctshield_001_matches_security_log_clear():
    matches = []

    with Evtx(EVTX_PATH) as log:
        for record in log.records():
            root = ET.fromstring(record.xml())

            event_id = root.findtext(
                "e:System/e:EventID",
                namespaces=NS
            )

            channel = root.findtext(
                "e:System/e:Channel",
                namespaces=NS
            )

            if event_id == EXPECTED_EVENT_ID and channel == "Security":
                matches.append(record)

    assert matches, (
        "CTSHIELD-001 did not match any Security Event ID 1102 "
        "in the selected EVTX sample."
    )

    print(f"CTSHIELD-001 matched {len(matches)} event(s).")


if __name__ == "__main__":
    test_ctshield_001_matches_security_log_clear()
