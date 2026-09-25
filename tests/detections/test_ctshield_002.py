from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET


EVTX_PATH = (
    "data/raw/evtx-attack-samples/"
    "Credential Access/kerberos_pwd_spray_4771.evtx"
)

EXPECTED_EVENT_ID = "4771"
EXPECTED_STATUS = "0x00000018"

NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def test_ctshield_002_matches_kerberos_pre_authentication_failures():
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

            status = None

            for data in root.findall(
                "e:EventData/e:Data",
                namespaces=NS
            ):
                if data.attrib.get("Name") == "Status":
                    status = data.text
                    break

            if (
                event_id == EXPECTED_EVENT_ID
                and channel == "Security"
                and status == EXPECTED_STATUS
            ):
                matches.append(record)

    assert matches, (
        "CTSHIELD-002 did not match any Security Event ID 4771 "
        "with Status 0x00000018."
    )

    print(
        "CTSHIELD-002 matched "
        f"{len(matches)} Kerberos pre-authentication failure event(s)."
    )


if __name__ == "__main__":
    test_ctshield_002_matches_kerberos_pre_authentication_failures()
