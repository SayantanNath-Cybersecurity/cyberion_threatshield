from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET


EVTX_PATH = (
    "data/raw/evtx-attack-samples/"
    "Lateral Movement/LM_WMI_4624_4688_TargetHost.evtx"
)

EXPECTED_EVENT_ID = "4688"
EXPECTED_PROCESS = r"C:\Windows\System32\wbem\WmiPrvSE.exe"

NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def test_ctshield_003_matches_wmi_provider_host():
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

            new_process_name = data.get("NewProcessName")

            if new_process_name == EXPECTED_PROCESS:
                matches.append(data)

    assert matches, (
        "CTSHIELD-003 did not match a Security Event ID 4688 "
        "for WmiPrvSE.exe."
    )

    print(
        "CTSHIELD-003 matched "
        f"{len(matches)} WmiPrvSE.exe process creation event(s)."
    )


if __name__ == "__main__":
    test_ctshield_003_matches_wmi_provider_host()
