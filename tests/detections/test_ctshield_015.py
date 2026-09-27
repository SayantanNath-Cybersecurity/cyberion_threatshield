from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET


EVTX_PATH = (
    "data/raw/evtx-attack-samples/"
    "Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx"
)

EXPECTED_EVENT_ID = "10"
SOURCE_INDICATOR = r"\mimikatz.exe"
TARGET_INDICATOR = r"\lsass.exe"

NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def test_ctshield_015_matches_mimikatz_lsass_access():
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

            source_image = data.get("SourceImage") or ""
            target_image = data.get("TargetImage") or ""

            if (
                source_image.lower().endswith(
                    SOURCE_INDICATOR.lower()
                )
                and target_image.lower().endswith(
                    TARGET_INDICATOR.lower()
                )
            ):
                matches.append(data)

    assert matches, (
        "CTSHIELD-015 did not match the expected "
        "Mimikatz-to-LSASS process access event."
    )

    print(
        f"CTSHIELD-015 matched "
        f"{len(matches)} Mimikatz-to-LSASS "
        f"process access event(s)."
    )
