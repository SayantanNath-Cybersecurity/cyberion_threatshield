from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET


EVTX_PATH = (
    "data/raw/evtx-attack-samples/"
    "Credential Access/"
    "phish_windows_credentials_powershell_scriptblockLog_4104.evtx"
)

EXPECTED_EVENT_ID = "4104"

REQUIRED_INDICATORS = (
    "PromptForCredential",
    "GetNetworkCredential().password",
)

NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def test_ctshield_008_matches_powershell_credential_prompt():
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

            script_block = data.get("ScriptBlockText") or ""

            if all(
                indicator in script_block
                for indicator in REQUIRED_INDICATORS
            ):
                matches.append(data)

    assert matches, (
        "CTSHIELD-008 did not match the expected "
        "PowerShell credential-prompting event."
    )

    print(
        f"CTSHIELD-008 matched "
        f"{len(matches)} PowerShell credential-prompting "
        f"event(s)."
    )
