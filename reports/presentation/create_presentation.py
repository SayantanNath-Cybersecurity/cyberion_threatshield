from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE
from pptx.dml.color import RGBColor


OUTPUT = "reports/Cyberion_ThreatShield_Final_Presentation.pptx"

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)

# Theme
BG = RGBColor(10, 16, 28)
PANEL = RGBColor(18, 27, 43)
TEXT = RGBColor(235, 241, 248)
MUTED = RGBColor(160, 175, 195)
ACCENT = RGBColor(62, 211, 170)
BLUE = RGBColor(82, 156, 255)
ORANGE = RGBColor(255, 177, 79)
RED = RGBColor(245, 103, 103)
BORDER = RGBColor(38, 52, 73)


def add_background(slide):
    slide.background.fill.solid()
    slide.background.fill.fore_color.rgb = BG

    line = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE,
        0,
        0,
        prs.slide_width,
        Inches(0.08),
    )
    line.fill.solid()
    line.fill.fore_color.rgb = ACCENT
    line.line.fill.background()


def add_title(slide, title, subtitle=None):
    add_background(slide)

    box = slide.shapes.add_textbox(
        Inches(0.65),
        Inches(0.42),
        Inches(12),
        Inches(0.7),
    )
    p = box.text_frame.paragraphs[0]
    r = p.add_run()
    r.text = title
    r.font.size = Pt(29)
    r.font.bold = True
    r.font.color.rgb = TEXT

    if subtitle:
        box = slide.shapes.add_textbox(
            Inches(0.68),
            Inches(1.08),
            Inches(11.8),
            Inches(0.42),
        )
        p = box.text_frame.paragraphs[0]
        r = p.add_run()
        r.text = subtitle
        r.font.size = Pt(13)
        r.font.color.rgb = MUTED


def add_footer(slide, number):
    box = slide.shapes.add_textbox(
        Inches(0.68),
        Inches(7.08),
        Inches(12),
        Inches(0.22),
    )
    p = box.text_frame.paragraphs[0]
    p.alignment = PP_ALIGN.RIGHT
    r = p.add_run()
    r.text = f"Cyberion ThreatShield  •  {number}"
    r.font.size = Pt(9)
    r.font.color.rgb = MUTED


def add_bullets(slide, items, x=0.85, y=1.65, w=11.7, h=4.9, font=19):
    box = slide.shapes.add_textbox(
        Inches(x),
        Inches(y),
        Inches(w),
        Inches(h),
    )

    tf = box.text_frame
    tf.word_wrap = True
    tf.clear()

    for index, item in enumerate(items):
        p = tf.paragraphs[0] if index == 0 else tf.add_paragraph()
        p.text = item
        p.level = 0
        p.font.size = Pt(font)
        p.font.color.rgb = TEXT
        p.space_after = Pt(12)
        p.bullet = True

    return box


def add_stat(slide, x, y, w, h, value, label, accent=ACCENT):
    shape = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE,
        Inches(x),
        Inches(y),
        Inches(w),
        Inches(h),
    )
    shape.fill.solid()
    shape.fill.fore_color.rgb = PANEL
    shape.line.color.rgb = BORDER

    value_box = slide.shapes.add_textbox(
        Inches(x + 0.15),
        Inches(y + 0.18),
        Inches(w - 0.3),
        Inches(0.62),
    )
    p = value_box.text_frame.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    r = p.add_run()
    r.text = value
    r.font.size = Pt(30)
    r.font.bold = True
    r.font.color.rgb = accent

    label_box = slide.shapes.add_textbox(
        Inches(x + 0.15),
        Inches(y + 0.92),
        Inches(w - 0.3),
        Inches(h - 1.0),
    )
    p = label_box.text_frame.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    r = p.add_run()
    r.text = label
    r.font.size = Pt(12)
    r.font.color.rgb = MUTED


def add_card(slide, x, y, w, h, heading, body, accent=ACCENT):
    shape = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE,
        Inches(x),
        Inches(y),
        Inches(w),
        Inches(h),
    )
    shape.fill.solid()
    shape.fill.fore_color.rgb = PANEL
    shape.line.color.rgb = BORDER

    bar = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE,
        Inches(x),
        Inches(y),
        Inches(0.07),
        Inches(h),
    )
    bar.fill.solid()
    bar.fill.fore_color.rgb = accent
    bar.line.fill.background()

    heading_box = slide.shapes.add_textbox(
        Inches(x + 0.25),
        Inches(y + 0.18),
        Inches(w - 0.4),
        Inches(0.4),
    )
    p = heading_box.text_frame.paragraphs[0]
    r = p.add_run()
    r.text = heading
    r.font.size = Pt(16)
    r.font.bold = True
    r.font.color.rgb = TEXT

    body_box = slide.shapes.add_textbox(
        Inches(x + 0.25),
        Inches(y + 0.72),
        Inches(w - 0.45),
        Inches(h - 0.9),
    )
    tf = body_box.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    r = p.add_run()
    r.text = body
    r.font.size = Pt(12.5)
    r.font.color.rgb = MUTED


# ---------------------------------------------------------
# Slide 1
# ---------------------------------------------------------

slide = prs.slides.add_slide(prs.slide_layouts[6])
add_background(slide)

box = slide.shapes.add_textbox(
    Inches(0.8),
    Inches(1.35),
    Inches(11.8),
    Inches(1.25),
)
p = box.text_frame.paragraphs[0]
r = p.add_run()
r.text = "CYBERION THREATSHIELD"
r.font.size = Pt(38)
r.font.bold = True
r.font.color.rgb = TEXT

box = slide.shapes.add_textbox(
    Inches(0.85),
    Inches(2.65),
    Inches(10.8),
    Inches(0.9),
)
p = box.text_frame.paragraphs[0]
r = p.add_run()
r.text = "Detection Engineering & Threat Hunting"
r.font.size = Pt(25)
r.font.color.rgb = ACCENT

box = slide.shapes.add_textbox(
    Inches(0.87),
    Inches(3.55),
    Inches(9.8),
    Inches(1.0),
)
p = box.text_frame.paragraphs[0]
r = p.add_run()
r.text = "Evidence-driven Windows telemetry analysis using Sigma and MITRE ATT&CK"
r.font.size = Pt(17)
r.font.color.rgb = MUTED

add_stat(slide, 9.8, 5.0, 1.35, 1.35, "19", "Sigma rules")
add_stat(slide, 11.25, 5.0, 1.35, 1.35, "22", "Tests passed", BLUE)
add_footer(slide, 1)


# ---------------------------------------------------------
# Slide 2
# ---------------------------------------------------------

slide = prs.slides.add_slide(prs.slide_layouts[6])
add_title(
    slide,
    "Project Objective",
    "A detection-content engineering engagement, not a custom application",
)

add_bullets(
    slide,
    [
        "Analyze public Windows Event Log telemetry and identify attacker behaviors.",
        "Author Sigma detections mapped to specific MITRE ATT&CK techniques.",
        "Validate detections against actual sample telemetry and document false-positive considerations.",
        "Use threat hunting and incident investigation to turn detections into actionable security evidence.",
        "Produce reusable coverage, investigation, tuning, and response documentation.",
    ],
)

add_footer(slide, 2)


# ---------------------------------------------------------
# Slide 3
# ---------------------------------------------------------

slide = prs.slides.add_slide(prs.slide_layouts[6])
add_title(
    slide,
    "Telemetry & Methodology",
    "Evidence was examined before detection logic was written",
)

add_card(
    slide,
    0.75,
    1.55,
    3.8,
    2.05,
    "Dataset",
    "EVTX-ATT&CK-SAMPLES public Windows Event Log collection.\n\n278 EVTX files were available in the selected repository snapshot.",
    BLUE,
)

add_card(
    slide,
    4.78,
    1.55,
    3.8,
    2.05,
    "Analysis",
    "Python-based EVTX parsing and targeted event-field inspection to understand the actual telemetry.",
    ACCENT,
)

add_card(
    slide,
    8.8,
    1.55,
    3.8,
    2.05,
    "Detection",
    "Sigma rule authoring with ATT&CK mapping, severity rationale, false-positive discussion, and syntax validation.",
    ORANGE,
)

add_bullets(
    slide,
    [
        "Workflow: observe telemetry → identify behavior → draft rule → test against evidence → tune → document.",
        "The project emphasizes reproducibility and evidence-backed coverage claims.",
    ],
    y=4.1,
    h=2.0,
    font=17,
)

add_footer(slide, 3)


# ---------------------------------------------------------
# Slide 4
# ---------------------------------------------------------

slide = prs.slides.add_slide(prs.slide_layouts[6])
add_title(
    slide,
    "Detection Engineering Output",
    "The final library targets concrete attacker behaviors observed in telemetry",
)

add_stat(slide, 0.75, 1.55, 2.55, 1.55, "19", "Final Sigma rules")
add_stat(slide, 3.55, 1.55, 2.55, 1.55, "3", "Correlation-style rules", ORANGE)
add_stat(slide, 6.35, 1.55, 2.55, 1.55, "20", "Techniques assessed", BLUE)
add_stat(slide, 9.15, 1.55, 2.55, 1.55, "4+", "ATT&CK tactics represented", ACCENT)

add_bullets(
    slide,
    [
        "Examples include WMI execution, Kerberos authentication failures, DCSync, PowerShell credential activity, LSASS access, scheduled tasks, service creation, tunneling, and credential use.",
        "Each submitted rule includes an ATT&CK technique ID and false-positive considerations.",
    ],
    y=3.65,
    h=2.5,
    font=16,
)

add_footer(slide, 4)


# ---------------------------------------------------------
# Slide 5
# ---------------------------------------------------------

slide = prs.slides.add_slide(prs.slide_layouts[6])
add_title(
    slide,
    "MITRE ATT&CK Coverage",
    "Coverage is documented technique-by-technique rather than only at tactic level",
)

add_card(
    slide,
    0.8,
    1.55,
    3.75,
    3.9,
    "Execution & Lateral Movement",
    "T1047 WMI\nT1021.006 Windows Remote Management\nT1059.001 PowerShell\n\nDetections connect specific Windows event fields to attacker behavior.",
    ACCENT,
)

add_card(
    slide,
    4.78,
    1.55,
    3.75,
    3.9,
    "Credential Access",
    "T1003.001 LSASS\nT1003.006 DCSync\nT1110.001 / T1110.003 authentication abuse\nT1555.003 browser credential stores",
    BLUE,
)

add_card(
    slide,
    8.76,
    1.55,
    3.75,
    3.9,
    "Persistence / Defense Evasion",
    "T1053.005 scheduled tasks\nT1543.003 services\nT1553.006 test signing\nT1136.002 computer account creation",
    ORANGE,
)

add_footer(slide, 5)


# ---------------------------------------------------------
# Slide 6
# ---------------------------------------------------------

slide = prs.slides.add_slide(prs.slide_layouts[6])
add_title(
    slide,
    "Correlation Detection",
    "Three rules move beyond isolated log lines",
)

add_card(
    slide,
    0.75,
    1.45,
    3.85,
    4.25,
    "CTSHIELD-018",
    "Kerberos pre-authentication failures against multiple accounts.\n\nGroups by source IP over a 5-minute window and requires multiple target accounts.\n\nTechnique: T1110.003",
    BLUE,
)

add_card(
    slide,
    4.74,
    1.45,
    3.85,
    4.25,
    "CTSHIELD-019",
    "Network logon followed by WMI Provider Host execution on the same host.\n\nCorrelates Event IDs 4624 and 4688 within 5 minutes.\n\nTechnique: T1047",
    ACCENT,
)

add_card(
    slide,
    8.73,
    1.45,
    3.85,
    4.25,
    "CTSHIELD-020",
    "IIS worker-process explicit credential use followed by successful network logon.\n\nCorrelates Event IDs 4648 and 4624.\n\nTechnique: T1078",
    ORANGE,
)

add_footer(slide, 6)


# ---------------------------------------------------------
# Slide 7
# ---------------------------------------------------------

slide = prs.slides.add_slide(prs.slide_layouts[6])
add_title(
    slide,
    "Threat Hunting",
    "Hypothesis-driven analysis of raw telemetry",
)

add_card(
    slide,
    0.85,
    1.55,
    5.75,
    4.35,
    "HUNT-001 • WMI Remote Execution",
    "Hypothesis: WMI activity may indicate remote execution.\n\nApproach: inspect authentication and process-creation evidence, then reconstruct event order.\n\nOutcome: evidence supported the WMI execution pattern and was carried into incident investigation.",
    ACCENT,
)

add_card(
    slide,
    6.75,
    1.55,
    5.75,
    4.35,
    "HUNT-002 • Kerberos Authentication Failures",
    "Hypothesis: repeated Kerberos failures may reveal authentication abuse.\n\nApproach: inspect Event ID 4771, source addresses, target accounts, and timestamps.\n\nOutcome: multiple target accounts from the same source supported a password-spraying pattern.",
    BLUE,
)

add_footer(slide, 7)


# ---------------------------------------------------------
# Slide 8
# ---------------------------------------------------------

slide = prs.slides.add_slide(prs.slide_layouts[6])
add_title(
    slide,
    "Incident Investigation",
    "Confirmed findings were converted into structured case reports",
)

add_card(
    slide,
    0.85,
    1.55,
    5.75,
    4.45,
    "CASE-001 • WMI Remote Execution",
    "Evidence reconstructed from Windows Security and process-creation telemetry.\n\nMapped to WMI-based execution activity.\n\nThe case documents timeline, technique mapping, impact considerations, closure rationale, and response guidance.",
    ACCENT,
)

add_card(
    slide,
    6.75,
    1.55,
    5.75,
    4.45,
    "CASE-002 • Web Server Credential Use",
    "Event 4648 and Event 4624 evidence showed IIS worker-process credential use followed by successful network logon.\n\nThe case treats T1078 as associated evidence and documents the limitations of Security-event-only evidence.",
    ORANGE,
)

add_footer(slide, 8)


# ---------------------------------------------------------
# Slide 9
# ---------------------------------------------------------

slide = prs.slides.add_slide(prs.slide_layouts[6])
add_title(
    slide,
    "Rule Tuning & False Positives",
    "Detection quality was treated as an engineering problem",
)

add_card(
    slide,
    0.85,
    1.55,
    3.75,
    4.15,
    "CTSHIELD-006",
    "Failed interactive logon\n\nTuning pass documented an observed false-positive scenario, the resulting logic refinement, and the trade-off accepted.",
    BLUE,
)

add_card(
    slide,
    4.78,
    1.55,
    3.75,
    4.15,
    "CTSHIELD-016",
    "PowerShell remoting child process\n\nThe tuning evidence records the tested behavior and precision considerations around legitimate administrative activity.",
    ACCENT,
)

add_card(
    slide,
    8.71,
    1.55,
    3.75,
    4.15,
    "CTSHIELD-017",
    "Retired experimental detection\n\nIts test and tuning evidence remain as engineering history, while the rule itself was removed from the final library.",
    ORANGE,
)

add_footer(slide, 9)


# ---------------------------------------------------------
# Slide 10
# ---------------------------------------------------------

slide = prs.slides.add_slide(prs.slide_layouts[6])
add_title(
    slide,
    "IOC Research & Response Readiness",
    "Indicators were connected to operational security workflows",
)

add_card(
    slide,
    0.85,
    1.55,
    5.75,
    4.3,
    "IOC Research",
    "Telemetry-derived indicators were documented with context and operationalization guidance.\n\nThe research connects indicators to practical detection or watchlist use rather than treating IOCs as isolated artifacts.",
    BLUE,
)

add_card(
    slide,
    6.75,
    1.55,
    5.75,
    4.3,
    "Response Playbooks",
    "PB-001 WMI remote execution response\nPB-002 Kerberos authentication failure response\nPB-003 Web-server credential-use response\n\nEach playbook addresses trigger, investigation, containment, recovery, and stakeholder communication.",
    ACCENT,
)

add_footer(slide, 10)


# ---------------------------------------------------------
# Slide 11
# ---------------------------------------------------------

slide = prs.slides.add_slide(prs.slide_layouts[6])
add_title(
    slide,
    "Validation & Reproducibility",
    "The final state was checked before completion",
)

add_stat(slide, 0.85, 1.55, 2.55, 1.55, "22", "Automated tests passed", ACCENT)
add_stat(slide, 3.65, 1.55, 2.55, 1.55, "19", "Detection reports", BLUE)
add_stat(slide, 6.45, 1.55, 2.55, 1.55, "3", "Tuning reports", ORANGE)
add_stat(slide, 9.25, 1.55, 2.55, 1.55, "0", "Sigma validation errors", ACCENT)

add_bullets(
    slide,
    [
        "The test suite validates detection logic against actual EVTX-derived telemetry.",
        "Sigma syntax and condition validation completed successfully.",
        "Supporting hunts, cases, playbooks, coverage documentation, methodology, and executive reporting are present in the repository.",
    ],
    y=3.7,
    h=2.2,
    font=16,
)

add_footer(slide, 11)


# ---------------------------------------------------------
# Slide 12
# ---------------------------------------------------------

slide = prs.slides.add_slide(prs.slide_layouts[6])
add_title(
    slide,
    "Key Findings",
    "What the project demonstrates",
)

add_bullets(
    slide,
    [
        "Windows security telemetry can support meaningful detection content when field-level behavior is understood first.",
        "Correlation adds context that single-event detections cannot provide on their own.",
        "False-positive analysis and tuning are central to usable SOC detections.",
        "Threat hunting provides a bridge from detection logic to investigative evidence.",
        "Case reports and playbooks turn technical findings into repeatable analyst workflows.",
        "The resulting repository is reusable detection-engineering content rather than a hosted security application.",
    ],
    y=1.55,
    h=4.9,
    font=18,
)

add_footer(slide, 12)


# ---------------------------------------------------------
# Slide 13
# ---------------------------------------------------------

slide = prs.slides.add_slide(prs.slide_layouts[6])
add_title(
    slide,
    "Project Deliverables",
    "Repository package aligned to the engagement scope",
)

deliverables = [
    ("Detection library", "19 Sigma rules"),
    ("ATT&CK assessment", "Coverage matrix + 20 techniques assessed"),
    ("Threat hunting", "2 structured hunt reports"),
    ("Incident investigation", "2 case reports"),
    ("Response", "3 incident response playbooks"),
    ("Quality", "3 tuning passes + FP analysis"),
    ("Research", "IOC research + operationalization"),
    ("Reporting", "Methodology + executive summary + presentation"),
]

colors = [ACCENT, BLUE, ORANGE, ACCENT]

for index, (heading, body) in enumerate(deliverables):
    column = index % 2
    row = index // 2

    add_card(
        slide,
        0.8 + column * 6.0,
        1.45 + row * 1.35,
        5.65,
        1.05,
        heading,
        body,
        colors[index % len(colors)],
    )

add_footer(slide, 13)


# ---------------------------------------------------------
# Slide 14
# ---------------------------------------------------------

slide = prs.slides.add_slide(prs.slide_layouts[6])
add_background(slide)

box = slide.shapes.add_textbox(
    Inches(0.8),
    Inches(1.7),
    Inches(11.8),
    Inches(0.9),
)
p = box.text_frame.paragraphs[0]
p.alignment = PP_ALIGN.CENTER
r = p.add_run()
r.text = "CYBERION THREATSHIELD"
r.font.size = Pt(34)
r.font.bold = True
r.font.color.rgb = TEXT

box = slide.shapes.add_textbox(
    Inches(1.3),
    Inches(2.7),
    Inches(10.8),
    Inches(1.1),
)
p = box.text_frame.paragraphs[0]
p.alignment = PP_ALIGN.CENTER
r = p.add_run()
r.text = "From raw Windows telemetry to tested detections, hunts, investigations, and response."
r.font.size = Pt(20)
r.font.color.rgb = ACCENT

box = slide.shapes.add_textbox(
    Inches(2.0),
    Inches(4.2),
    Inches(9.3),
    Inches(0.8),
)
p = box.text_frame.paragraphs[0]
p.alignment = PP_ALIGN.CENTER
r = p.add_run()
r.text = "Detection Engineering • Threat Hunting • Incident Response"
r.font.size = Pt(15)
r.font.color.rgb = MUTED

add_footer(slide, 14)


# Save
prs.save(OUTPUT)

print(f"Created: {OUTPUT}")
print(f"Slides: {len(prs.slides)}")
