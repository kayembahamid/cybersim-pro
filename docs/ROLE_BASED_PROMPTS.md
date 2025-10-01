# Role-Based Prompt Templates

CyberSim Pro works best when every participant in an exercise has clear intent and guardrails. The following bundles provide ready-made prompts for different audiences. Copy them into your MCP client or modify to match your organisation’s vocabulary.

---

## Red Team Facilitator

**Scenario Kickoff**
```
You are the red-team facilitator operating in a closed lab. Objective: simulate an [ATT&CK technique] campaign against the <TARGET GROUP> environment.
Constraints:
- All activity is synthetic.
- Never provide live payloads or credentials.
- Highlight the MITRE tactics and expected detective controls.
Confirm you understand, then request a scenario seed.
```

**Attack Walkthrough**
```
Invoke `simulate_attack` using:
{
  "attack_type": "<campaign type>",
  "target": "<system or segment>",
  "intensity": "high",
  "training": true
}
Narrate each phase, the attacker’s intent, and the breadcrumbs left for defenders. Pause after every phase for blue-team discussion.
```

**Containment Handoff**
```
We are switching to defender focus. Summarise the top three containment levers and the fastest rollback path. Keep remediation advice practical and tool-agnostic.
```

---

## Blue Team / SOC Analyst

**Detection Deep Dive**
```
Using the latest simulation output, identify the log sources, analytics, and thresholds that should trigger alerts. Map each to MITRE technique IDs and propose accompanying Sigma or KQL searches.
```

**Triage Checklist**
```
Produce a triage worksheet with the following columns:
- Signal / Alert name
- Quick validation steps
- Escalation criteria
- Containment playbook link
Focus on high-impact findings first.
```

**Hunt Mission**
```
Assume the attacker is still active. Provide three proactive hunting hypotheses with data sources, query snippets, and success/failure criteria. Keep results in JSON for easy export.
```

---

## Purple Team Facilitator

**Joint Planning Prompt**
```
We are running a purple-team workshop. List the attack phases we will rehearse, the red-team objective for each, and the expected blue-team response. Include success metrics (detection latency, containment time, communication clarity).
```

**After-Action Matrix**
```
Create a table with rows [People, Process, Technology] and columns [What worked, Gaps, Next steps]. Populate it using the latest simulation data and emphasise shared ownership.
```

**Scorecard Template**
```
Output a JSON scorecard with:
- detectionLatencyMinutes
- containmentTimeMinutes
- falsePositiveNotes
- remediationTickets (array)
- executiveSummary
```

---

## Executive / Leadership Briefing

**Risk Snapshot**
```
Summarise the scenario in plain language:
- Business function impacted
- Hypothetical loss estimates (financial/regulatory/reputation)
- Current resilience rating (green/amber/red)
- Top three mitigation commitments with owners
Keep to 200 words.
```

**Board Follow-Up**
```
Draft an email from the CISO to the executive team describing:
1. What was tested
2. What we learned
3. Immediate actions
4. Investment decisions to consider
Tone: factual, calm, focused on resilience.
```

**Regulator Readiness**
```
Assume a regulator requests evidence of tabletop exercises. Produce a paragraph describing the scenario, the controls tested, and how the audit log (`logs/audit.log`) proves due diligence.
```

---

## Field Notes
- Prefix your prompts with environment context (e.g., “Closed lab”, “Training dataset only”).
- Store customised templates in version control next to the Audit Log to preserve intent.
- Review templates quarterly to align with evolving threat intelligence and compliance obligations.
