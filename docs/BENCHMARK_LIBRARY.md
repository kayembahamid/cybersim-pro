# Benchmark Library

Use these ready-made scenarios to benchmark detection, response, and governance outcomes across industries. Each recipe links tool parameters with recommended scorecard KPIs and export artefacts.

## Finance / Retail Payments
- **Scenario**: `create_scenario` with `{"type":"ransomware","difficulty":"advanced","sector":"finance","adversary_profile":"fin7"}`
- **Follow-up**: `simulate_attack` (high intensity), `analyze_network` (`focus`: `["anomalies","threats"]`)
- **KPIs**: Detection latency < 12h, containment < 8h, no payment data exposure
- **Artefacts**: Deploy Sigma `sigma-network-beaconing`, Splunk `splunk_http_injection`

## Healthcare / PHI Protection
- **Scenario**: `create_scenario` with `{"type":"data_breach","difficulty":"advanced","sector":"healthcare"}`
- **Follow-up**: `forensics_analysis` (artifact `disk`, `analysis_depth`: `comprehensive`), `generate_report` (`report_type`: `incident`)
- **KPIs**: PHI access triaged within 1h, regulatory response within 48h
- **Artefacts**: Sentinel `sentinel_smb_lateral`, DLP containment playbook from report scorecard

## Government / Diplomatic Missions
- **Scenario**: `create_scenario` with `{"type":"apt","difficulty":"expert","sector":"government","adversary_profile":"apt29","focus_cves":["CVE-2023-23397"]}`
- **Follow-up**: `simulate_attack` (critical intensity) to review command chain, `investigate_incident` (`scope`: `deep_dive`)
- **KPIs**: Identify Outlook zero-day exploitation, reduce dwell time to < 48h
- **Artefacts**: Plugin-provided JA3 hunts, executive dashboard for leadership war-room

## Manufacturing / OT Safety
- **Scenario**: `create_scenario` with `{"type":"ddos","difficulty":"advanced","sector":"ot"}`
- **Follow-up**: `analyze_network` on `{"focus":["threats","anomalies"]}`, `simulate_attack` for lateral IT-to-OT pivot
- **KPIs**: OT network segmentation test, containment < 6h, PLC integrity preserved
- **Artefacts**: Integration hook -> Cortex XSOAR automation, D3FEND mapping for OT controls

## SaaS / Cloud Platforms
- **Scenario**: `create_scenario` with `{"type":"apt","difficulty":"advanced","sector":"cloud"}`
- **Follow-up**: `analyze_network` (duration 30, focus `["anomalies","vulnerabilities"]`), `generate_report` (`report_type`: `executive`, `mode`: `facilitation`)
- **KPIs**: Cross-tenant drift detection, automation coverage for IAM incidents
- **Artefacts**: KQL beaconing detection, maturity roadmap alignment with ISO 27001

Keep the library updated as new adversary profiles and community contributions arrive. Pair each benchmark with audit log reviews to validate controls and training progress.
