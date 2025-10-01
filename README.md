# CyberSim Pro MCP Server

CyberSim Pro is a professional-grade Model Context Protocol (MCP) server purpose-built for cybersecurity training, purple-team collaboration, and executive readiness. It equips AI assistants and automation pipelines with structured tools to generate scenarios, simulate adversaries, analyse telemetry, investigate incidents, perform forensics, and publish board-ready reports—all while recording an immutable audit trail.

---

## Table of Contents
- [Feature Highlights](#feature-highlights)
- [Quick Start](#quick-start)
  - [Run with Node.js](#run-with-nodejs)
  - [Run with Docker](#run-with-docker)
  - [HTTP Bridge (REST API)](#http-bridge-rest-api)
- [MCP Client Integration](#mcp-client-integration)
  - [Claude Desktop](#claude-desktop)
  - [Cline VS Code Extension](#cline-vscode-extension)
- [Tool Reference & Walkthroughs](#tool-reference--walkthroughs)
  - [1. `create_scenario`](#1-create_scenario)
  - [2. `simulate_attack`](#2-simulate_attack)
  - [3. `analyze_network`](#3-analyze_network)
  - [4. `investigate_incident`](#4-investigate_incident)
  - [5. `forensics_analysis`](#5-forensics_analysis)
  - [6. `generate_report`](#6-generate_report)
  - [7. `stop_simulation`](#7-stop_simulation)
  - [8. `replay_telemetry`](#8-replay_telemetry)
  - [9. `list_metrics`](#9-list_metrics)
  - [10. `export_controls`](#10-export_controls)
  - [11. `sync_risk_register`](#11-sync_risk_register)
  - [12. `generate_validation_report`](#12-generate_validation_report)
- [Advanced Capabilities](#advanced-capabilities)
  - [Adaptive Adversary Profiles & Plugins](#adaptive-adversary-profiles--plugins)
  - [Command-Chain Drill-Down](#command-chain-drill-down)
  - [Detection Engineering Packs](#detection-engineering-packs)
  - [Executive & Governance Suite](#executive--governance-suite)
  - [Audit Logging & Kill Switch](#audit-logging--kill-switch)
  - [Role-Based Access & Approvals](#role-based-access--approvals)
  - [Risk & Compliance Sync](#risk--compliance-sync)
- [Operational Playbooks](#operational-playbooks)
- [Contributing & Community Sharing](#contributing--community-sharing)
- [Support Resources](#support-resources)
- [License](#license)

---

## Feature Highlights
- **Adaptive adversary scenarios** tied to real-world APT/FIN actor playbooks, sector-aware CVEs, and plugin-provided intel.
- **Command-chain drill-down**: pseudo CLI steps (guardrailed) for every attack phase to map outputs to analyst tooling.
- **Detection engineering bundles**: Sigma, Splunk, and KQL artefacts, MITRE ATT&CK heatmaps, gap analysis, and SOAR integration hooks.
- **Incident response suite**: deep investigations, forensic artefacts, purple-team scorecards, facilitation kits, executive dashboards, maturity roadmaps, and procurement briefs.
- **Operational guardrails**: append-only audit logs, approval-gated RBAC, `stop_simulation` kill switch, role-based prompt templates, and formal policy & ethics guide.
- **Telemetry replay & metrics**: overlay real PCAP/EDR/SIEM events on simulations, auto-capture readiness metrics, and expose historical trends.
- **Risk & control automation**: export compensating controls, sync with GRC platforms, and produce auditor-ready validation digests.

---

## Quick Start

### Run with Node.js
```bash
# Clone the repository (or copy into your workspace)
cd cybersim-pro-mcp

# Install dependencies
npm install

# Build TypeScript sources
npm run build

# Start the MCP server over stdio
node build/index.js
```

### Run with Docker
```bash
# Build the image (from the repo root)
docker build -t cybersim-pro-mcp .

# Launch in stdio mode (for Claude, Cline, etc.)
docker run --rm -i cybersim-pro-mcp
```

### HTTP Bridge (REST API)
Expose tools to REST clients or GPT Actions.
```bash
npm run serve:http  # defaults to http://localhost:8787
```
Secure with environment variables:
- `CYBERSIM_API_KEY` – require `Authorization: Bearer <key>` header
- `CYBERSIM_IP_ALLOW` – comma-separated list (`127.0.0.1,::1,local,203.0.113.10`)
- `CYBERSIM_APPROVAL_TOKEN` – shared secret required for restricted tools (`simulate_attack`, `stop_simulation`, `replay_telemetry`)
- `CYBERSIM_RBAC_CONFIG` – optional path to a JSON role policy (see [Role-Based Access & Approvals](#role-based-access--approvals))
- Metrics, control feeds, and audit digests are persisted to `./metrics/`, `./controls/`, and `./logs/` respectively.

Sample health & scenario creation:
```bash
curl -s http://localhost:8787/health

curl -s -X POST http://localhost:8787/tool/create_scenario \
  -H 'Content-Type: application/json' \
  -d '{
        "type": "ransomware",
        "difficulty": "advanced",
        "environment": "corporate",
        "sector": "finance",
        "adversary_profile": "fin7",
        "focus_cves": ["CVE-2024-21410"],
        "operator": {"id": "alice", "role": "controller"},
        "approval_token": "${CYBERSIM_APPROVAL_TOKEN}"
      }' | jq
```

---

## MCP Client Integration

### Claude Desktop
macOS path: `~/Library/Application Support/Claude/claude_desktop_config.json`
```json
{
  "mcpServers": {
    "cybersim-pro": {
      "command": "node",
      "args": ["/absolute/path/to/cybersim-pro-mcp/build/index.js"]
    }
  }
}
```
For Docker-backed execution:
```json
{
  "mcpServers": {
    "cybersim-pro-docker": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "cybersim-pro-mcp"]
    }
  }
}
```

### Cline VS Code Extension
Open **Command Palette → “Cline: Open MCP Settings”** and add:
```json
{
  "mcpServers": {
    "cybersim-pro": {
      "command": "node",
      "args": ["/absolute/path/to/cybersim-pro-mcp/build/index.js"]
    }
  }
}
```
Wrapper scripts in `./scripts/` support runtime switching via `CYBERSIM_RUNTIME`.

---

## Tool Reference & Walkthroughs
Each tool can be invoked through MCP clients or directly via the HTTP bridge. Examples below use `jq` for clarity.

### 1. `create_scenario`
Generate a tailored scenario with adaptive adversary content.

**HTTP Request**
```bash
curl -s -X POST http://localhost:8787/tool/create_scenario \
  -H 'Content-Type: application/json' \
  -d '{
        "type": "apt",
        "difficulty": "expert",
        "environment": "cloud",
        "sector": "government",
        "adversary_profile": "apt29",
        "focus_cves": ["CVE-2023-23397"]
      }' | jq '.id, .description, .threatIntel'
```

**What you get**
- Scenario ID (e.g., `SCN-...`)
- Sector-aligned objectives and timelines
- Adversary profile with CVEs, detection opportunities, plugin insight list

Use the returned `scenarioId` to reference the scenario in follow-up drills, reports, or evidence.

---

### 2. `simulate_attack`
Simulate a multi-phase attack and inspect the command-chain drill-down.

**HTTP Request**
```bash
curl -s -X POST http://localhost:8787/tool/simulate_attack \
  -H 'Content-Type: application/json' \
  -d '{
        "attack_type": "ransomware",
        "target": "FILESERVER-001",
        "intensity": "high"
      }' | jq '{simulationId, commandChain: .commandChain[0:5], phases: [.phases[0].artifacts[0]]}'
```

**Highlights**
- `commandChain` array details redacted pseudo commands, safeguards, and MITRE references for each phase.
- `phases` include techniques, detection methods, and evidence artefacts.
- `simulationId` feeds into `stop_simulation` or reporting workflows.

---

### 3. `analyze_network`
Analyse network segments and receive detection artefacts plus coverage insights.

**HTTP Request**
```bash
curl -s -X POST http://localhost:8787/tool/analyze_network \
  -H 'Content-Type: application/json' \
  -d '{
        "network_segment": "DMZ",
        "duration": 30,
        "focus": ["anomalies", "threats", "vulnerabilities"]
      }' | jq '{
        statistics: .statistics.bandwidthUtilization,
        sigma: .detectionArtifacts.sigma[0],
        splunk: .detectionArtifacts.splunk[0].query,
        heatmap: .mitreHeatmap[0:3],
        integration: .integrationHooks
      }'
```

**Output**
- Auto-generated Sigma/Splunk/KQL detections with descriptions & tags
- MITRE ATT&CK + D3FEND heatmap coverage with gap analysis
- Integration hooks for Splunk ES, Sentinel, and Cortex XSOAR
- Recommendations aligned with anomalies/vulnerabilities/threats

---

### 4. `investigate_incident`
Run a timeline-driven investigation with evidence, root cause, containment, and remediation details.

**HTTP Request**
```bash
curl -s -X POST http://localhost:8787/tool/investigate_incident \
  -H 'Content-Type: application/json' \
  -d '{
        "incident_id": "INC-2024-001",
        "scope": "deep_dive"
      }' | jq '{severity, timeline: .timeline.events[0:3], rootCause, containmentActions[0]}'
```

**Deliverables**
- Attack path reconstruction with dwell time
- Findings and supporting evidence (with chain-of-custody records)
- Containment actions, remediation steps, and lessons learned

---

### 5. `forensics_analysis`
Produce digital forensic artefacts for memory, disk, network, logs, or registry sources.

**HTTP Request**
```bash
curl -s -X POST http://localhost:8787/tool/forensics_analysis \
  -H 'Content-Type: application/json' \
  -d '{
        "artifact_type": "disk",
        "system_id": "WORKSTATION-001",
        "analysis_depth": "comprehensive"
      }' | jq '{artifactSummary: .findings[0], chainOfCustody: .chainOfCustody[0]}'
```

Expect curated findings, hash validation, custody records, and preservation guidance.

---

### 6. `generate_report`
Generate executive, incident, vulnerability, or compliance reports with optional facilitation mode.

**HTTP Request**
```bash
curl -s -X POST http://localhost:8787/tool/generate_report \
  -H 'Content-Type: application/json' \
  -d '{
        "report_type": "executive",
        "incident_ids": ["INC-2024-001", "INC-2024-002"],
        "include_recommendations": true,
        "mode": "facilitation"
      }' | jq '{
        executiveSummary,
        scorecard: .scorecard.metrics,
        facilitationKit: .facilitationKit.agenda,
        dashboard: .executiveDashboard.heatmap,
        roadmap: .maturityRoadmap.milestones,
        procurement: .procurementBrief.faqs
      }'
```

Key sections:
- Executive summary & risk posture
- Purple-team scorecard metrics and lessons
- Facilitation kit (kickoff prompt, teleprompter notes, agenda)
- Executive dashboard (risk, downtime, financial exposure)
- Maturity roadmap (NIST CSF, CMMC, ISO 27001 alignment)
- Procurement brief (FAQs, legal considerations, risk controls)

---

### 7. `stop_simulation`
Kill a single simulation or all active runs with audit logging.

```bash
# Stop a specific simulation ID
target="SIM-1759281782112"
curl -s -X POST http://localhost:8787/tool/stop_simulation \
  -H 'Content-Type: application/json' \
  -d "{\"simulation_id\": \"$target\", \"reason\": \"Executive requested early termination\", \"operator\": {\"id\": \"alice\", \"role\": \"controller\"}, \"approval_token\": \"${CYBERSIM_APPROVAL_TOKEN}\"}"

# Stop everything (returns list of terminated runs)
curl -s -X POST http://localhost:8787/tool/stop_simulation \
  -H 'Content-Type: application/json' \
  -d '{"operator":{"id":"alice","role":"controller"},"approval_token":"'"${CYBERSIM_APPROVAL_TOKEN}"'"}'
```

The audit logger records the termination reason, counts, and timestamps for compliance evidence.

---

### 8. `replay_telemetry`
Overlay raw telemetry (PCAP/EDR/SIEM exports) against a live simulation to validate coverage.

**HTTP Request**
```bash
curl -s -X POST http://localhost:8787/tool/replay_telemetry \
  -H 'Content-Type: application/json' \
  -d '{
        "simulation_id": "SIM-1759281782112",
        "telemetry": [
          {"timestamp":"2024-05-01T10:00:00Z","indicator":"powershell.exe","description":"Beacon to rare domain","techniqueId":"t1059.001"}
        ],
        "operator": {"id": "alice", "role": "controller"},
        "approval_token": "'"${CYBERSIM_APPROVAL_TOKEN}"'"
      }' | jq '{matchedTechniques, detectionGaps, observations}'
```

Matched techniques confirm detections fired; `detectionGaps` highlight phases lacking telemetry coverage. Recommended controls are appended automatically to the compensating-control feed.

---

### 9. `list_metrics`
Summarise readiness metrics across all exercises.

```bash
curl -s -X POST http://localhost:8787/tool/list_metrics -H 'Content-Type: application/json' -d '{}' | jq
```

Outputs include total exercises, reports generated, and average detection/containment times alongside the latest trend entries.

---

### 10. `export_controls`
Export the consolidated compensating-control feed (detections, automations, gap closures).

```bash
curl -s -X POST http://localhost:8787/tool/export_controls -H 'Content-Type: application/json' -d '{}' | jq '.[0:5]'
```

Each entry includes category, source, priority, and payload ready for SIEM/SOAR ingestion.

---

### 11. `sync_risk_register`
Generate REST payloads for governance platforms such as ServiceNow GRC, Archer, or OneTrust.

```bash
curl -s -X POST http://localhost:8787/tool/sync_risk_register \
  -H 'Content-Type: application/json' \
  -d '{
        "system": "servicenow",
        "incident_id": "INC-2024-001",
        "priority": "Critical",
        "owner": "risk.governance@example.com"
      }' | jq
```

The response provides the endpoint, HTTP method, payload, and checklist for operators to update the risk register.

---

### 12. `generate_validation_report`
Produce an auditor-facing summary with hashed proof of recent CyberSim activity.

```bash
curl -s -X POST http://localhost:8787/tool/generate_validation_report -H 'Content-Type: application/json' -d '{}' | jq
```

The digest contains the SHA-256 hash, total entries, and redacted samples suitable for regulator briefings.

---

## Advanced Capabilities

### Adaptive Adversary Profiles & Plugins
- Profiles (e.g., APT29, FIN7) embed motivations, campaigns, preferred tactics, CVEs, and countermeasures.
- `PluginRegistry` (`src/utils/pluginRegistry.ts`) lets you register sector or vendor-specific intel providers. Each plugin can inject CVEs, notes, and detection enhancements.
- Scenario outputs surface `threatIntel.pluginInsights` referencing contributing providers.

### Command-Chain Drill-Down
Simulations include `commandChain` entries describing pseudo commands, safeguards, and technique references. Use these to:
- Map red-team actions to your tooling (e.g., WMI logs, PowerShell policy)
- Provide narrations during live tabletop facilitation
- Export to internal red-team wikis without exposing live payloads

### Detection Engineering Packs
Network analysis responses include:
- Sigma rules (YAML-string), Splunk searches, Sentinel KQL queries
- Playbooks for triage/containment
- MITRE ATT&CK + D3FEND mappings and coverage heatmaps
- Integration hooks for Splunk ES saved searches, Sentinel analytics rules, and Cortex XSOAR playbooks

### Executive & Governance Suite
`generate_report` outputs provide everything needed for leadership alignment:
- Executive dashboard, downtime estimates, financial impact
- Purple-team metrics & lessons learned
- Facilitation kit for hybrid workshops
- Maturity roadmap with quarterly milestones and framework alignment
- Procurement brief with FAQ, legal, and risk-control summaries

### Audit Logging & Kill Switch
- Every tool invocation is appended to `logs/audit.log` (configurable via `CYBERSIM_AUDIT_LOG_DIR`).
- Entries capture timestamp, tool, sanitized arguments, metadata (scenario/report IDs), and error messages.
- The `stop_simulation` tool halts activity immediately and records the termination reason for traceability.
- `generate_validation_report` produces hashed digests of audit activity for auditors and regulators.

### Role-Based Access & Approvals
- High-impact tools (`simulate_attack`, `stop_simulation`, `replay_telemetry`) respect role policies defined via `CYBERSIM_RBAC_CONFIG`.
- Restricted tools require a shared approval token (`CYBERSIM_APPROVAL_TOKEN`), enabling dual-control or change-ticket workflows.
- Operator metadata is captured in the audit log, supporting segregation-of-duties reviews.
- Default policy grants analysts access to low-risk tooling while controllers/CISOs can execute adversary simulations.

### Risk & Compliance Sync
- `sync_risk_register` generates ready-to-post payloads for ServiceNow GRC, Archer, OneTrust, or custom systems.
- `export_controls` provides the compensating-control feed derived from detection packs, telemetry gaps, and automation hooks.
- Telemetry replay and network analysis automatically feed the control register so lessons learned become enforceable controls.

---

## Operational Playbooks
- **Learning Path** – follow beginner → intermediate → advanced exercises (see *Learning Path* section below) to ramp analysts.
- **Role-Based Prompt Templates** – prebuilt red/blue/purple/executive prompts in `docs/ROLE_BASED_PROMPTS.md`.
- **Policy & Ethics Guide** – acceptable use, regulatory alignment, and safety checklist in `docs/POLICY_AND_ETHICS.md`.
- **Benchmark Library** – curated scenarios per industry with KPIs in `docs/BENCHMARK_LIBRARY.md`.
- **Community Sharing Program** – contribute sanitized scenarios/detections using the workflow in `docs/COMMUNITY_PROGRAM.md`.

### Learning Path (Recap)
- **Beginner**: phishing or simple malware, focus on indicators and detection basics.
- **Intermediate**: ransomware/APT scenarios, run investigations and network analysis.
- **Advanced**: full kill-chain drills, deep forensics, executive reporting, automation via HTTP bridge.

---

## Contributing & Community Sharing
1. Fork the repository and branch from `main` (or `community/main` when contributing to shared content).
2. Add code or documentation, ensuring TypeScript builds succeed (`npm run build`).
3. For community packs, follow sanitisation and metadata guidelines in `docs/COMMUNITY_PROGRAM.md`.
4. Submit a pull request; audit logs and documentation updates are encouraged alongside new features.

---

## Support Resources
- Role-based prompts: `docs/ROLE_BASED_PROMPTS.md`
- Policy & ethics: `docs/POLICY_AND_ETHICS.md`
- Plugin guide: `docs/PLUGIN_ARCHITECTURE.md`
- Benchmark scenarios: `docs/BENCHMARK_LIBRARY.md`
- Community sharing workflow: `docs/COMMUNITY_PROGRAM.md`

For assistance:
1. Review the documentation above.
2. Inspect source code comments and example responses.
3. Reproduce minimal scenarios (`create_scenario` → `simulate_attack`) to isolate issues.
4. File issues or discussions on the GitHub repository.

---

## License
Released under the [MIT License](LICENSE). Use, modify, and adapt CyberSim Pro MCP Server for authorised defensive purposes.
