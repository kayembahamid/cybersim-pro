# CyberSim Pro MCP Server

A professional-grade Model Context Protocol (MCP) server for cybersecurity training, simulation, and incident response. This server provides AI assistants with powerful tools to create realistic security scenarios, simulate attacks, analyze networks, investigate incidents, and perform digital forensics.
# CyberSim Pro MCP Server

A professional-grade Model Context Protocol (MCP) server for cybersecurity training, simulation, and incident response. This server provides AI assistants with powerful tools to create realistic security scenarios, simulate attacks, analyze networks, investigate incidents, and perform digital forensics.

## 🎯 Overview

CyberSim Pro enables AI assistants to help security professionals and learners with:
- **Security Scenario Creation** - Generate realistic training scenarios across multiple attack types
- **Threat Simulation** - Simulate sophisticated cyberattacks with detailed TTPs
- **Network Analysis** - Analyze network traffic and identify security issues
- **Incident Response** - Conduct comprehensive incident investigations
- **Digital Forensics** - Perform forensic analysis on various artifact types
- **Security Reporting** - Generate executive and technical security reports

## 🏗️ Project Structure

```
cybersim-pro-mcp/
├── src/
│   ├── index.ts                          # Main server entry point
│   ├── scenarios/
│   │   └── scenarioManager.ts            # Security scenario management
│   ├── simulators/
│   │   ├── networkSimulator.ts           # Network traffic simulation
│   │   └── threatSimulator.ts            # Threat/attack simulation
│   ├── managers/
│   │   └── incidentResponseManager.ts    # Incident response management
│   └── analyzers/
│       └── forensicsAnalyzer.ts          # Digital forensics analysis
├── build/                                # Compiled JavaScript output
├── package.json                          # Project dependencies
├── tsconfig.json                         # TypeScript configuration
└── README.md                             # This file
```

## 🚀 Installation

### Prerequisites
- Node.js 18.0.0 or higher
- npm or yarn package manager

### Setup Steps

1. **Clone or create the project directory:**
```bash
mkdir cybersim-pro-mcp
cd cybersim-pro-mcp
```

2. **Create the source directory structure:**
```bash
mkdir -p src/{scenarios,simulators,managers,analyzers}
```

3. **Copy all source files into their respective directories:**
   - `index.ts` → `src/`
   - `scenarioManager.ts` → `src/scenarios/`
   - `networkSimulator.ts` → `src/simulators/`
   - `threatSimulator.ts` → `src/simulators/`
   - `incidentResponseManager.ts` → `src/managers/`
   - `forensicsAnalyzer.ts` → `src/analyzers/`

4. **Initialize and install dependencies:**
```bash
npm install
```

5. **Build the project:**
```bash
npm run build
```

## 🐳 Docker

Build and run the MCP server inside Docker (stdio-based):

1) Build image

```bash
docker build -t cybersim-pro-mcp ./cybersim-pro-mcp
```

2) Run (stdio)

```bash
docker run --rm -i cybersim-pro-mcp
```

To use Docker with the Cline VS Code extension, configure the server as:

```json
{
  "mcpServers": {
    "cybersim-pro": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "cybersim-pro-mcp"]
    }
  }
}
```

Notes
- The server communicates over stdio; no ports are exposed.
- Rebuild the image after changes: `docker build -t cybersim-pro-mcp ./cybersim-pro-mcp`.

### Unified Launcher (Node or Docker)

Use a single wrapper that runs Node by default, or Docker when `CYBERSIM_RUNTIME=docker`:

Wrapper script: `cybersim-pro-mcp/scripts/run-cybersim.sh`

Examples:

```bash
# Local build (Node)
CYBERSIM_RUNTIME=node cybersim-pro-mcp/scripts/run-cybersim.sh

# Docker image (ensure image is built)
CYBERSIM_RUNTIME=docker cybersim-pro-mcp/scripts/run-cybersim.sh
```

Configure Cline (VS Code) to use the unified launcher:

```json
{
  "mcpServers": {
    "cybersim-pro-auto": {
      "command": "/absolute/path/to/cybersim-pro-mcp/scripts/run-cybersim.sh",
      "args": []
    }
  }
}
```

Claude Desktop can also point to the same script; set `CYBERSIM_RUNTIME` in your shell or via a small wrapper if desired.

### HTTP Bridge (for GPT Actions and non‑MCP clients)

Run a simple HTTP server that mirrors the MCP tools:

```bash
cd cybersim-pro-mcp
npm run serve:http
# Default port: 8787 (override with PORT=xxxx)
```

Example calls:

```bash
curl -sS http://localhost:8787/health

curl -sS -X POST http://localhost:8787/tool/create_scenario \
  -H 'Content-Type: application/json' \
  -d '{"type":"ransomware","difficulty":"advanced","environment":"corporate"}'
```

OpenAPI spec: `cybersim-pro-mcp/http-openapi.yaml` (serve this file when configuring GPT Actions).

#### Make it public quickly (tunnels)

You can expose the local HTTP bridge with a tunnel service:

```bash
# Example using Cloudflare Tunnel (warp/v2) or ngrok
# ngrok (requires account):
ngrok http 8787

# cloudflared (if you have a domain):
cloudflared tunnel --url http://localhost:8787
```

For production, run in Docker on a server/VPS and expose the port:

```bash
# Build image
docker build -t cybersim-pro-mcp ./cybersim-pro-mcp

# Run HTTP bridge publicly on port 8787
docker run -d --name cybersim-pro-http \
  -e CYBERSIM_MODE=http \
  -e CYBERSIM_API_KEY=YOUR_SECRET_TOKEN \
  -p 8787:8787 \
  cybersim-pro-mcp

# Verify
curl -sS http://YOUR_SERVER_IP:8787/health

curl -sS -X POST http://YOUR_SERVER_IP:8787/tool/create_scenario \
  -H 'Authorization: Bearer YOUR_SECRET_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"type":"ransomware","difficulty":"advanced"}'

Security options
- API key: set `CYBERSIM_API_KEY` and send `Authorization: Bearer <key>` on requests (required for /tool/* when set).
- IP allowlist (optional): set `CYBERSIM_IP_ALLOW` with comma-separated IPs (e.g., `127.0.0.1,::1,203.0.113.10,local`). Requests must come from allowed IPs.

## 📦 Publish to Docker Hub and list in MCP Toolkit

1) Create a Docker Hub repository named `cybersim-pro-mcp` under your account.

2) Set GitHub secrets in your repository:
   - `DOCKERHUB_USERNAME`
   - `DOCKERHUB_TOKEN` (Docker Hub access token)

3) Tag a release in Git (`v1.0.0`, etc.). The workflow builds multi-arch images and pushes:
   - `.github/workflows/docker-publish.yml`

4) Verify on Docker Hub: `hamcodes/cybersim-pro-mcp` has tags `latest`, `vX.Y.Z`.

5) Improve discoverability: Dockerfile includes OCI labels (title, description, source, license).

6) Submit to MCP Toolkit Catalog:
   - Click “Contribute” in the MCP Toolkit UI or open the catalog repo and add an entry.
   - Use `cybersim-pro-mcp/mcp-catalog.json` as a template; update `image`, `repository`, `homepage`, and `maintainers`.
   - Provide an icon (SVG/PNG) if requested by the catalog and link it.

Suggested Docker run snippet for catalog card (stdio):

```
docker run --rm -i hamcodes/cybersim-pro-mcp:latest
```

Suggested Docker run snippet for catalog card (HTTP):

```
docker run --rm -p 8787:8787 -e CYBERSIM_MODE=http hamcodes/cybersim-pro-mcp:latest
```
```

## 📝 Configuration

### Claude Desktop Integration

Add to your Claude Desktop configuration file:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

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

#### Claude Desktop via Docker

Build the image first:

```bash
docker build -t cybersim-pro-mcp ./cybersim-pro-mcp
```

Then use this Claude Desktop config to run the server in Docker:

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

#### Claude Desktop (macOS) — Quick Launch Scripts

You can point Claude directly to helper scripts for Node or Docker:

```json
{
  "mcpServers": {
    "cybersim-pro-node": {
      "command": "/absolute/path/to/cybersim-pro-mcp/scripts/run-cybersim-node.sh",
      "args": []
    },
    "cybersim-pro-docker": {
      "command": "/absolute/path/to/cybersim-pro-mcp/scripts/run-cybersim-docker.sh",
      "args": []
    }
  }
}
```

Notes
- The Node script expects a built server at `build/index.js`.
- The Docker script expects a built image named `cybersim-pro-mcp` (see Docker section).

### Cline VSCode Extension Integration

Add to your Cline MCP settings:

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

## 🔧 Available Tools

### 1. create_scenario
Create customizable cybersecurity training scenarios.

**Parameters:**
- `type` (required): phishing, ransomware, ddos, data_breach, insider_threat, apt
- `difficulty` (required): beginner, intermediate, advanced, expert
- `environment` (optional): corporate, cloud, IoT, etc.

**Example:**
```json
{
  "type": "ransomware",
  "difficulty": "advanced",
  "environment": "corporate"
}
```

### 2. simulate_attack
Simulate realistic cyberattacks with detailed attack phases.

**Parameters:**
- `attack_type` (required): Type of attack to simulate
- `target` (required): Target system or network segment
- `intensity` (optional): low, medium, high, critical

**Example:**
```json
{
  "attack_type": "ransomware",
  "target": "WORKSTATION-001",
  "intensity": "high"
}
```

### 3. analyze_network
Analyze network traffic and identify security issues.

**Parameters:**
- `network_segment` (required): Network segment to analyze
- `duration` (optional): Analysis duration in minutes (default: 10)
- `focus` (optional): Array of focus areas - anomalies, vulnerabilities, threats

**Example:**
```json
{
  "network_segment": "DMZ",
  "duration": 30,
  "focus": ["anomalies", "threats"]
}
```

### 4. investigate_incident
Conduct incident response investigations.

**Parameters:**
- `incident_id` (required): Unique incident identifier
- `scope` (optional): initial, full, deep_dive (default: initial)

**Example:**
```json
{
  "incident_id": "INC-2024-001",
  "scope": "full"
}
```

### 5. forensics_analysis
Perform digital forensics on system artifacts.

**Parameters:**
- `artifact_type` (required): memory, disk, network, logs, registry
- `system_id` (required): System identifier
- `analysis_depth` (optional): quick, standard, comprehensive (default: standard)

**Example:**
```json
{
  "artifact_type": "memory",
  "system_id": "WORKSTATION-001",
  "analysis_depth": "comprehensive"
}
```

### 6. generate_report
Generate comprehensive security reports.

**Parameters:**
- `report_type` (required): incident, vulnerability, compliance, executive
- `incident_ids` (optional): Array of related incident IDs
- `include_recommendations` (optional): Boolean (default: true)

**Example:**
```json
{
  "report_type": "executive",
  "incident_ids": ["INC-2024-001", "INC-2024-002"],
  "include_recommendations": true
}
```

## 💡 Usage Examples

### Example 1: Create and Simulate a Ransomware Attack

```
User: Create an advanced ransomware scenario in a corporate environment

AI uses: create_scenario
- type: "ransomware"
- difficulty: "advanced"
- environment: "corporate"

User: Now simulate this attack with high intensity

AI uses: simulate_attack
- attack_type: "ransomware"
- target: "FILESERVER-001"
- intensity: "high"
```

### Example 2: Investigate a Security Incident

```
User: Investigate incident INC-2024-001 with full scope

AI uses: investigate_incident
- incident_id: "INC-2024-001"
- scope: "full"

User: Perform comprehensive forensics on the affected system

AI uses: forensics_analysis
- artifact_type: "disk"
- system_id: "WORKSTATION-001"
- analysis_depth: "comprehensive"

User: Generate an executive report

AI uses: generate_report
- report_type: "executive"
- incident_ids: ["INC-2024-001"]
- include_recommendations: true
```

### Example 3: Network Security Assessment

```
User: Analyze our DMZ network for threats and vulnerabilities

AI uses: analyze_network
- network_segment: "DMZ"
- duration: 60
- focus: ["threats", "vulnerabilities", "anomalies"]
```

## 🎓 Learning Path

### Beginner Level
1. Start with basic scenarios (phishing, simple malware)
2. Use "beginner" difficulty settings
3. Focus on understanding attack indicators
4. Review detection methods and recommendations

### Intermediate Level
1. Progress to multi-phase attacks (ransomware, APT)
2. Use "intermediate" difficulty
3. Practice incident investigation techniques
4. Analyze network traffic patterns

### Advanced Level
1. Work with complex scenarios (APT campaigns)
2. Use "advanced" or "expert" difficulty
3. Conduct deep forensic analysis
4. Generate comprehensive security reports

## 🔒 Security Features

### MITRE ATT&CK Integration
All scenarios and simulations are mapped to MITRE ATT&CK framework, providing:
- Tactic and technique identification
- TTP (Tactics, Techniques, Procedures) documentation
- Industry-standard threat categorization

### Realistic Indicators of Compromise (IOCs)
Generated IOCs include:
- File hashes (SHA-256)
- IP addresses and domains
- Registry keys and file paths
- Network signatures

### Chain of Custody
Digital forensics maintains proper evidence handling:
- Cryptographic hash verification
- Timestamped custody records
- Handler documentation
- Evidence preservation

## 🤖 Working with AI Guardrails

- Lead each session with explicit defensive context (authorized lab, training goal) so MCP clients treat the simulation as a safety exercise.
- Phrase red-team actions as simulated steps that support detection practice instead of real exploitation instructions.
- Include safety flags in tool prompts or scenario templates (for example, `training=true`, `environment="lab"`) to help downstream assistants interpret intent.
- Sanitize payload-like output by returning placeholders or high-level descriptions while preserving investigative details to reduce guardrail triggers.
- Provide operators with acceptable-use guidance and keep conversations focused on detection, mitigation, and lessons learned to align with platform policies.

## 🗣️ Prompt Playbook

Use these ready-to-copy prompts when you connect CyberSim Pro to Claude, Cline, or another MCP client.

**Session kickoff (share first):**
```text
You are assisting with a SOC tabletop in an isolated lab environment.
Objective: train defenders on ransomware response.
Constraints: describe only simulated attacker actions, never real payloads.
Confirm readiness, then we will invoke CyberSim Pro tools.
```

**Scenario creation:**
```text
Invoke the CyberSim Pro tool `create_scenario` with:
{
  "type": "ransomware",
  "difficulty": "advanced",
  "environment": "corporate",
  "training": true
}
Return the narrative, impacted assets, and the MITRE ATT&CK techniques we should brief to analysts.
```

**Simulated attacker run:**
```text
Run `simulate_attack` using the current scenario. Emphasize the lateral movement phase and call out artifacts analysts should monitor. Keep all payloads redacted as `[SIMULATED_PAYLOAD]`.
```

**Network-focused drill:**
```text
Analyze the DMZ segment for a 30-minute window with `analyze_network`.
Parameters: {"network_segment":"DMZ","duration":30,"focus":["anomalies","threats"],"training":true}.
Convert the findings into three SOC alert playbooks (detection, triage, containment).
```

**Host investigation:**
```text
Investigate incident INC-TRAIN-2025-002 at full scope with `investigate_incident`.
Summarize host findings, timeline, and recommended containment actions suitable for the blue-team briefing.
```

**Forensics deep dive:**
```text
Run `forensics_analysis` on WORKSTATION-TRAIN-07 with analysis depth "comprehensive".
Redact any live malware binaries as `[REDACTED_SAMPLE]` but keep hashes, timestamps, and chain-of-custody notes.
```

**Executive wrap-up:**
```text
Use `generate_report` with report_type "executive" covering incidents INC-TRAIN-2025-001 and INC-TRAIN-2025-002.
Include lessons learned, policy updates, and technology improvements for leadership.
```

**Closeout reflection:**
```text
Summarize key defensive takeaways from today’s tabletop by People, Process, and Technology. Highlight next steps for blue-team readiness.
```

## 📊 Output Formats

All tools return structured JSON data including:
- Detailed findings and analysis
- Timeline reconstruction
- Evidence artifacts
- Recommendations
- MITRE ATT&CK mappings
- IOCs and signatures

## 🛠️ Development

### Build Commands

```bash
# Build the project
npm run build

# Watch mode for development
npm run watch

# Run the server directly
npm run dev
```

### Extending the Server

To add new tools:
1. Add tool definition in `getTools()` method
2. Create handler method in `CyberSimProServer` class
3. Implement business logic in appropriate module
4. Update documentation

## 📚 References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Model Context Protocol Documentation](https://modelcontextprotocol.io/)
- [SANS Incident Response](https://www.sans.org/white-papers/)

## 🤝 Use Cases

### Security Training
- Create realistic scenarios for SOC analysts
- Practice incident response procedures
- Develop threat hunting skills
- Learn digital forensics techniques

### Red Team Exercises
- Plan attack simulations
- Document attack chains
- Generate realistic IOCs
- Test detection capabilities

### Security Assessments
- Conduct network analysis
- Identify vulnerabilities
- Generate compliance reports
- Document security posture

### Incident Response
- Investigate security incidents
- Perform forensic analysis
- Reconstruct attack timelines
- Generate incident reports

## 📄 License

MIT License - Feel free to use and modify for your needs

## 🆘 Support

For issues, questions, or contributions:
- Review the documentation above
- Check the source code comments
- Examine the example outputs
- Test with simple scenarios first

## 🎯 Roadmap

Future enhancements:
- Additional attack scenario types
- Integration with threat intelligence feeds
- Automated playbook generation
- Custom report templates
- Multi-tenancy support
- Cloud platform simulations

---

**Built with ❤️ for the cybersecurity community**
