Title: Add CyberSim Pro MCP server (security training, simulation, IR & forensics)

Summary
- Name: CyberSim Pro
- Version: v1.1.0 (adaptive adversaries & executive scorecards)
- Image: hamcodes/cybersim-pro-mcp:latest
- Repo: https://github.com/kayembahamid/cybersim-pro
- Icon: https://raw.githubusercontent.com/kayembahamid/cybersim-pro/main/cybersim-pro-mcp/assets/icon.svg

Description
CyberSim Pro is a professional-grade MCP server that equips AI assistants with security tooling:
- Create realistic security scenarios (phishing, ransomware, APT, etc.)
- Simulate attacks with detailed TTPs and MITRE ATT&CK mapping
- Analyze network segments for anomalies, vulnerabilities, and threats
- Conduct incident response investigations with timelines and evidence
- Perform digital forensics on memory, disk, logs, registry artifacts
- Generate executive and technical security reports with purple-team scorecards, facilitation kits, and executive dashboards
- Export detection engineering packs (Sigma, Splunk, KQL) and MITRE ATT&CK/D3FEND heatmaps
- Leverage plugin-based threat intel (sector-specific CVEs, community packs) with immutable audit logging
- Replay real telemetry against simulations, capture readiness metrics, enforce RBAC/approvals, and sync compensating controls into enterprise risk registers

Docker usage
- stdio (for MCP clients like Claude/Cline):
  docker run --rm -i hamcodes/cybersim-pro-mcp:latest

- http (bridge for non‑MCP clients / Actions):
  docker run --rm -p 8787:8787 -e CYBERSIM_MODE=http hamcodes/cybersim-pro-mcp:latest

Security (HTTP mode)
- Optional API key: set CYBERSIM_API_KEY and send Authorization: Bearer <key>
- Optional IP allowlist: CYBERSIM_IP_ALLOW="127.0.0.1,::1,local,203.0.113.10"

Catalog entry (JSON)
See mcp-catalog.json in the repository root of the server folder (cybersim-pro-mcp/mcp-catalog.json). It includes id, name, description, icon, image, instructions (stdio/http), categories, license, repository, homepage, maintainers.

Notes
- Image includes OCI labels and supports both stdio and HTTP modes.
- Tested locally and published to Docker Hub under hamcodes.
