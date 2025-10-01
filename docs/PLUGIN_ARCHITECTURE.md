# Plugin Architecture

CyberSim Pro ships with an extensible plugin registry that lets teams integrate custom threat intelligence, detection content, or scenario augmenters without modifying core code. Plugins live completely in code, so you can version-control contributions alongside playbooks and guardrails.

## Threat Intelligence Providers

`PluginRegistry` (see `src/utils/pluginRegistry.ts`) exposes a singleton registry with helper methods for plugging in custom providers:

```ts
import { PluginRegistry, ThreatIntelPlugin } from "../utils/pluginRegistry.js";

const registry = PluginRegistry.getInstance();

const myFeed: ThreatIntelPlugin = {
  id: "finance-ti-feed",
  name: "Finance ISAC Stream",
  description: "Sector-specific trending CVEs and detection ideas",
  supportedSectors: ["finance"],
  fetchIntel(request) {
    if (request.sector !== "finance") return undefined;
    return {
      providerId: "finance-ti-feed",
      providerName: "Finance ISAC Stream",
      cves: ["CVE-2024-21410"],
      notes: ["Targeted spearphishing via managed service partners"],
      detectionEnhancements: ["Deploy adaptive MFA analytics for partner accounts"],
    };
  },
};

registry.registerThreatIntelProvider(myFeed);
```

Registered providers receive the scenario type, selected sector, and the resolved adversary profile (if any). The `SecurityScenarioManager` merges contributions into:

- `targetedCves` — combined list of CVEs used in the scenario
- `threatIntel.pluginInsights` — surfaced alongside adversary background
- detection opportunity lists and objectives (so operators immediately see how to action the intel)

## Built-in Provider

A default provider ships with CyberSim Pro to seed curated CVEs and focus areas for common sectors and adversary profiles (`apt29`, `fin7`, OT, cloud, etc.). The provider demonstrates how to:

- Map CVEs to industries and actors
- Feed additional detection enhancements (e.g., JA3 fingerprint hunts, POS telemetry)
- Supply context notes that are rendered inside documentation and scenarios

## Additional Plugin Ideas

- **Detection Packs**: Register a provider that emits Sigma/Splunk/KQL snippets for a proprietary telemetry stack.
- **Scenario Augmenters**: Extend the registry (or mirror the same pattern) for injecting custom objectives, timelines, or training hints.
- **Telemetry Replay Hooks**: Provide instructions for replaying captured PCAP/EDR data specific to your environment.

> 🔒 Plugins run in-process with the MCP server. Follow the same secure coding standards you apply to the core project, and ensure providers only expose sanitised training data.

## Operational Workflow

1. Create a plugin module under `src/plugins/` or `src/custom/` and export a registration helper.
2. Import and register the plugin from `src/index.ts` or a local bootstrap script (e.g., `scripts/load-plugins.ts`).
3. Keep plugin code guarded by environment flags if it should only run in certain deployments.
4. Document the plugin in your internal runbooks and add regression tests where possible.

With the plugin registry you can keep CyberSim Pro aligned with live threat intelligence feeds while retaining an immutable audit log of every augmentation applied during exercises.
