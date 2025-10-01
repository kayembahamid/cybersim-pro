export interface ThreatIntelRequest {
  scenarioType: string;
  sector: string;
  adversaryId?: string;
}

export interface ThreatIntelContribution {
  providerId: string;
  providerName: string;
  cves: string[];
  notes: string[];
  detectionEnhancements: string[];
}

export interface ThreatIntelPlugin {
  id: string;
  name: string;
  description: string;
  supportedSectors: string[];
  fetchIntel(request: ThreatIntelRequest): ThreatIntelContribution | undefined;
}

export class PluginRegistry {
  private static instance: PluginRegistry;
  private threatIntelProviders: ThreatIntelPlugin[] = [];
  private defaultsBootstrapped = false;

  private constructor() {
    this.bootstrapDefaults();
  }

  static getInstance(): PluginRegistry {
    if (!PluginRegistry.instance) {
      PluginRegistry.instance = new PluginRegistry();
    }
    return PluginRegistry.instance;
  }

  registerThreatIntelProvider(provider: ThreatIntelPlugin): void {
    const exists = this.threatIntelProviders.some((p) => p.id === provider.id);
    if (!exists) {
      this.threatIntelProviders.push(provider);
    }
  }

  collectThreatIntel(request: ThreatIntelRequest): ThreatIntelContribution[] {
    return this.threatIntelProviders
      .map((provider) => provider.fetchIntel(request))
      .filter((contribution): contribution is ThreatIntelContribution => Boolean(contribution));
  }

  listThreatIntelProviders(): ThreatIntelPlugin[] {
    return [...this.threatIntelProviders];
  }

  private bootstrapDefaults(): void {
    if (this.defaultsBootstrapped) {
      return;
    }

    const defaultProvider: ThreatIntelPlugin = {
      id: "default-cve-feed",
      name: "CyberSim Default CVE Feed",
      description: "Static mapping of trending CVEs by sector and adversary profile for lab simulations.",
      supportedSectors: ["finance", "healthcare", "government", "enterprise", "ot", "cloud"],
      fetchIntel: (request: ThreatIntelRequest): ThreatIntelContribution | undefined => {
        const sectorKey = request.sector.toLowerCase();
        const adversaryKey = request.adversaryId?.toLowerCase();

        const cveMap: Record<string, string[]> = {
          finance: ["CVE-2024-21410", "CVE-2023-48795"],
          healthcare: ["CVE-2024-27198", "CVE-2023-34362"],
          government: ["CVE-2023-23397", "CVE-2024-29988"],
          enterprise: ["CVE-2024-26169", "CVE-2024-29974"],
          ot: ["CVE-2024-4323", "CVE-2023-3079"],
          cloud: ["CVE-2024-21762", "CVE-2024-24576"],
          apt29: ["CVE-2023-23397", "CVE-2023-42793"],
          fin7: ["CVE-2024-21410", "CVE-2024-29988"],
        };

        const notesMap: Record<string, string[]> = {
          finance: [
            "Trending targeting of managed service providers impacting payment environments",
            "Credential stuffing spikes observed against retail portals",
          ],
          healthcare: [
            "Increased ransomware targeting of electronic health record platforms",
            "Legacy VPN appliances remain exposed in regional clinics",
          ],
          government: [
            "State-sponsored spearphishing using diplomatic lures",
            "Zero-day exploitation of secure mail gateways",
          ],
          enterprise: [
            "Supply-chain compromises across CI/CD providers",
            "Rise in data exfiltration via cloud storage misconfigurations",
          ],
          ot: [
            "ICS protocol abuse through unsecured remote access gateways",
            "Ransomware groups experimenting with PLC payloads",
          ],
          cloud: [
            "Cross-tenant isolation bugs exploited for lateral movement",
            "Misconfigured API gateways enabling privilege escalation",
          ],
          apt29: [
            "Diplomatic-themed lures distributing Outlook-based zero-day exploits",
            "Low-and-slow HTTPS beaconing leveraging cloud CDN infrastructure",
          ],
          fin7: [
            "Compromised remote monitoring tools distributing Carbanak payloads",
            "Weaponised SSH vulnerability CVE-2023-48795 for lateral pivot",
          ],
        };

        const detectionMap: Record<string, string[]> = {
          finance: ["Deploy POS memory scraping detection analytics", "Enable card data DLP for outbound traffic"],
          healthcare: ["Implement EDR response playbooks for radiology and lab systems", "Audit access to EHR privileged accounts"],
          government: ["Enhance monitoring for Outlook anomalous reminder properties", "Correlate VPN logins with identity assurance"],
          enterprise: ["Instrument CI/CD logs for unsigned artifact uploads", "Deploy anomaly detection on cloud storage APIs"],
          ot: ["Introduce anomaly detection on Modbus communications", "Segment remote access paths into OT VLAN"],
          cloud: ["Enable workload identity analytics across tenants", "Monitor API error spikes for privilege escalation attempts"],
          apt29: ["Hunt for Outlook reminder abuse (PropertyTag 0x851F)", "Baseline JA3 fingerprinting for suspected Cozy Bear tooling"],
          fin7: ["Alert on SSH multiplexing and port forwarding from POS subnets", "Monitor for lateral RDP usage across store endpoints"],
        };

        const key = adversaryKey && cveMap[adversaryKey] ? adversaryKey : sectorKey;
        const cves = cveMap[key];
        if (!cves) {
          return undefined;
        }

        return {
          providerId: defaultProvider.id,
          providerName: defaultProvider.name,
          cves,
          notes: notesMap[key] || [],
          detectionEnhancements: detectionMap[key] || [],
        };
      },
    };

    this.registerThreatIntelProvider(defaultProvider);
    this.defaultsBootstrapped = true;
  }
}
