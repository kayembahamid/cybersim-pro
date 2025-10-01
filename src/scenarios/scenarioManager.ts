import { AdversaryProfile, getAdversaryProfile, listAdversaryProfiles } from "../data/adversaryProfiles.js";
import { PluginRegistry, ThreatIntelContribution } from "../utils/pluginRegistry.js";

export interface ThreatIntelSnapshot {
  actor: string;
  aliases: string[];
  motivation: string;
  region: string;
  recentCampaigns: string[];
  exploitCves: string[];
  preferredTactics: string[];
  intelligenceDate: string;
  detectionOpportunities: string[];
  countermeasures: string[];
  references: string[];
  pluginInsights: ThreatIntelContribution[];
}

export interface SecurityScenario {
  id: string;
  type: string;
  difficulty: string;
  environment: string;
  sector: string;
  description: string;
  objectives: string[];
  attackVectors: AttackVector[];
  defenses: Defense[];
  timeline: TimelineEvent[];
  successCriteria: string[];
  hints: Hint[];
  mitreTactics: string[];
  adversaryProfile?: AdversaryProfile;
  threatIntel: ThreatIntelSnapshot;
  targetedCves: string[];
}

export interface AttackVector {
  phase: string;
  technique: string;
  mitreId: string;
  description: string;
  indicators: string[];
}

export interface Defense {
  layer: string;
  control: string;
  effectiveness: string;
  implementation: string;
}

export interface TimelineEvent {
  timestamp: string;
  event: string;
  severity: string;
  details: string;
}

export interface Hint {
  level: number;
  content: string;
  revealCondition: string;
}

interface ScenarioOptions {
  sector?: string;
  adversaryProfile?: string;
  cveFocus?: string[];
}

export class SecurityScenarioManager {
  private scenarios: Map<string, SecurityScenario> = new Map();
  private scenarioCounter: number = 0;
  private pluginRegistry: PluginRegistry = PluginRegistry.getInstance();

  async createScenario(
    type: string,
    difficulty: string,
    environment?: string,
    options: ScenarioOptions = {}
  ): Promise<SecurityScenario> {
    const scenarioId = `SCN-${Date.now()}-${++this.scenarioCounter}`;
    const env = environment || "corporate";
    const sector = options.sector || env;
    const profile = this.resolveAdversaryProfile(type, sector, options.adversaryProfile);
    const pluginInsights = this.pluginRegistry.collectThreatIntel({
      scenarioType: type,
      sector,
      adversaryId: profile?.id,
    });
    const targetedCves = this.resolveTargetedCves(profile, options.cveFocus, pluginInsights);

    const scenario = this.generateScenarioTemplate(
      scenarioId,
      type,
      difficulty,
      env,
      sector,
      profile,
      targetedCves,
      pluginInsights
    );

    this.scenarios.set(scenarioId, scenario);
    return scenario;
  }

  private generateScenarioTemplate(
    id: string,
    type: string,
    difficulty: string,
    environment: string,
    sector: string,
    profile: AdversaryProfile | undefined,
    targetedCves: string[],
    pluginInsights: ThreatIntelContribution[]
  ): SecurityScenario {
    const templates: Record<string, any> = {
      phishing: {
        description: `Advanced spear-phishing campaign targeting ${environment} environment`,
        objectives: [
          "Identify malicious email indicators",
          "Trace attacker infrastructure",
          "Assess credential compromise",
          "Implement email security controls",
        ],
        mitreTactics: [
          "TA0001 - Initial Access",
          "TA0006 - Credential Access",
          "TA0009 - Collection",
        ],
        attackVectors: [
          {
            phase: "Reconnaissance",
            technique: "Gather Victim Identity Information",
            mitreId: "T1589",
            description: "Attacker researches target organization via LinkedIn and social media",
            indicators: ["Suspicious profile views", "Connection requests from unknown domains"],
          },
          {
            phase: "Weaponization",
            technique: "Spearphishing Attachment",
            mitreId: "T1566.001",
            description: "Crafted email with malicious Office document containing macros",
            indicators: [
              "Email from spoofed executive domain",
              "Urgency-based language",
              "Suspicious attachment (Q4_Financial_Report.docm)",
            ],
          },
          {
            phase: "Exploitation",
            technique: "User Execution: Malicious File",
            mitreId: "T1204.002",
            description: "User opens document, enabling macros that execute PowerShell payload",
            indicators: [
              "PowerShell execution with encoded commands",
              "Outbound connection to suspicious IP",
              "Registry persistence modifications",
            ],
          },
        ],
        defenses: [
          {
            layer: "Email Security",
            control: "SPF/DKIM/DMARC validation",
            effectiveness: difficulty === "beginner" ? "High" : "Medium",
            implementation: "Configure email gateway with strict authentication policies",
          },
          {
            layer: "Endpoint Protection",
            control: "Macro execution restrictions",
            effectiveness: "High",
            implementation: "Group Policy to disable macros in Office documents from internet",
          },
          {
            layer: "Network Security",
            control: "Egress filtering",
            effectiveness: "Medium",
            implementation: "Block outbound connections to suspicious IPs and domains",
          },
          {
            layer: "User Awareness",
            control: "Security training",
            effectiveness: difficulty === "beginner" ? "Low" : "Medium",
            implementation: "Regular phishing simulation exercises and awareness training",
          },
        ],
      },
      ransomware: {
        description: `Sophisticated ransomware attack on ${environment} infrastructure`,
        objectives: [
          "Detect initial compromise vector",
          "Identify lateral movement patterns",
          "Isolate affected systems",
          "Recover encrypted data",
          "Prevent future attacks",
        ],
        mitreTactics: [
          "TA0001 - Initial Access",
          "TA0002 - Execution",
          "TA0003 - Persistence",
          "TA0004 - Privilege Escalation",
          "TA0005 - Defense Evasion",
          "TA0008 - Lateral Movement",
          "TA0040 - Impact",
        ],
        attackVectors: [
          {
            phase: "Initial Access",
            technique: "Exploit Public-Facing Application",
            mitreId: "T1190",
            description: "Exploitation of unpatched VPN gateway vulnerability (CVE-2023-XXXXX)",
            indicators: [
              "Unusual VPN authentication attempts",
              "Suspicious user agent strings",
              "Failed exploitation attempts in logs",
            ],
          },
          {
            phase: "Privilege Escalation",
            technique: "Valid Accounts: Domain Accounts",
            mitreId: "T1078.002",
            description: "Compromised domain admin credentials used for elevation",
            indicators: [
              "Unusual admin login from workstation",
              "Off-hours authentication",
              "Multiple failed Kerberos authentication attempts",
            ],
          },
          {
            phase: "Lateral Movement",
            technique: "Remote Services: SMB/Windows Admin Shares",
            mitreId: "T1021.002",
            description: "Spread via network shares using compromised credentials",
            indicators: [
              "Unusual SMB traffic patterns",
              "Administrative share access from non-IT systems",
              "Rapid file transfers across network segments",
            ],
          },
          {
            phase: "Impact",
            technique: "Data Encrypted for Impact",
            mitreId: "T1486",
            description: "Mass encryption of files with .locked extension and ransom note deployment",
            indicators: [
              "High disk I/O activity",
              "Batch file modifications",
              "Ransom note (README_FOR_DECRYPT.txt) on desktops",
              "Shadow copy deletion",
            ],
          },
        ],
        defenses: [
          {
            layer: "Network Security",
            control: "Network segmentation",
            effectiveness: "High",
            implementation: "Isolate critical systems with VLANs and firewall rules",
          },
          {
            layer: "Endpoint Protection",
            control: "EDR with behavioral analysis",
            effectiveness: "High",
            implementation: "Deploy EDR solution with ransomware-specific detection rules",
          },
          {
            layer: "Identity & Access",
            control: "Privileged Access Management",
            effectiveness: "High",
            implementation: "Implement just-in-time admin access and MFA",
          },
          {
            layer: "Data Protection",
            control: "Offline backups",
            effectiveness: "Critical",
            implementation: "Maintain air-gapped or immutable backup copies",
          },
        ],
      },
      ddos: {
        description: `Distributed Denial of Service attack against ${environment} services`,
        objectives: [
          "Identify attack type and source",
          "Implement mitigation strategies",
          "Maintain service availability",
          "Document attack patterns",
        ],
        mitreTactics: ["TA0040 - Impact"],
        attackVectors: [
          {
            phase: "Reconnaissance",
            technique: "Active Scanning",
            mitreId: "T1595",
            description: "Attacker probes infrastructure to identify weak points",
            indicators: ["Port scanning activity", "Service enumeration attempts"],
          },
          {
            phase: "Resource Development",
            technique: "Botnet",
            mitreId: "T1584.005",
            description: "Attacker leverages compromised IoT devices as botnet",
            indicators: ["Traffic from IoT device IP ranges", "Geographically distributed sources"],
          },
          {
            phase: "Impact",
            technique: "Network Denial of Service",
            mitreId: "T1498",
            description: "Multi-vector DDoS including SYN flood, UDP amplification, and HTTP flood",
            indicators: [
              "Sudden spike in inbound traffic (100x normal)",
              "High connection rate",
              "Incomplete TCP handshakes",
              "DNS amplification patterns",
            ],
          },
        ],
        defenses: [
          {
            layer: "Network",
            control: "Rate limiting",
            effectiveness: "Medium",
            implementation: "Configure connection limits per source IP",
          },
          {
            layer: "Infrastructure",
            control: "CDN & DDoS protection",
            effectiveness: "High",
            implementation: "Enable cloud-based DDoS mitigation service",
          },
          {
            layer: "Application",
            control: "WAF rules",
            effectiveness: "Medium",
            implementation: "Deploy Web Application Firewall with anti-DDoS rules",
          },
        ],
      },
      data_breach: {
        description: `Data exfiltration incident in ${environment} environment`,
        objectives: [
          "Identify compromised data",
          "Trace exfiltration methods",
          "Determine breach timeline",
          "Assess legal and compliance impacts",
        ],
        mitreTactics: [
          "TA0001 - Initial Access",
          "TA0003 - Persistence",
          "TA0009 - Collection",
          "TA0010 - Exfiltration",
        ],
        attackVectors: [
          {
            phase: "Initial Access",
            technique: "Valid Accounts",
            mitreId: "T1078",
            description: "Compromised database administrator credentials from dark web breach",
            indicators: ["Login from unusual location", "Access outside business hours"],
          },
          {
            phase: "Collection",
            technique: "Data from Information Repositories",
            mitreId: "T1213",
            description: "SQL queries extracting customer PII from production database",
            indicators: [
              "Unusual database queries",
              "Large result sets",
              "SELECT statements with no WHERE clause",
            ],
          },
          {
            phase: "Exfiltration",
            technique: "Exfiltration Over Web Service",
            mitreId: "T1567",
            description: "Data uploaded to attacker-controlled cloud storage",
            indicators: [
              "Large outbound data transfers",
              "Connections to file-sharing services",
              "Encrypted traffic to unknown destinations",
            ],
          },
        ],
        defenses: [
          {
            layer: "Data Security",
            control: "Data Loss Prevention (DLP)",
            effectiveness: "High",
            implementation: "Deploy DLP policies to monitor and block sensitive data transfers",
          },
          {
            layer: "Database Security",
            control: "Database Activity Monitoring",
            effectiveness: "High",
            implementation: "Implement DAM solution to detect anomalous queries",
          },
          {
            layer: "Access Control",
            control: "Least privilege",
            effectiveness: "High",
            implementation: "Restrict database access to only necessary personnel",
          },
        ],
      },
      insider_threat: {
        description: `Malicious insider activity detected in ${environment}`,
        objectives: [
          "Identify insider threat indicators",
          "Investigate user behavior anomalies",
          "Preserve evidence for investigation",
          "Implement insider threat controls",
        ],
        mitreTactics: [
          "TA0009 - Collection",
          "TA0010 - Exfiltration",
        ],
        attackVectors: [
          {
            phase: "Collection",
            technique: "Data Staged",
            mitreId: "T1074",
            description: "Employee stages proprietary source code to personal USB drive",
            indicators: [
              "Large file copies to removable media",
              "Access to repositories outside normal duties",
              "Downloads during resignation period",
            ],
          },
          {
            phase: "Exfiltration",
            technique: "Exfiltration Over Physical Medium",
            mitreId: "T1052",
            description: "Data transferred via unauthorized USB device",
            indicators: [
              "USB device registration events",
              "File system events on removable storage",
              "Badge access logs showing late-night presence",
            ],
          },
        ],
        defenses: [
          {
            layer: "Endpoint",
            control: "USB device control",
            effectiveness: "High",
            implementation: "Whitelist approved USB devices, block all others",
          },
          {
            layer: "Monitoring",
            control: "User Behavior Analytics (UBA)",
            effectiveness: "Medium",
            implementation: "Deploy UEBA to detect anomalous user activity",
          },
          {
            layer: "Policy",
            control: "Off-boarding procedures",
            effectiveness: "Medium",
            implementation: "Revoke access immediately upon termination notice",
          },
        ],
      },
      apt: {
        description: `Advanced Persistent Threat campaign targeting ${environment} infrastructure`,
        objectives: [
          "Identify threat actor TTPs",
          "Map attack kill chain",
          "Discover persistence mechanisms",
          "Attribute attack to threat group",
          "Complete threat eradication",
        ],
        mitreTactics: [
          "TA0001 - Initial Access",
          "TA0002 - Execution",
          "TA0003 - Persistence",
          "TA0004 - Privilege Escalation",
          "TA0005 - Defense Evasion",
          "TA0006 - Credential Access",
          "TA0007 - Discovery",
          "TA0008 - Lateral Movement",
          "TA0009 - Collection",
          "TA0011 - Command and Control",
        ],
        attackVectors: [
          {
            phase: "Initial Compromise",
            technique: "Spearphishing Link",
            mitreId: "T1566.002",
            description: "Targeted spearphishing with link to watering hole site",
            indicators: [
              "Email from compromised partner organization",
              "Malicious JavaScript on legitimate-looking site",
              "Browser exploitation attempt",
            ],
          },
          {
            phase: "Persistence",
            technique: "Boot or Logon Autostart Execution",
            mitreId: "T1547",
            description: "Registry Run key modification for persistence",
            indicators: [
              "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run modifications",
              "Scheduled task creation",
              "WMI event subscription",
            ],
          },
          {
            phase: "Credential Access",
            technique: "OS Credential Dumping: LSASS Memory",
            mitreId: "T1003.001",
            description: "Memory dump of LSASS process to extract credentials",
            indicators: [
              "LSASS access by unusual process",
              "MiniDumpWriteDump API calls",
              "Suspicious PowerShell activity",
            ],
          },
          {
            phase: "Lateral Movement",
            technique: "Remote Services: RDP",
            mitreId: "T1021.001",
            description: "RDP connections using stolen credentials",
            indicators: [
              "RDP connections between workstations",
              "Unusual Terminal Services activity",
              "Port 3389 traffic on internal network",
            ],
          },
          {
            phase: "Command and Control",
            technique: "Application Layer Protocol: DNS",
            mitreId: "T1071.004",
            description: "DNS tunneling for C2 communications",
            indicators: [
              "High volume DNS queries to single domain",
              "Unusual DNS query patterns",
              "Long DNS TXT record responses",
            ],
          },
          {
            phase: "Collection",
            technique: "Archive Collected Data",
            mitreId: "T1560",
            description: "Intellectual property archived and encrypted for exfiltration",
            indicators: [
              "RAR or 7z compression of sensitive files",
              "Password-protected archives",
              "Large files in temporary directories",
            ],
          },
        ],
        defenses: [
          {
            layer: "Network",
            control: "Network traffic analysis",
            effectiveness: "High",
            implementation: "Deploy NTA solution to detect C2 beaconing patterns",
          },
          {
            layer: "Endpoint",
            control: "EDR with threat hunting",
            effectiveness: "Critical",
            implementation: "Continuous monitoring and proactive threat hunting",
          },
          {
            layer: "Identity",
            control: "Credential protection",
            effectiveness: "High",
            implementation: "Implement Credential Guard and Protected Process Light",
          },
          {
            layer: "Intelligence",
            control: "Threat intelligence integration",
            effectiveness: "Medium",
            implementation: "Integrate IOC feeds and known APT TTPs into security tools",
          },
        ],
      },
    };

    const template = templates[type] || templates.phishing;
    
    const timeline = this.generateTimeline(type, difficulty);
    const hints = this.generateHints(type, difficulty);

    return {
      id,
      type,
      difficulty,
      environment,
      sector,
      description: this.buildScenarioDescription(
        template.description,
        profile,
        sector,
        targetedCves,
        pluginInsights
      ),
      objectives: this.applyObjectiveContext(
        template.objectives,
        profile,
        sector,
        pluginInsights
      ),
      attackVectors: this.applyAttackVectorContext(template.attackVectors, profile, targetedCves),
      defenses: template.defenses,
      timeline,
      successCriteria: this.generateSuccessCriteria(type, difficulty),
      hints,
      mitreTactics: this.mergeMitreTactics(template.mitreTactics, profile),
      adversaryProfile: profile,
      threatIntel: this.composeThreatIntelSnapshot(profile, targetedCves, pluginInsights),
      targetedCves,
    };
  }

  private resolveAdversaryProfile(
    type: string,
    sector: string,
    explicitKey?: string
  ): AdversaryProfile | undefined {
    if (explicitKey) {
      return getAdversaryProfile(explicitKey) || undefined;
    }

    const normalizedSector = this.normalizeSector(sector);
    const profiles = listAdversaryProfiles();
    const sectorMatch = profiles.find((profile) =>
      profile.targetSectors
        .map((sectorKey) => this.normalizeSector(sectorKey))
        .includes(normalizedSector)
    );
    if (sectorMatch) {
      return sectorMatch;
    }

    if (type === "apt" || type === "data_breach") {
      return getAdversaryProfile("apt29");
    }

    if (type === "ransomware" || type === "insider_threat") {
      return getAdversaryProfile("fin7");
    }

    return undefined;
  }

  private resolveTargetedCves(
    profile: AdversaryProfile | undefined,
    cveFocus: string[] | undefined,
    pluginInsights: ThreatIntelContribution[]
  ): string[] {
    const cves = new Set<string>();
    profile?.exploitCves.forEach((cve) => cves.add(cve));
    cveFocus?.forEach((cve) => cves.add(cve.toUpperCase()));
    pluginInsights.forEach((insight) => {
      insight.cves.forEach((cve) => cves.add(cve.toUpperCase()));
    });
    return Array.from(cves);
  }

  private composeThreatIntelSnapshot(
    profile: AdversaryProfile | undefined,
    targetedCves: string[],
    pluginInsights: ThreatIntelContribution[]
  ): ThreatIntelSnapshot {
    if (profile) {
      const pluginDetection = pluginInsights.flatMap((insight) => insight.detectionEnhancements);
      return {
        actor: profile.alias[0] || profile.id,
        aliases: profile.alias,
        motivation: profile.motivation,
        region: profile.region,
        recentCampaigns: profile.recentCampaigns,
        exploitCves: targetedCves,
        preferredTactics: profile.preferredTactics,
        intelligenceDate: profile.lastUpdated,
        detectionOpportunities: Array.from(
          new Set([...profile.detectionOpportunities, ...pluginDetection])
        ),
        countermeasures: profile.countermeasures,
        references: profile.references,
        pluginInsights,
      };
    }

    return {
      actor: "Simulated Adversary",
      aliases: [],
      motivation: "Training",
      region: "Global",
      recentCampaigns: ["Composite scenario generated for lab purposes"],
      exploitCves: targetedCves,
      preferredTactics: ["TA0001", "TA0002", "TA0003"],
      intelligenceDate: new Date().toISOString().split("T")[0],
      detectionOpportunities: [
        "Validate security monitoring against baseline attack chain",
        "Capture telemetry for hunt templates",
      ],
      countermeasures: [
        "Ensure multi-layered detections for MITRE ATT&CK coverage",
        "Review tabletop outputs with detection engineering team",
      ],
      references: [],
      pluginInsights,
    };
  }

  private buildScenarioDescription(
    baseDescription: string,
    profile: AdversaryProfile | undefined,
    sector: string,
    targetedCves: string[],
    pluginInsights: ThreatIntelContribution[]
  ): string {
    const sectorBlurb = ` Focus: ${sector} sector operations.`;
    const profileBlurb = profile
      ? ` Modeled on adversary playbook ${profile.alias[0] || profile.id.toUpperCase()}.`
      : "";
    const cveBlurb = targetedCves.length
      ? ` CVE emphasis: ${targetedCves.join(", ")}.`
      : "";
    const pluginBlurb = pluginInsights.length
      ? ` Plugin intel from ${pluginInsights.map((insight) => insight.providerName).join(", ")}.`
      : "";
    return `${baseDescription}${sectorBlurb}${profileBlurb}${cveBlurb}${pluginBlurb}`.trim();
  }

  private applyObjectiveContext(
    objectives: string[],
    profile: AdversaryProfile | undefined,
    sector: string,
    pluginInsights: ThreatIntelContribution[]
  ): string[] {
    const contextualObjectives = [...objectives];
    if (profile) {
      contextualObjectives.push(
        `Map detections to ${profile.alias[0] || profile.id.toUpperCase()} TTPs across the kill chain.`
      );
    }
    contextualObjectives.push(`Capture sector-specific playbook adjustments for ${sector}.`);
    pluginInsights.forEach((insight) => {
      contextualObjectives.push(`Apply ${insight.providerName} detection enhancements during the drill.`);
    });
    return Array.from(new Set(contextualObjectives));
  }

  private applyAttackVectorContext(
    attackVectors: AttackVector[],
    profile: AdversaryProfile | undefined,
    targetedCves: string[]
  ): AttackVector[] {
    const primaryCve = targetedCves[0];
    return attackVectors.map((vector) => {
      let description = vector.description;
      if (primaryCve) {
        description = description.replace(/CVE-\d{4}-XXXXX/g, primaryCve);
      }

      if (profile) {
        description = `${description} (Aligned with ${profile.alias[0] || profile.id.toUpperCase()} playbook).`;
      }

      const indicators = Array.from(
        new Set([
          ...vector.indicators,
          ...(primaryCve ? [`Exploit targeting ${primaryCve}`] : []),
        ])
      );

      return {
        ...vector,
        description,
        indicators,
      };
    });
  }

  private mergeMitreTactics(
    baseTactics: string[],
    profile: AdversaryProfile | undefined
  ): string[] {
    if (!profile) {
      return baseTactics;
    }

    const enriched = new Set(baseTactics);
    profile.preferredTactics.forEach((tacticId) => {
      const alreadyPresent = Array.from(enriched).some((entry) => entry.startsWith(`${tacticId} `) || entry === tacticId);
      if (!alreadyPresent) {
        enriched.add(`${tacticId} - Actor-preferred tactic`);
      }
    });

    return Array.from(enriched);
  }

  private normalizeSector(sector: string): string {
    return sector.trim().toLowerCase().replace(/[^a-z0-9]+/g, "_");
  }

  private generateTimeline(type: string, difficulty: string): TimelineEvent[] {
    const now = new Date();
    const events: TimelineEvent[] = [];

    // Generate realistic timeline based on attack type
    const timeOffsets = difficulty === "beginner" ? [0, 15, 30, 45, 60] : [0, 30, 120, 240, 480];

    timeOffsets.forEach((offset, index) => {
      const timestamp = new Date(now.getTime() - offset * 60000).toISOString();
      events.push({
        timestamp,
        event: `Phase ${index + 1} activity detected`,
        severity: index > 2 ? "High" : "Medium",
        details: `Attack progression event #${index + 1}`,
      });
    });

    return events.reverse();
  }

  private generateHints(type: string, difficulty: string): Hint[] {
    const hintSets: Record<string, string[]> = {
      phishing: [
        "Check the sender's email domain carefully",
        "Look for urgency-based language in the message",
        "Examine any attachments for suspicious file types",
        "Review email headers for authentication failures",
      ],
      ransomware: [
        "Check for unusual process execution patterns",
        "Look for mass file encryption activity",
        "Examine network traffic for C2 communications",
        "Review backup integrity and availability",
      ],
      ddos: [
        "Monitor network bandwidth utilization",
        "Check for abnormal connection rates",
        "Analyze source IP distribution",
        "Review DNS query patterns",
      ],
    };

    const hints = hintSets[type] || hintSets.phishing;
    const numHints = difficulty === "beginner" ? 4 : difficulty === "intermediate" ? 3 : 2;

    return hints.slice(0, numHints).map((content, index) => ({
      level: index + 1,
      content,
      revealCondition: `After ${(index + 1) * 5} minutes of investigation`,
    }));
  }

  private generateSuccessCriteria(type: string, difficulty: string): string[] {
    const baseCriteria = [
      "Identify initial attack vector",
      "Document all indicators of compromise",
      "Implement immediate containment measures",
      "Generate comprehensive incident report",
    ];

    if (difficulty === "advanced" || difficulty === "expert") {
      baseCriteria.push(
        "Attribute attack to specific threat actor or group",
        "Develop detection rules for future prevention",
        "Conduct root cause analysis"
      );
    }

    return baseCriteria;
  }

  getScenario(scenarioId: string): SecurityScenario | undefined {
    return this.scenarios.get(scenarioId);
  }

  listScenarios(): SecurityScenario[] {
    return Array.from(this.scenarios.values());
  }
}
