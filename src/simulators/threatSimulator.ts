export interface AttackSimulationResult {
  simulationId: string;
  attackType: string;
  target: string;
  intensity: string;
  startTime: string;
  endTime: string;
  status: string;
  stopReason?: string;
  terminatedAt?: string;
  phases: AttackPhase[];
  commandChain: CommandChainEntry[];
  iocs: IOC[];
  detectionRate: number;
  impactAssessment: ImpactAssessment;
  mitreAttackMapping: MitreMapping[];
}

export interface AttackPhase {
  phase: string;
  startTime: string;
  duration: number;
  techniques: Technique[];
  success: boolean;
  detectedBy: string[];
  artifacts: Artifact[];
  commandChain: CommandChainEntry[];
}

export interface CommandChainEntry {
  phase: string;
  step: number;
  pseudoCommand: string;
  description: string;
  safeguards: string[];
  techniqueRef?: string;
}

export interface Technique {
  name: string;
  mitreId: string;
  description: string;
  executed: boolean;
  detected: boolean;
  detectionMethod?: string;
}

export interface Artifact {
  type: string;
  location: string;
  content: string;
  timestamp: string;
}

export interface IOC {
  type: string;
  value: string;
  severity: string;
  firstSeen: string;
  tlp: string; // Traffic Light Protocol
}

export interface ImpactAssessment {
  scope: string;
  affectedAssets: string[];
  dataCompromised: boolean;
  estimatedDowntime: number;
  financialImpact: string;
  reputationalImpact: string;
}

export interface MitreMapping {
  tactic: string;
  technique: string;
  techniqueId: string;
  subtechnique?: string;
}

export class ThreatSimulator {
  private activeSimulations: Map<string, AttackSimulationResult> = new Map();
  private readonly commandChainLibrary: Record<
    string,
    Record<
      string,
      { pseudoCommand: string; description: string; safeguards: string[]; technique?: string }[]
    >
  > = {
    ransomware: {
      "Initial Access": [
        {
          pseudoCommand: "send-phish --template=ransomware_notice.eml --attachment=[SIMULATED_PAYLOAD]",
          description: "Deliver crafted phishing email with ransomware dropper",
          safeguards: ["Email sandboxing", "DMARC enforcement"],
          technique: "T1566.001",
        },
        {
          pseudoCommand: "inject-vpn --target=gateway --exploit=CVE-2023-27997",
          description: "Test perimeter appliance exploit as alternate ingress",
          safeguards: ["Virtual patching", "Perimeter anomaly detection"],
          technique: "T1190",
        },
      ],
      Execution: [
        {
          pseudoCommand: "powershell -enc [SIMULATED_PAYLOAD]",
          description: "Execute launcher via encoded PowerShell",
          safeguards: ["Script block logging", "EDR command-line policy"],
          technique: "T1059.001",
        },
        {
          pseudoCommand: "rundll32.exe payload.dll,EntryPoint",
          description: "Load ransomware core through LOLBIN invocation",
          safeguards: ["Application control", "Command-line monitoring"],
          technique: "T1218.011",
        },
      ],
      "Credential Access": [
        {
          pseudoCommand: "procdump64.exe -ma lsass.exe C:\\Temp\\lsass.dmp",
          description: "Dump credentials from LSASS memory",
          safeguards: ["Credential Guard", "Process access auditing"],
          technique: "T1003.001",
        },
      ],
      "Lateral Movement": [
        {
          pseudoCommand: "wmic /node:FILESERVER process call create C:\\Windows\\Temp\\payload.exe",
          description: "Launch payload remotely through WMI",
          safeguards: ["WMI logging", "Remote execution restrictions"],
          technique: "T1047",
        },
        {
          pseudoCommand: "net use \\\\FILESERVER\\C$ /user:DOMAIN\\admin [REDACTED] && copy payload.exe \\\\FILESERVER\\C$\\temp\\",
          description: "Copy binary via admin shares for lateral deployment",
          safeguards: ["Admin share monitoring", "Just-in-time access"],
          technique: "T1021.002",
        },
      ],
      Impact: [
        {
          pseudoCommand: "vssadmin Delete Shadows /All /Quiet",
          description: "Remove Volume Shadow Copies to inhibit recovery",
          safeguards: ["Shadow copy monitoring", "Ransomware canary"],
          technique: "T1490",
        },
        {
          pseudoCommand: "encryptor.exe --scope=//corp/share --mode=aes256",
          description: "Simulate mass encryption across network shares",
          safeguards: ["File integrity monitoring", "Network segmentation"],
          technique: "T1486",
        },
      ],
    },
    apt: {
      Reconnaissance: [
        {
          pseudoCommand: "masscan 0.0.0.0/0 -p22,80,443,445 --rate 1000",
          description: "Enumerate exposed services at scale",
          safeguards: ["Egress monitoring", "Threat intelligence correlation"],
          technique: "T1595",
        },
        {
          pseudoCommand: "harvest-profiles --platform=linkedin --org='Target Corp'",
          description: "Collect personnel metadata for spearphishing",
          safeguards: ["Brand monitoring", "Awareness training"],
          technique: "T1589",
        },
      ],
      "Initial Compromise": [
        {
          pseudoCommand: "exploit-cve --id=CVE-2023-42793 --target=https://portal.target.example",
          description: "Exploit remote code execution in portal service",
          safeguards: ["Virtual patching", "WAF behavioral rules"],
          technique: "T1190",
        },
      ],
      "Establish Foothold": [
        {
          pseudoCommand: "upload-webshell --path=/var/www/html/.cache.php --payload=[SIMULATED_PAYLOAD]",
          description: "Plant web shell for follow-on operations",
          safeguards: ["Integrity monitoring", "Web directory allowlists"],
          technique: "T1505.003",
        },
      ],
      "Command and Control": [
        {
          pseudoCommand: "beacon --protocol=dns --profile=low-slow --domain=cdn.example",
          description: "Maintain covert DNS-based C2 channel",
          safeguards: ["DNS analytics", "Beaconing detection"],
          technique: "T1071.004",
        },
      ],
      "Credential Access": [
        {
          pseudoCommand: "invoke-mimikatz --module=sekurlsa::logonpasswords",
          description: "Harvest credentials from memory using credential tool",
          safeguards: ["Application control", "LSASS protection"],
          technique: "T1003.001",
        },
      ],
      "Lateral Movement": [
        {
          pseudoCommand: "wmiexec.py domain\\admin@[SIMULATED_HOST]",
          description: "Pivot into additional hosts using remote service execution",
          safeguards: ["WMI command auditing", "Network segmentation"],
          technique: "T1047",
        },
      ],
    },
    ddos: {
      "Botnet Coordination": [
        {
          pseudoCommand: "botnet-controller --issue 'prep flood udp 203.0.113.10 80 120s'",
          description: "Prime botnet nodes for upcoming flood",
          safeguards: ["Botnet sinkholing", "Traffic rate limiting"],
          technique: "T1584.005",
        },
      ],
      "Traffic Flood": [
        {
          pseudoCommand: "launch-flood --type=syn --pps=500000 --duration=600",
          description: "Simulate high-volume SYN flood",
          safeguards: ["Adaptive rate limiting", "SYN cookies"],
          technique: "T1498",
        },
        {
          pseudoCommand: "invoke-amplification --vector=dns --reflectors=list.txt",
          description: "Trigger DNS amplification using reflector list",
          safeguards: ["DNS response rate limiting", "Upstream scrubbing"],
          technique: "T1498.002",
        },
      ],
    },
    default: {
      default: [
        {
          pseudoCommand: "simulate-step --phase=[PHASE] --detail=[REDACTED]",
          description: "Generic simulated command placeholder",
          safeguards: ["Review logs", "Validate guardrails"],
        },
      ],
    },
  };

  async simulateAttack(
    attackType: string,
    target: string,
    intensity: string
  ): Promise<AttackSimulationResult> {
    const simulationId = `SIM-${Date.now()}`;
    const startTime = new Date().toISOString();

    const phases = this.generateAttackPhases(attackType, intensity);
    const iocs = this.generateIOCs(attackType, phases);
    const detectionRate = this.calculateDetectionRate(phases, intensity);
    const impactAssessment = this.assessImpact(attackType, target, intensity);
    const mitreMapping = this.mapToMitreAttack(attackType, phases);
    const commandChain = phases.flatMap((phase) => phase.commandChain);

    // Simulate attack duration based on intensity
    const durationMinutes = intensity === "low" ? 30 : intensity === "medium" ? 60 : intensity === "high" ? 120 : 240;
    const endTime = new Date(Date.now() + durationMinutes * 60000).toISOString();

    const result: AttackSimulationResult = {
      simulationId,
      attackType,
      target,
      intensity,
      startTime,
      endTime,
      status: "Active",
      phases,
      commandChain,
      iocs,
      detectionRate,
      impactAssessment,
      mitreAttackMapping: mitreMapping,
    };

    this.activeSimulations.set(simulationId, result);
    return result;
  }

  private generateAttackPhases(attackType: string, intensity: string): AttackPhase[] {
    type PhaseTemplate = Omit<AttackPhase, "commandChain">;
    const phaseTemplates: Record<string, PhaseTemplate[]> = {
      ransomware: [
        {
          phase: "Initial Access",
          startTime: new Date().toISOString(),
          duration: 300,
          techniques: [
            {
              name: "Phishing Email",
              mitreId: "T1566.001",
              description: "Spearphishing attachment containing malicious macro",
              executed: true,
              detected: intensity !== "critical",
              detectionMethod: intensity !== "critical" ? "Email gateway sandbox" : undefined,
            },
          ],
          success: true,
          detectedBy: intensity !== "critical" ? ["Email Security Gateway"] : [],
          artifacts: [
            {
              type: "Email",
              location: "user@company.com inbox",
              content: "Subject: Urgent - Q4 Financial Report [malicious_doc.docm attached]",
              timestamp: new Date().toISOString(),
            },
          ],
        },
        {
          phase: "Execution",
          startTime: new Date(Date.now() + 300000).toISOString(),
          duration: 180,
          techniques: [
            {
              name: "User Execution",
              mitreId: "T1204.002",
              description: "User opens malicious document and enables macros",
              executed: true,
              detected: intensity === "low",
              detectionMethod: intensity === "low" ? "Endpoint protection" : undefined,
            },
            {
              name: "PowerShell",
              mitreId: "T1059.001",
              description: "Macro executes obfuscated PowerShell payload",
              executed: true,
              detected: intensity !== "critical",
              detectionMethod: intensity !== "critical" ? "PowerShell logging" : undefined,
            },
          ],
          success: true,
          detectedBy: intensity === "low" ? ["EDR"] : [],
          artifacts: [
            {
              type: "Process",
              location: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              content: "powershell.exe -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMgA=",
              timestamp: new Date(Date.now() + 300000).toISOString(),
            },
          ],
        },
        {
          phase: "Persistence",
          startTime: new Date(Date.now() + 480000).toISOString(),
          duration: 120,
          techniques: [
            {
              name: "Registry Run Keys",
              mitreId: "T1547.001",
              description: "Malware establishes persistence via registry Run key",
              executed: true,
              detected: intensity === "low" || intensity === "medium",
              detectionMethod: intensity === "low" || intensity === "medium" ? "Registry monitoring" : undefined,
            },
          ],
          success: true,
          detectedBy: intensity === "low" || intensity === "medium" ? ["EDR", "SIEM"] : [],
          artifacts: [
            {
              type: "Registry",
              location: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
              content: "SecurityUpdate: C:\\Users\\Public\\svchost.exe",
              timestamp: new Date(Date.now() + 480000).toISOString(),
            },
          ],
        },
        {
          phase: "Credential Access",
          startTime: new Date(Date.now() + 600000).toISOString(),
          duration: 300,
          techniques: [
            {
              name: "LSASS Memory Dumping",
              mitreId: "T1003.001",
              description: "Credential dumping from LSASS process memory",
              executed: true,
              detected: intensity !== "critical",
              detectionMethod: intensity !== "critical" ? "Credential Guard" : undefined,
            },
          ],
          success: intensity === "high" || intensity === "critical",
          detectedBy: intensity === "low" || intensity === "medium" ? ["EDR", "Credential Guard"] : [],
          artifacts: [
            {
              type: "File",
              location: "C:\\Windows\\Temp\\lsass.dmp",
              content: "[Binary memory dump]",
              timestamp: new Date(Date.now() + 600000).toISOString(),
            },
          ],
        },
        {
          phase: "Lateral Movement",
          startTime: new Date(Date.now() + 900000).toISOString(),
          duration: 600,
          techniques: [
            {
              name: "SMB/Admin Shares",
              mitreId: "T1021.002",
              description: "Lateral spread via administrative shares using stolen credentials",
              executed: intensity === "high" || intensity === "critical",
              detected: intensity === "low" || intensity === "medium",
              detectionMethod: intensity === "low" || intensity === "medium" ? "Network monitoring" : undefined,
            },
          ],
          success: intensity === "high" || intensity === "critical",
          detectedBy: intensity === "low" || intensity === "medium" ? ["Network IDS", "SIEM"] : [],
          artifacts: [
            {
              type: "Network",
              location: "SMB connections to \\\\FILESERVER\\C$",
              content: "Multiple admin share connections from WORKSTATION01",
              timestamp: new Date(Date.now() + 900000).toISOString(),
            },
          ],
        },
        {
          phase: "Impact",
          startTime: new Date(Date.now() + 1500000).toISOString(),
          duration: 1800,
          techniques: [
            {
              name: "Data Encrypted for Impact",
              mitreId: "T1486",
              description: "Mass file encryption across network using AES-256",
              executed: true,
              detected: true,
              detectionMethod: "Behavioral analysis - mass file modifications",
            },
            {
              name: "Inhibit System Recovery",
              mitreId: "T1490",
              description: "Deletion of volume shadow copies",
              executed: true,
              detected: intensity !== "critical",
              detectionMethod: intensity !== "critical" ? "SIEM alert" : undefined,
            },
          ],
          success: true,
          detectedBy: ["EDR", "File Integrity Monitoring", "SIEM"],
          artifacts: [
            {
              type: "File",
              location: "C:\\Users\\*\\Desktop\\README_FOR_DECRYPT.txt",
              content: "Your files have been encrypted. Contact restore@protonmail.com with ID: XYZ123",
              timestamp: new Date(Date.now() + 1500000).toISOString(),
            },
            {
              type: "Command",
              location: "Command line",
              content: "vssadmin.exe Delete Shadows /All /Quiet",
              timestamp: new Date(Date.now() + 1500000).toISOString(),
            },
          ],
        },
      ],
      apt: [
        {
          phase: "Reconnaissance",
          startTime: new Date().toISOString(),
          duration: 3600,
          techniques: [
            {
              name: "Active Scanning",
              mitreId: "T1595.001",
              description: "Port scanning and service enumeration of target network",
              executed: true,
              detected: intensity === "low",
              detectionMethod: intensity === "low" ? "IDS" : undefined,
            },
            {
              name: "Gather Victim Identity Information",
              mitreId: "T1589",
              description: "OSINT gathering via LinkedIn and social media",
              executed: true,
              detected: false,
            },
          ],
          success: true,
          detectedBy: intensity === "low" ? ["IDS"] : [],
          artifacts: [
            {
              type: "Network",
              location: "Firewall logs",
              content: "Port scan detected from 203.0.113.42: ports 22,80,443,445,3389",
              timestamp: new Date().toISOString(),
            },
          ],
        },
        {
          phase: "Initial Compromise",
          startTime: new Date(Date.now() + 3600000).toISOString(),
          duration: 600,
          techniques: [
            {
              name: "Exploit Public-Facing Application",
              mitreId: "T1190",
              description: "Exploitation of CVE-2023-XXXXX in web application",
              executed: true,
              detected: intensity !== "critical",
              detectionMethod: intensity !== "critical" ? "WAF" : undefined,
            },
          ],
          success: true,
          detectedBy: intensity === "low" || intensity === "medium" ? ["WAF", "IDS"] : [],
          artifacts: [
            {
              type: "Web Log",
              location: "/var/log/apache2/access.log",
              content: "POST /api/upload HTTP/1.1 [payload: webshell.php]",
              timestamp: new Date(Date.now() + 3600000).toISOString(),
            },
          ],
        },
        {
          phase: "Establish Foothold",
          startTime: new Date(Date.now() + 4200000).toISOString(),
          duration: 300,
          techniques: [
            {
              name: "Web Shell",
              mitreId: "T1505.003",
              description: "Deployment of PHP webshell for persistent access",
              executed: true,
              detected: intensity === "low",
              detectionMethod: intensity === "low" ? "File integrity monitoring" : undefined,
            },
          ],
          success: true,
          detectedBy: intensity === "low" ? ["FIM", "EDR"] : [],
          artifacts: [
            {
              type: "File",
              location: "/var/www/html/uploads/image.php",
              content: "<?php @eval($_POST['cmd']); ?>",
              timestamp: new Date(Date.now() + 4200000).toISOString(),
            },
          ],
        },
        {
          phase: "Command and Control",
          startTime: new Date(Date.now() + 4500000).toISOString(),
          duration: 600,
          techniques: [
            {
              name: "DNS Tunneling",
              mitreId: "T1071.004",
              description: "DNS-based C2 channel using subdomain encoding",
              executed: true,
              detected: intensity !== "critical",
              detectionMethod: intensity !== "critical" ? "DNS security" : undefined,
            },
          ],
          success: true,
          detectedBy: intensity === "low" || intensity === "medium" ? ["DNS Security", "Network Monitor"] : [],
          artifacts: [
            {
              type: "DNS Query",
              location: "DNS logs",
              content: "Query: ZGF0YS5leGZpbC5jMnNlcnZlci5jb20 (base64 encoded data)",
              timestamp: new Date(Date.now() + 4500000).toISOString(),
            },
          ],
        },
      ],
      ddos: [
        {
          phase: "Botnet Coordination",
          startTime: new Date().toISOString(),
          duration: 300,
          techniques: [
            {
              name: "Botnet Command",
              mitreId: "T1584.005",
              description: "C2 server coordinates 50,000 compromised IoT devices",
              executed: true,
              detected: false,
            },
          ],
          success: true,
          detectedBy: [],
          artifacts: [
            {
              type: "Intelligence",
              location: "Threat intel feed",
              content: "Botnet C2: 198.51.100.42 orchestrating attack",
              timestamp: new Date().toISOString(),
            },
          ],
        },
        {
          phase: "Attack Launch",
          startTime: new Date(Date.now() + 300000).toISOString(),
          duration: 3600,
          techniques: [
            {
              name: "Network Flood",
              mitreId: "T1498.001",
              description: "Multi-vector DDoS: SYN flood + UDP amplification + HTTP flood",
              executed: true,
              detected: true,
              detectionMethod: "DDoS protection service",
            },
          ],
          success: intensity === "high" || intensity === "critical",
          detectedBy: ["DDoS Protection", "Network Monitoring"],
          artifacts: [
            {
              type: "Network",
              location: "Network metrics",
              content: "Traffic spike: 450 Gbps inbound (normal: 5 Gbps)",
              timestamp: new Date(Date.now() + 300000).toISOString(),
            },
          ],
        },
      ],
    };

    const templates = phaseTemplates[attackType] || phaseTemplates.ransomware;
    let commandStep = 1;

    return templates.map((phase) => {
      const commandChain = this.generateCommandChainEntries(
        attackType,
        phase.phase,
        commandStep,
        phase.techniques
      );
      commandStep += Math.max(commandChain.length, 1);
      return {
        ...phase,
        commandChain,
      };
    });
  }

  private generateCommandChainEntries(
    attackType: string,
    phase: string,
    startStep: number,
    techniques: Technique[]
  ): CommandChainEntry[] {
    const typeKey = attackType.toLowerCase();
    const library = this.commandChainLibrary[typeKey] || this.commandChainLibrary.default;
    const entries =
      library[phase] || library.default || this.commandChainLibrary.default.default;

    return entries.map((entry, index) => ({
      phase,
      step: startStep + index,
      pseudoCommand: entry.pseudoCommand,
      description: entry.description,
      safeguards: entry.safeguards,
      techniqueRef: entry.technique || techniques[0]?.mitreId,
    }));
  }

  private generateIOCs(attackType: string, phases: AttackPhase[]): IOC[] {
    const iocs: IOC[] = [];

    phases.forEach((phase) => {
      phase.artifacts.forEach((artifact) => {
        // Extract IOCs from artifacts
        if (artifact.type === "Network" || artifact.type === "DNS Query") {
          const ipMatch = artifact.content.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
          if (ipMatch) {
            iocs.push({
              type: "IPv4",
              value: ipMatch[0],
              severity: "High",
              firstSeen: artifact.timestamp,
              tlp: "TLP:AMBER",
            });
          }

          const domainMatch = artifact.content.match(/([a-z0-9-]+\.)+[a-z]{2,}/i);
          if (domainMatch) {
            iocs.push({
              type: "Domain",
              value: domainMatch[0],
              severity: "High",
              firstSeen: artifact.timestamp,
              tlp: "TLP:AMBER",
            });
          }
        }

        if (artifact.type === "File") {
          const fileMatch = artifact.location.match(/[^\\\/]+\.(exe|dll|ps1|docm|php|jsp)$/i);
          if (fileMatch) {
            iocs.push({
              type: "Filename",
              value: fileMatch[0],
              severity: "Medium",
              firstSeen: artifact.timestamp,
              tlp: "TLP:AMBER",
            });
          }

          // Generate file hash IOC
          const hash = this.generateHash(artifact.location);
          iocs.push({
            type: "SHA256",
            value: hash,
            severity: "High",
            firstSeen: artifact.timestamp,
            tlp: "TLP:AMBER",
          });
        }

        if (artifact.type === "Registry") {
          iocs.push({
            type: "Registry Key",
            value: artifact.location,
            severity: "Medium",
            firstSeen: artifact.timestamp,
            tlp: "TLP:GREEN",
          });
        }
      });
    });

    return iocs;
  }

  private generateHash(input: string): string {
    // Simple hash generation for simulation purposes
    let hash = "";
    for (let i = 0; i < 64; i++) {
      hash += Math.floor(Math.random() * 16).toString(16);
    }
    return hash;
  }

  private calculateDetectionRate(phases: AttackPhase[], intensity: string): number {
    let totalTechniques = 0;
    let detectedTechniques = 0;

    phases.forEach((phase) => {
      phase.techniques.forEach((technique) => {
        totalTechniques++;
        if (technique.detected) {
          detectedTechniques++;
        }
      });
    });

    const baseRate = totalTechniques > 0 ? (detectedTechniques / totalTechniques) * 100 : 0;
    
    // Adjust for intensity
    const intensityModifier = {
      low: 1.2,
      medium: 1.0,
      high: 0.8,
      critical: 0.6,
    };

    return Math.min(100, Math.round(baseRate * intensityModifier[intensity as keyof typeof intensityModifier]));
  }

  private assessImpact(attackType: string, target: string, intensity: string): ImpactAssessment {
    const impactTemplates: Record<string, Partial<ImpactAssessment>> = {
      ransomware: {
        scope: intensity === "critical" ? "Enterprise-wide" : intensity === "high" ? "Multiple departments" : "Single department",
        dataCompromised: true,
        estimatedDowntime: intensity === "critical" ? 72 : intensity === "high" ? 48 : 24,
        financialImpact: intensity === "critical" ? "$5M - $10M" : intensity === "high" ? "$1M - $5M" : "$100K - $1M",
        reputationalImpact: "Severe - public disclosure required, customer trust impacted",
      },
      apt: {
        scope: "Targeted systems and data repositories",
        dataCompromised: true,
        estimatedDowntime: 0,
        financialImpact: "$500K - $2M (investigation and remediation costs)",
        reputationalImpact: "High - intellectual property theft, potential espionage implications",
      },
      ddos: {
        scope: "Public-facing services",
        dataCompromised: false,
        estimatedDowntime: intensity === "critical" ? 12 : intensity === "high" ? 6 : 2,
        financialImpact: intensity === "critical" ? "$500K - $1M" : "$50K - $500K",
        reputationalImpact: "Moderate - service availability impacted, customer experience degraded",
      },
      phishing: {
        scope: "Individual users and their access privileges",
        dataCompromised: true,
        estimatedDowntime: 0,
        financialImpact: "$50K - $250K",
        reputationalImpact: "Low to Moderate - depends on data accessed",
      },
      data_breach: {
        scope: "Customer PII and sensitive data",
        dataCompromised: true,
        estimatedDowntime: 0,
        financialImpact: "$2M - $10M (includes fines, legal costs, notification)",
        reputationalImpact: "Critical - regulatory penalties, loss of customer trust, brand damage",
      },
    };

    const template = impactTemplates[attackType] || impactTemplates.ransomware;

    return {
      scope: template.scope || "Unknown",
      affectedAssets: this.generateAffectedAssets(attackType, intensity),
      dataCompromised: template.dataCompromised || false,
      estimatedDowntime: template.estimatedDowntime || 0,
      financialImpact: template.financialImpact || "Unknown",
      reputationalImpact: template.reputationalImpact || "Unknown",
    };
  }

  private generateAffectedAssets(attackType: string, intensity: string): string[] {
    const assetCounts = {
      low: 5,
      medium: 15,
      high: 50,
      critical: 200,
    };

    const count = assetCounts[intensity as keyof typeof assetCounts] || 10;
    const assets: string[] = [];

    for (let i = 1; i <= Math.min(count, 10); i++) {
      assets.push(`${attackType === "ddos" ? "WEB-SERVER" : "WORKSTATION"}-${String(i).padStart(3, "0")}`);
    }

    if (count > 10) {
      assets.push(`... and ${count - 10} more assets`);
    }

    return assets;
  }

  private mapToMitreAttack(attackType: string, phases: AttackPhase[]): MitreMapping[] {
    const mappings: MitreMapping[] = [];

    phases.forEach((phase) => {
      phase.techniques.forEach((technique) => {
        // Parse MITRE ATT&CK ID to extract tactic
        const tacticMap: Record<string, string> = {
          T1566: "Initial Access",
          T1204: "Execution",
          T1059: "Execution",
          T1547: "Persistence",
          T1003: "Credential Access",
          T1021: "Lateral Movement",
          T1486: "Impact",
          T1490: "Impact",
          T1595: "Reconnaissance",
          T1589: "Reconnaissance",
          T1190: "Initial Access",
          T1505: "Persistence",
          T1071: "Command and Control",
          T1584: "Resource Development",
          T1498: "Impact",
        };

        const baseId = technique.mitreId.split(".")[0];
        const tactic = tacticMap[baseId] || "Unknown";

        mappings.push({
          tactic,
          technique: technique.name,
          techniqueId: technique.mitreId,
          subtechnique: technique.mitreId.includes(".") ? technique.mitreId.split(".")[1] : undefined,
        });
      });
    });

    return mappings;
  }

  stopSimulation(simulationId: string, reason?: string): AttackSimulationResult | null {
    const simulation = this.activeSimulations.get(simulationId);
    if (!simulation) {
      return null;
    }

    const terminatedAt = new Date().toISOString();
    const updated: AttackSimulationResult = {
      ...simulation,
      status: "Terminated",
      endTime: terminatedAt,
      terminatedAt,
      stopReason: reason || "manual_stop",
    };

    this.activeSimulations.delete(simulationId);
    return updated;
  }

  stopAllSimulations(reason?: string): AttackSimulationResult[] {
    const terminated: AttackSimulationResult[] = [];
    for (const simulationId of Array.from(this.activeSimulations.keys())) {
      const result = this.stopSimulation(simulationId, reason);
      if (result) {
        terminated.push(result);
      }
    }
    return terminated;
  }

  getSimulation(simulationId: string): AttackSimulationResult | undefined {
    return this.activeSimulations.get(simulationId);
  }

  listActiveSimulations(): AttackSimulationResult[] {
    return Array.from(this.activeSimulations.values()).filter((sim) => sim.status === "Active");
  }
}
