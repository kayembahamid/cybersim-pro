import type { ExecutionContext, ExecutionProvenance } from "../utils/executionContext.js";

export interface NetworkAnalysisResult {
  segmentId: string;
  duration: number;
  timestamp: string;
  statistics: NetworkStatistics;
  anomalies: Anomaly[];
  vulnerabilities: Vulnerability[];
  threats: ThreatIndicator[];
  recommendations: string[];
  topology: NetworkTopology;
  detectionArtifacts: DetectionArtifactSet;
  mitreHeatmap: MitreHeatmapEntry[];
  gapAnalysis: DetectionGap[];
  integrationHooks: IntegrationHook[];
  provenance?: ExecutionProvenance;
}

export interface NetworkStatistics {
  totalPackets: number;
  totalBytes: number;
  protocolDistribution: Record<string, number>;
  topTalkers: Connection[];
  bandwidthUtilization: number;
  packetLoss: number;
  averageLatency: number;
}

export interface Anomaly {
  type: string;
  severity: string;
  description: string;
  affectedHosts: string[];
  detectionTime: string;
  confidence: number;
}

export interface Vulnerability {
  cveId: string;
  severity: string;
  affectedAssets: string[];
  description: string;
  cvssScore: number;
  exploitable: boolean;
}

export interface ThreatIndicator {
  type: string;
  indicator: string;
  source: string;
  destination: string;
  protocol: string;
  description: string;
  mitreMapping: string;
}

export interface Connection {
  source: string;
  destination: string;
  port: number;
  protocol: string;
  bytes: number;
  packets: number;
  duration: number;
}

export interface NetworkTopology {
  nodes: NetworkNode[];
  connections: NetworkConnection[];
  segments: NetworkSegment[];
}

export interface NetworkNode {
  id: string;
  type: string;
  ipAddress: string;
  hostname: string;
  os: string;
  services: Service[];
  securityPosture: string;
}

export interface NetworkConnection {
  source: string;
  destination: string;
  connectionType: string;
  bandwidth: string;
}

export interface NetworkSegment {
  id: string;
  name: string;
  cidr: string;
  vlan: number;
  securityZone: string;
}

export interface Service {
  port: number;
  protocol: string;
  service: string;
  version: string;
  banner: string;
}

export interface DetectionArtifactSet {
  sigma: DetectionRuleArtifact[];
  splunk: DetectionRuleArtifact[];
  kql: DetectionRuleArtifact[];
  playbooks: DetectionPlaybook[];
}

export interface DetectionRuleArtifact {
  id: string;
  title: string;
  query: string;
  description: string;
  references: string[];
  tags: string[];
}

export interface DetectionPlaybook {
  name: string;
  focus: string;
  steps: string[];
}

export interface MitreHeatmapEntry {
  tactic: string;
  techniqueId: string;
  technique: string;
  coverage: "covered" | "partial" | "missing";
  detectionAsset?: string;
  d3fendMappings: string[];
}

export interface DetectionGap {
  area: string;
  severity: "low" | "medium" | "high";
  description: string;
  recommendations: string[];
}

export interface IntegrationHook {
  platform: string;
  type: string;
  description: string;
  configuration: Record<string, string>;
  samplePayload: Record<string, unknown>;
}

export class NetworkSimulator {
  private activeAnalyses: Map<string, NetworkAnalysisResult> = new Map();

  async analyzeNetwork(
    networkSegment: string,
    duration: number,
    focus: string[],
    context?: ExecutionContext
  ): Promise<NetworkAnalysisResult> {
    const analysisId = `NET-${Date.now()}`;
    
    // Generate realistic network topology
    const topology = this.generateTopology(networkSegment);
    
    // Simulate network traffic analysis
    const statistics = this.generateStatistics(duration, topology);
    
    // Detect anomalies based on focus areas
    const anomalies = focus.includes("anomalies")
      ? this.detectAnomalies(statistics, topology)
      : [];
    
    // Identify vulnerabilities
    const vulnerabilities = focus.includes("vulnerabilities")
      ? this.scanVulnerabilities(topology)
      : [];
    
    // Detect threats
    const threats = focus.includes("threats")
      ? this.detectThreats(statistics, topology)
      : [];
    
    // Generate recommendations
    const recommendations = this.generateRecommendations(
      anomalies,
      vulnerabilities,
      threats
    );

    const detectionArtifacts = this.generateDetectionArtifacts(
      networkSegment,
      anomalies,
      vulnerabilities,
      threats,
      focus
    );
    const mitreHeatmap = this.buildMitreHeatmap(threats, detectionArtifacts);
    const gapAnalysis = this.buildGapAnalysis(mitreHeatmap, focus);
    const integrationHooks = this.buildIntegrationHooks(
      networkSegment,
      detectionArtifacts
    );

    const result: NetworkAnalysisResult = {
      segmentId: networkSegment,
      duration,
      timestamp: new Date().toISOString(),
      statistics,
      anomalies,
      vulnerabilities,
      threats,
      recommendations,
      topology,
      detectionArtifacts,
      mitreHeatmap,
      gapAnalysis,
      integrationHooks,
      provenance: context?.provenance,
    };

    this.activeAnalyses.set(analysisId, result);
    return result;
  }

  private generateTopology(segment: string): NetworkTopology {
    const nodes: NetworkNode[] = [
      {
        id: "FW-001",
        type: "firewall",
        ipAddress: "10.0.1.1",
        hostname: "fw-perimeter-01",
        os: "Palo Alto PAN-OS 11.0",
        services: [
          { port: 443, protocol: "TCP", service: "HTTPS", version: "TLS 1.3", banner: "" },
        ],
        securityPosture: "Hardened",
      },
      {
        id: "SW-001",
        type: "switch",
        ipAddress: "10.0.1.2",
        hostname: "core-sw-01",
        os: "Cisco IOS 15.2",
        services: [
          { port: 22, protocol: "TCP", service: "SSH", version: "OpenSSH 8.2", banner: "" },
        ],
        securityPosture: "Good",
      },
      {
        id: "SRV-001",
        type: "server",
        ipAddress: "10.0.10.50",
        hostname: "web-server-01",
        os: "Ubuntu 22.04 LTS",
        services: [
          { port: 80, protocol: "TCP", service: "HTTP", version: "Apache 2.4.52", banner: "Apache/2.4.52 (Ubuntu)" },
          { port: 443, protocol: "TCP", service: "HTTPS", version: "Apache 2.4.52", banner: "Apache/2.4.52 (Ubuntu)" },
          { port: 22, protocol: "TCP", service: "SSH", version: "OpenSSH 8.9", banner: "OpenSSH_8.9p1 Ubuntu" },
        ],
        securityPosture: "Moderate",
      },
      {
        id: "SRV-002",
        type: "server",
        ipAddress: "10.0.10.51",
        hostname: "db-server-01",
        os: "Windows Server 2022",
        services: [
          { port: 1433, protocol: "TCP", service: "MS SQL", version: "SQL Server 2022", banner: "" },
          { port: 3389, protocol: "TCP", service: "RDP", version: "10.0", banner: "" },
        ],
        securityPosture: "Moderate",
      },
      {
        id: "WKS-001",
        type: "workstation",
        ipAddress: "10.0.20.100",
        hostname: "employee-pc-01",
        os: "Windows 11 Pro",
        services: [
          { port: 445, protocol: "TCP", service: "SMB", version: "3.1.1", banner: "" },
        ],
        securityPosture: "Fair",
      },
      {
        id: "WKS-002",
        type: "workstation",
        ipAddress: "10.0.20.101",
        hostname: "employee-pc-02",
        os: "Windows 11 Pro",
        services: [
          { port: 445, protocol: "TCP", service: "SMB", version: "3.1.1", banner: "" },
        ],
        securityPosture: "Fair",
      },
    ];

    const connections: NetworkConnection[] = [
      { source: "Internet", destination: "FW-001", connectionType: "WAN", bandwidth: "1 Gbps" },
      { source: "FW-001", destination: "SW-001", connectionType: "Internal", bandwidth: "10 Gbps" },
      { source: "SW-001", destination: "SRV-001", connectionType: "Internal", bandwidth: "1 Gbps" },
      { source: "SW-001", destination: "SRV-002", connectionType: "Internal", bandwidth: "1 Gbps" },
      { source: "SW-001", destination: "WKS-001", connectionType: "Internal", bandwidth: "1 Gbps" },
      { source: "SW-001", destination: "WKS-002", connectionType: "Internal", bandwidth: "1 Gbps" },
    ];

    const segments: NetworkSegment[] = [
      { id: "DMZ", name: "DMZ Zone", cidr: "10.0.10.0/24", vlan: 10, securityZone: "DMZ" },
      { id: "INTERNAL", name: "Internal Network", cidr: "10.0.20.0/24", vlan: 20, securityZone: "Internal" },
      { id: "MGMT", name: "Management Network", cidr: "10.0.1.0/24", vlan: 1, securityZone: "Management" },
    ];

    return { nodes, connections, segments };
  }

  private generateStatistics(duration: number, topology: NetworkTopology): NetworkStatistics {
    const basePackets = duration * 10000; // 10k packets per minute
    const totalPackets = basePackets + Math.floor(Math.random() * basePackets * 0.2);
    const totalBytes = totalPackets * (Math.random() * 1000 + 500); // Average packet size 500-1500 bytes

    const protocolDistribution: Record<string, number> = {
      TCP: 65 + Math.random() * 10,
      UDP: 20 + Math.random() * 10,
      ICMP: 5 + Math.random() * 5,
      Other: 5 + Math.random() * 5,
    };

    const topTalkers: Connection[] = [
      {
        source: "10.0.20.100",
        destination: "10.0.10.50",
        port: 443,
        protocol: "TCP",
        bytes: Math.floor(totalBytes * 0.25),
        packets: Math.floor(totalPackets * 0.20),
        duration: duration * 60,
      },
      {
        source: "10.0.20.101",
        destination: "10.0.10.50",
        port: 443,
        protocol: "TCP",
        bytes: Math.floor(totalBytes * 0.18),
        packets: Math.floor(totalPackets * 0.15),
        duration: duration * 60,
      },
      {
        source: "10.0.10.50",
        destination: "10.0.10.51",
        port: 1433,
        protocol: "TCP",
        bytes: Math.floor(totalBytes * 0.15),
        packets: Math.floor(totalPackets * 0.12),
        duration: duration * 60,
      },
    ];

    return {
      totalPackets,
      totalBytes: Math.floor(totalBytes),
      protocolDistribution,
      topTalkers,
      bandwidthUtilization: 45 + Math.random() * 30, // 45-75% utilization
      packetLoss: Math.random() * 0.5, // 0-0.5% packet loss
      averageLatency: 10 + Math.random() * 20, // 10-30ms latency
    };
  }

  private detectAnomalies(statistics: NetworkStatistics, topology: NetworkTopology): Anomaly[] {
    const anomalies: Anomaly[] = [];

    // Port scan detection
    if (Math.random() > 0.6) {
      anomalies.push({
        type: "Port Scan",
        severity: "Medium",
        description: "Sequential port scanning activity detected from external source",
        affectedHosts: ["10.0.10.50", "10.0.10.51"],
        detectionTime: new Date(Date.now() - Math.random() * 300000).toISOString(),
        confidence: 0.85,
      });
    }

    // Data exfiltration
    if (Math.random() > 0.7) {
      anomalies.push({
        type: "Data Exfiltration",
        severity: "High",
        description: "Unusually large outbound data transfer detected to external IP",
        affectedHosts: ["10.0.20.100"],
        detectionTime: new Date(Date.now() - Math.random() * 600000).toISOString(),
        confidence: 0.78,
      });
    }

    // Lateral movement
    if (Math.random() > 0.65) {
      anomalies.push({
        type: "Lateral Movement",
        severity: "High",
        description: "Unusual SMB traffic between workstations indicating potential lateral movement",
        affectedHosts: ["10.0.20.100", "10.0.20.101"],
        detectionTime: new Date(Date.now() - Math.random() * 450000).toISOString(),
        confidence: 0.72,
      });
    }

    // DNS tunneling
    if (Math.random() > 0.75) {
      anomalies.push({
        type: "DNS Tunneling",
        severity: "Critical",
        description: "Suspicious DNS query patterns consistent with DNS tunneling for C2",
        affectedHosts: ["10.0.20.101"],
        detectionTime: new Date(Date.now() - Math.random() * 200000).toISOString(),
        confidence: 0.88,
      });
    }

    // Bandwidth anomaly
    if (statistics.bandwidthUtilization > 70) {
      anomalies.push({
        type: "Bandwidth Anomaly",
        severity: "Medium",
        description: "Network bandwidth utilization exceeds baseline by 40%",
        affectedHosts: ["10.0.1.2"],
        detectionTime: new Date().toISOString(),
        confidence: 0.92,
      });
    }

    return anomalies;
  }

  private scanVulnerabilities(topology: NetworkTopology): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    // Check for vulnerable services
    topology.nodes.forEach((node) => {
      node.services.forEach((service) => {
        // Simulate vulnerability detection
        if (service.service === "Apache" && Math.random() > 0.5) {
          vulnerabilities.push({
            cveId: "CVE-2023-25690",
            severity: "High",
            affectedAssets: [node.hostname],
            description: "Apache HTTP Server mod_proxy_uwsgi HTTP response splitting vulnerability",
            cvssScore: 7.5,
            exploitable: true,
          });
        }

        if (service.service === "OpenSSH" && service.version.includes("8.9") && Math.random() > 0.6) {
          vulnerabilities.push({
            cveId: "CVE-2023-38408",
            severity: "Medium",
            affectedAssets: [node.hostname],
            description: "OpenSSH remote code execution vulnerability in ssh-agent",
            cvssScore: 6.8,
            exploitable: false,
          });
        }

        if (service.service === "MS SQL" && Math.random() > 0.7) {
          vulnerabilities.push({
            cveId: "CVE-2023-21528",
            severity: "Critical",
            affectedAssets: [node.hostname],
            description: "SQL Server Remote Code Execution Vulnerability",
            cvssScore: 9.8,
            exploitable: true,
          });
        }

        if (service.service === "RDP" && Math.random() > 0.55) {
          vulnerabilities.push({
            cveId: "CVE-2023-21562",
            severity: "High",
            affectedAssets: [node.hostname],
            description: "Windows Remote Desktop Protocol vulnerability allowing authentication bypass",
            cvssScore: 8.1,
            exploitable: true,
          });
        }
      });

      // Configuration vulnerabilities
      if (node.securityPosture === "Fair" && Math.random() > 0.5) {
        vulnerabilities.push({
          cveId: "CONFIG-001",
          severity: "Medium",
          affectedAssets: [node.hostname],
          description: "Weak password policy detected - passwords do not meet complexity requirements",
          cvssScore: 5.5,
          exploitable: false,
        });
      }
    });

    return vulnerabilities;
  }

  private detectThreats(statistics: NetworkStatistics, topology: NetworkTopology): ThreatIndicator[] {
    const threats: ThreatIndicator[] = [];

    // Malicious IP communication
    if (Math.random() > 0.6) {
      threats.push({
        type: "Malicious IP Communication",
        indicator: "203.0.113.42",
        source: "10.0.20.100",
        destination: "203.0.113.42",
        protocol: "TCP/443",
        description: "Communication with known malicious IP associated with APT29 (Cozy Bear)",
        mitreMapping: "T1071.001 - Application Layer Protocol: Web Protocols",
      });
    }

    // Suspicious domain access
    if (Math.random() > 0.65) {
      threats.push({
        type: "Suspicious Domain",
        indicator: "mal1c10us-c2-server.xyz",
        source: "10.0.20.101",
        destination: "198.51.100.73",
        protocol: "TCP/80",
        description: "DNS resolution and connection to domain with DGA characteristics",
        mitreMapping: "T1568.002 - Dynamic Resolution: Domain Generation Algorithms",
      });
    }

    // Cryptomining activity
    if (Math.random() > 0.7) {
      threats.push({
        type: "Cryptomining",
        indicator: "stratum+tcp://pool.minexmr.com:4444",
        source: "10.0.20.100",
        destination: "pool.minexmr.com",
        protocol: "TCP/4444",
        description: "Outbound connection to cryptocurrency mining pool",
        mitreMapping: "T1496 - Resource Hijacking",
      });
    }

    // Exploit attempt
    if (Math.random() > 0.75) {
      threats.push({
        type: "Exploit Attempt",
        indicator: "SQL Injection Pattern",
        source: "192.0.2.15",
        destination: "10.0.10.50",
        protocol: "TCP/80",
        description: "HTTP request containing SQL injection payload targeting web application",
        mitreMapping: "T1190 - Exploit Public-Facing Application",
      });
    }

    return threats;
  }

  private generateRecommendations(
    anomalies: Anomaly[],
    vulnerabilities: Vulnerability[],
    threats: ThreatIndicator[]
  ): string[] {
    const recommendations: string[] = [];

    // Anomaly-based recommendations
    if (anomalies.some((a) => a.type === "Port Scan")) {
      recommendations.push("Implement rate limiting on firewall to prevent port scanning");
      recommendations.push("Deploy network-based IDS/IPS to detect and block scanning activity");
    }

    if (anomalies.some((a) => a.type === "Data Exfiltration")) {
      recommendations.push("Enable Data Loss Prevention (DLP) controls on egress traffic");
      recommendations.push("Implement baseline monitoring for abnormal data transfer volumes");
    }

    if (anomalies.some((a) => a.type === "DNS Tunneling")) {
      recommendations.push("Deploy DNS security solution to detect tunneling patterns");
      recommendations.push("Monitor and analyze DNS query lengths and entropy");
    }

    if (anomalies.some((a) => a.type === "Lateral Movement")) {
      recommendations.push("Implement network segmentation to limit lateral movement");
      recommendations.push("Enable SMB signing and disable SMBv1 protocol");
    }

    // Vulnerability-based recommendations
    const criticalVulns = vulnerabilities.filter((v) => v.severity === "Critical");
    if (criticalVulns.length > 0) {
      recommendations.push(`Immediately patch ${criticalVulns.length} critical vulnerabilities identified`);
      recommendations.push("Implement virtual patching via WAF/IPS until patches can be applied");
    }

    const exploitableVulns = vulnerabilities.filter((v) => v.exploitable);
    if (exploitableVulns.length > 0) {
      recommendations.push("Prioritize patching of exploitable vulnerabilities with available PoC exploits");
    }

    // Threat-based recommendations
    if (threats.some((t) => t.type === "Malicious IP Communication")) {
      recommendations.push("Block communication with identified malicious IPs at perimeter firewall");
      recommendations.push("Integrate threat intelligence feeds for automatic IOC blocking");
    }

    if (threats.some((t) => t.type === "Cryptomining")) {
      recommendations.push("Block cryptocurrency mining pools at DNS and firewall level");
      recommendations.push("Investigate compromised host for malware and persistence mechanisms");
    }

    // General recommendations
    if (recommendations.length === 0) {
      recommendations.push("Continue monitoring network traffic for baseline establishment");
      recommendations.push("Conduct regular vulnerability assessments");
      recommendations.push("Review and update security policies quarterly");
    }

    return recommendations;
  }

  private generateDetectionArtifacts(
    segment: string,
    anomalies: Anomaly[],
    vulnerabilities: Vulnerability[],
    threats: ThreatIndicator[],
    focus: string[]
  ): DetectionArtifactSet {
    const sigma: DetectionRuleArtifact[] = [];
    const splunk: DetectionRuleArtifact[] = [];
    const kql: DetectionRuleArtifact[] = [];
    const playbooks: DetectionPlaybook[] = [];

    const hasBeaconing = threats.some((threat) => threat.mitreMapping.startsWith("T1071"));
    const hasDnsTunneling = anomalies.some((anomaly) => anomaly.type === "DNS Tunneling");
    const hasLateralMovement = anomalies.some((anomaly) => anomaly.type === "Lateral Movement");
    const hasExploitAttempts = threats.some((threat) => threat.mitreMapping.startsWith("T1190"));

    if (hasBeaconing) {
      const sigmaBeaconRule = [
        "title: Suspicious Low-Volume HTTPS Beaconing",
        "id: sigma-network-beaconing",
        "status: experimental",
        "description: Detects periodic low-volume HTTPS connections indicative of command and control.",
        "logsource:",
        "  product: zeek",
        "  service: http",
        "detection:",
        "  selection:",
        "    method: GET",
        "    resp_bytes|lt: 1500",
        "    request_body_len: 0",
        "  timeframe: 15m",
        "  condition: selection",
        "fields:",
        "  - id.orig_h",
        "  - id.resp_h",
        "  - ts",
        "  - user_agent",
        "tags:",
        "  - attack.T1071.001",
      ].join("\n");

      sigma.push({
        id: "sigma-network-beaconing",
        title: "Suspicious Low-Volume HTTPS Beaconing",
        query: sigmaBeaconRule,
        description: "Flags beacon-style HTTPS sessions from the segment for hunt teams.",
        references: ["https://attack.mitre.org/techniques/T1071/001/"],
        tags: ["attack.T1071.001", `segment.${segment}`],
      });

      splunk.push({
        id: "splunk_beaconing_search",
        title: "Beaconing Pattern - HTTPS",
        query:
          "| tstats `summariesonly` count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=443 by _time span=5m All_Traffic.dest_ip All_Traffic.src_ip" +
          "\n| eventstats avg(count) AS avg_count stdev(count) AS stdev_count BY All_Traffic.src_ip All_Traffic.dest_ip" +
          "\n| where count < avg_count + (stdev_count * 0.2) AND count > 0" +
          "\n| eval tactic=\"Command and Control\", technique=\"T1071.001\"",
        description: "Highlights periodic low-volume web traffic that could represent beaconing.",
        references: ["https://attack.mitre.org/techniques/T1071/001/"],
        tags: ["attack.T1071.001", "splunk", `segment.${segment}`],
      });

      kql.push({
        id: "sentinel_beaconing_kql",
        title: "Beaconing Pattern - Microsoft Sentinel",
        query:
          "CommonSecurityLog\n| where DestinationPort == 443 and RequestClientApplication != ''" +
          "\n| summarize Count = count(), AvgBytes = avg(SentBytes) by bin(TimeGenerated, 5m), DestinationIP, SourceIP, RequestClientApplication" +
          "\n| where AvgBytes < 1500" +
          "\n| extend Tactic='Command and Control', TechniqueId='T1071.001'",
        description: "Detects recurring HTTPS sessions with small payloads.",
        references: ["https://learn.microsoft.com/azure/sentinel/"],
        tags: ["attack.T1071.001", "sentinel", `segment.${segment}`],
      });

      playbooks.push({
        name: "C2 Beacon Triage",
        focus: "Command and Control",
        steps: [
          "Validate destination IP/domain reputation",
          "Capture full packet trace for suspect connections",
          "Quarantine impacted host and initiate EDR triage",
        ],
      });
    }

    if (hasDnsTunneling) {
      sigma.push({
        id: "sigma-dns-tunneling",
        title: "High Entropy DNS Queries",
        query: [
          "title: High Entropy DNS Queries",
          "id: sigma-dns-tunneling",
          "logsource:",
          "  product: zeek",
          "  service: dns",
          "detection:",
          "  selection:",
          "    query|re: '[A-Za-z0-9]{40,}'",
          "  condition: selection",
          "tags:",
          "  - attack.T1071",
        ].join("\n"),
        description: "Detects DNS queries with high entropy indicative of tunneling.",
        references: ["https://attack.mitre.org/techniques/T1071/004/"],
        tags: ["attack.T1071.004", `segment.${segment}`],
      });

      splunk.push({
        id: "splunk_dns_entropy",
        title: "DNS Entropy",
        query:
          "index=dns sourcetype=zeek_dns" +
          "\n| eval label=if(strlen(query)>40,\"long\",\"short\")" +
          "\n| where label=\"long\"" +
          "\n| stats count by src_ip, query" +
          "\n| where count > 5" +
          "\n| eval tactic=\"Command and Control\", technique=\"T1071.004\"",
        description: "Finds repeated long DNS queries per host.",
        references: ["https://attack.mitre.org/techniques/T1071/004/"],
        tags: ["attack.T1071.004"],
      });

      playbooks.push({
        name: "DNS Tunnel Containment",
        focus: "DNS",
        steps: [
          "Block destination domain or IP",
          "Capture forensic image of DNS client host",
          "Review outbound firewall rules for DNS over HTTPS",
        ],
      });
    }

    if (hasLateralMovement) {
      kql.push({
        id: "sentinel_smb_lateral",
        title: "SMB Lateral Movement",
        query:
          "SecurityEvent\n| where EventID in (5140, 4624) and AccountType == 'User'" +
          "\n| summarize Attempts=count() by Computer, SubjectAccount, EventID" +
          "\n| where Attempts > 10" +
          "\n| extend Tactic='Lateral Movement', TechniqueId='T1021.002'",
        description: "Surfaces abnormal SMB share access volume indicative of lateral movement.",
        references: ["https://attack.mitre.org/techniques/T1021/002/"],
        tags: ["attack.T1021.002"],
      });

      playbooks.push({
        name: "Contain SMB Lateral Movement",
        focus: "SMB",
        steps: [
          "Disable or restrict administrative shares on impacted nodes",
          "Rotate credentials abused in the movement",
          "Deploy additional honeypot shares for continued monitoring",
        ],
      });
    }

    if (hasExploitAttempts || focus.includes("vulnerabilities")) {
      sigma.push({
        id: "sigma-web-exploit",
        title: "Web Application Exploit Attempt",
        query: [
          "title: Web Application Exploit Attempt",
          "logsource:",
          "  product: apache",
          "  service: access",
          "detection:",
          "  selection:",
          "    request|contains: " + '"union select"',
          "  timeframe: 5m",
          "  condition: selection",
          "tags:",
          "  - attack.T1190",
        ].join("\n"),
        description: "Detects SQL injection style payloads in HTTP traffic.",
        references: ["https://attack.mitre.org/techniques/T1190/"],
        tags: ["attack.T1190"],
      });

      splunk.push({
        id: "splunk_http_injection",
        title: "HTTP Injection Attempts",
        query:
          "index=web sourcetype=access_combined" +
          "\n| search (" + '"union select"' + " OR " + '"or 1=1"' + ")" +
          "\n| stats count by clientip, uri" +
          "\n| eval tactic=\"Initial Access\", technique=\"T1190\"",
        description: "Counts SQL injection signatures hitting web tier.",
        references: ["https://owasp.org/www-community/attacks/SQL_Injection"],
        tags: ["attack.T1190"],
      });
    }

    if (sigma.length === 0 && splunk.length === 0 && kql.length === 0) {
      sigma.push({
        id: "sigma-generic-network",
        title: "Generic Network Anomaly",
        query: "title: Generic Network Anomaly\ndescription: Placeholder rule for baseline monitoring",
        description: "Template sigma rule to customise for the segment.",
        references: [],
        tags: ["attack.TA0000"],
      });
    }

    if (playbooks.length === 0) {
      playbooks.push({
        name: "Standard SOC Runbook",
        focus: "Network Investigation",
        steps: [
          "Validate alert fidelity with packet capture",
          "Consult threat intel for matching indicators",
          "Document findings in case management platform",
        ],
      });
    }

    return { sigma, splunk, kql, playbooks };
  }

  private buildMitreHeatmap(
    threats: ThreatIndicator[],
    artifacts: DetectionArtifactSet
  ): MitreHeatmapEntry[] {
    const coverageByTechnique: Map<string, { asset: string; coverage: "covered" | "partial" }> =
      new Map();

    const registerArtifacts = (
      rules: DetectionRuleArtifact[],
      assetLabel: string
    ) => {
      rules.forEach((rule) => {
        rule.tags
          .filter((tag) => tag.startsWith("attack."))
          .forEach((tag) => {
            const techniqueId = tag.replace("attack.", "").toUpperCase();
            const existing = coverageByTechnique.get(techniqueId);
            if (!existing) {
              coverageByTechnique.set(techniqueId, { asset: `${assetLabel}: ${rule.title}`, coverage: "covered" });
            }
          });
      });
    };

    registerArtifacts(artifacts.sigma, "Sigma");
    registerArtifacts(artifacts.splunk, "Splunk");
    registerArtifacts(artifacts.kql, "Sentinel");

    const heatmap: Map<string, MitreHeatmapEntry> = new Map();

    threats.forEach((threat) => {
      const [techniqueIdRaw, techniqueNameRaw] = threat.mitreMapping.split(" - ");
      const techniqueId = techniqueIdRaw.trim().toUpperCase();
      const techniqueName = techniqueNameRaw || "Unknown";
      const coverage = coverageByTechnique.get(techniqueId);
      heatmap.set(techniqueId, {
        tactic: this.inferTacticFromTechnique(techniqueId),
        techniqueId,
        technique: techniqueName,
        coverage: coverage ? coverage.coverage : "missing",
        detectionAsset: coverage?.asset,
        d3fendMappings: this.mapTechniqueToD3fend(techniqueId),
      });
    });

    coverageByTechnique.forEach((coverage, techniqueId) => {
      if (!heatmap.has(techniqueId)) {
        heatmap.set(techniqueId, {
          tactic: this.inferTacticFromTechnique(techniqueId),
          techniqueId,
          technique: "Proactive Detection",
          coverage: coverage.coverage,
          detectionAsset: coverage.asset,
          d3fendMappings: this.mapTechniqueToD3fend(techniqueId),
        });
      }
    });

    return Array.from(heatmap.values());
  }

  private buildGapAnalysis(
    mitreHeatmap: MitreHeatmapEntry[],
    focus: string[]
  ): DetectionGap[] {
    const gaps: DetectionGap[] = [];

    mitreHeatmap
      .filter((entry) => entry.coverage === "missing")
      .forEach((entry) => {
        gaps.push({
          area: `${entry.tactic} / ${entry.technique}`,
          severity: "high",
          description: `No telemetry mapped to ${entry.techniqueId}; analysts should create coverage before next engagement.`,
          recommendations: [
            "Develop detection logic leveraging available telemetry",
            "Cross-check with purple-team to validate detection fidelity",
          ],
        });
      });

    if (focus.includes("vulnerabilities") && !mitreHeatmap.some((entry) => entry.techniqueId.startsWith("T1190"))) {
      gaps.push({
        area: "Initial Access / Exploit Public-Facing Application",
        severity: "medium",
        description: "Exploit detection coverage is lacking despite vulnerability focus.",
        recommendations: [
          "Instrument WAF/Reverse proxy logs for exploit patterns",
          "Add behavioural analytics for anomalous HTTP verbs",
        ],
      });
    }

    if (focus.includes("anomalies") && !mitreHeatmap.some((entry) => entry.techniqueId.startsWith("T1071"))) {
      gaps.push({
        area: "Command and Control",
        severity: "medium",
        description: "C2 detection coverage is minimal while anomaly focus requested network telemetry.",
        recommendations: [
          "Enable JA3/JA3S fingerprinting",
          "Collect proxy logs for advanced detections",
        ],
      });
    }

    return gaps;
  }

  private buildIntegrationHooks(
    segment: string,
    artifacts: DetectionArtifactSet
  ): IntegrationHook[] {
    const hooks: IntegrationHook[] = [];

    if (artifacts.splunk.length > 0) {
      hooks.push({
        platform: "Splunk Enterprise Security",
        type: "Saved Search",
        description: "Deploys beaconing saved search with adaptive response for auto ticketing.",
        configuration: {
          searchName: "CyberSim - HTTPS Beaconing",
          schedule: "*/5 * * * *",
          notableIndex: "notable",
          riskObject: segment,
        },
        samplePayload: {
          savedsearch: "CyberSim - HTTPS Beaconing",
          query: artifacts.splunk[0].query,
        },
      });
    }

    if (artifacts.kql.length > 0) {
      hooks.push({
        platform: "Microsoft Sentinel",
        type: "Analytics Rule",
        description: "Create scheduled analytics rule for SMB lateral movement with automation hooks.",
        configuration: {
          ruleTemplate: "Scheduled",
          frequency: "PT5M",
          severity: "High",
          tactic: "Lateral Movement",
        },
        samplePayload: {
          displayName: "CyberSim SMB Lateral Movement",
          query: artifacts.kql[0].query,
          tactics: ["LateralMovement"],
        },
      });
    }

    hooks.push({
      platform: "Cortex XSOAR",
      type: "Automation Playbook",
      description: "Purple-team runbook to ingest CyberSim detections and orchestrate containment",
      configuration: {
        playbook: "CyberSim-Network-Containment",
        inputs: "network_segment, detection_id, severity",
        notes: "Requires HTTPS integration with CyberSim HTTP bridge",
      },
      samplePayload: {
        inputs: {
          network_segment: segment,
          detection_id: artifacts.sigma[0]?.id || "sigma-generic-network",
          severity: "High",
        },
      },
    });

    return hooks;
  }

  private inferTacticFromTechnique(techniqueId: string): string {
    const prefix = techniqueId.split(".")[0];
    const mapping: Record<string, string> = {
      T1071: "Command and Control",
      T1021: "Lateral Movement",
      T1190: "Initial Access",
      T1496: "Impact",
      T1498: "Impact",
      T1568: "Command and Control",
      T1505: "Persistence",
    };
    return mapping[prefix] || "Unknown";
  }

  private mapTechniqueToD3fend(techniqueId: string): string[] {
    const prefix = techniqueId.split(".")[0];
    const mapping: Record<string, string[]> = {
      T1071: ["D3-CORR", "D3-CMTA"],
      T1021: ["D3-SYSM"],
      T1190: ["D3-PTCH"],
      T1496: ["D3-RCFG"],
      T1568: ["D3-DNSM"],
    };
    return mapping[prefix] || ["D3-GNRL"];
  }

  getAnalysis(analysisId: string): NetworkAnalysisResult | undefined {
    return this.activeAnalyses.get(analysisId);
  }
}
