import type { ExecutionContext, ExecutionProvenance } from "../utils/executionContext.js";

export interface IncidentInvestigation {
  incidentId: string;
  scope: string;
  status: string;
  severity: string;
  startTime: string;
  timeline: InvestigationTimeline;
  findings: Finding[];
  evidenceChain: Evidence[];
  rootCause: RootCause;
  containmentActions: ContainmentAction[];
  remediationSteps: RemediationStep[];
  lessonsLearned: string[];
  provenance?: ExecutionProvenance;
}

export interface InvestigationTimeline {
  events: TimelineEvent[];
  reconstructedAttackPath: AttackPathNode[];
  firstCompromise: string;
  lastActivity: string;
  dwellTime: number; // in hours
}

export interface TimelineEvent {
  timestamp: string;
  eventType: string;
  source: string;
  description: string;
  severity: string;
  correlatedEvents: string[];
}

export interface AttackPathNode {
  step: number;
  timestamp: string;
  action: string;
  source: string;
  target: string;
  technique: string;
  mitreId: string;
}

export interface Finding {
  id: string;
  category: string;
  description: string;
  severity: string;
  confidence: number;
  supportingEvidence: string[];
}

export interface Evidence {
  id: string;
  type: string;
  source: string;
  collectionTime: string;
  hash: string;
  custodyChain: CustodyRecord[];
  analysis: string;
}

export interface CustodyRecord {
  timestamp: string;
  handler: string;
  action: string;
  location: string;
}

export interface RootCause {
  primaryCause: string;
  contributingFactors: string[];
  vulnerabilitiesExploited: string[];
  controlFailures: string[];
}

export interface ContainmentAction {
  action: string;
  timestamp: string;
  implementedBy: string;
  effectiveness: string;
  impactOnOperations: string;
}

export interface RemediationStep {
  step: number;
  action: string;
  priority: string;
  estimatedEffort: string;
  status: string;
  assignedTo?: string;
}

export interface SecurityReport {
  reportId: string;
  reportType: string;
  generatedDate: string;
  executiveSummary: string;
  incidents: IncidentSummary[];
  riskAssessment: RiskAssessment;
  recommendations: Recommendation[];
  metrics: SecurityMetrics;
  appendices: Appendix[];
  scorecard: ScorecardOverview;
  facilitationKit: FacilitationKit;
  executiveDashboard: ExecutiveDashboard;
  maturityRoadmap: MaturityRoadmap;
  procurementBrief: ProcurementBrief;
  provenance?: ExecutionProvenance;
}

export interface IncidentSummary {
  incidentId: string;
  title: string;
  severity: string;
  status: string;
  brief: string;
}

export interface RiskAssessment {
  overallRiskLevel: string;
  riskFactors: RiskFactor[];
  threatLandscape: string;
  vulnerabilityPosture: string;
}

export interface RiskFactor {
  factor: string;
  likelihood: string;
  impact: string;
  riskScore: number;
  mitigation: string;
}

export interface Recommendation {
  priority: string;
  category: string;
  recommendation: string;
  rationale: string;
  estimatedCost: string;
  timeframe: string;
}

export interface SecurityMetrics {
  mttr: number; // Mean Time To Respond (hours)
  mttd: number; // Mean Time To Detect (hours)
  incidentCount: number;
  criticalIncidents: number;
  detectionRate: number;
  falsePositiveRate: number;
}

export interface Appendix {
  title: string;
  content: string;
}

export interface ScorecardOverview {
  exerciseSummary: string;
  metrics: {
    detectionLatencyHours: number;
    containmentTimeHours: number;
    eradicationTimeHours: number;
  };
  redTeam: TeamScorecard;
  blueTeam: TeamScorecard;
  purpleTeam: TeamScorecard;
}

export interface TeamScorecard {
  category: string;
  detectionLatency: string;
  containmentPerformance: string;
  lessonsLearned: string[];
  nextSteps: string[];
}

export interface FacilitationKit {
  kickoffPrompt: string;
  scenarioSeed: string;
  teleprompterNotes: string[];
  agenda: SessionAgendaItem[];
}

export interface SessionAgendaItem {
  phase: string;
  durationMinutes: number;
  objective: string;
  cues: string[];
}

export interface ExecutiveDashboard {
  riskHeadline: string;
  downtimeEstimateHours: number;
  financialExposureMillions: number;
  customerImpact: string;
  heatmap: DashboardHeatmapItem[];
  nextBoardActions: string[];
}

export interface DashboardHeatmapItem {
  dimension: string;
  status: "On Track" | "At Risk" | "Critical";
  notes: string;
}

export interface MaturityRoadmap {
  frameworkAlignment: FrameworkAlignment[];
  milestones: RoadmapMilestone[];
}

export interface FrameworkAlignment {
  framework: string;
  currentLevel: string;
  targetLevel: string;
  nextSteps: string[];
}

export interface RoadmapMilestone {
  quarter: string;
  theme: string;
  owner: string;
  deliverables: string[];
}

export interface ProcurementBrief {
  summary: string;
  faqs: ProcurementFaq[];
  legalConsiderations: string[];
  riskControls: string[];
}

export interface ProcurementFaq {
  question: string;
  answer: string;
}

export class IncidentResponseManager {
  private investigations: Map<string, IncidentInvestigation> = new Map();
  private reports: Map<string, SecurityReport> = new Map();

  async investigateIncident(
    incidentId: string,
    scope: string,
    context?: ExecutionContext
  ): Promise<IncidentInvestigation> {
    const investigation = await this.conductInvestigation(incidentId, scope);
    const enriched: IncidentInvestigation = {
      ...investigation,
      provenance: context?.provenance,
    };
    this.investigations.set(incidentId, enriched);
    return enriched;
  }

  private async conductInvestigation(incidentId: string, scope: string): Promise<IncidentInvestigation> {
    const startTime = new Date().toISOString();
    const severity = this.determineSeverity(incidentId);

    // Reconstruct timeline
    const timeline = this.reconstructTimeline(incidentId, scope);

    // Gather findings
    const findings = this.collectFindings(incidentId, scope);

    // Collect evidence
    const evidenceChain = this.collectEvidence(incidentId, scope);

    // Determine root cause
    const rootCause = this.analyzeRootCause(findings, timeline);

    // Document containment actions
    const containmentActions = this.documentContainment(incidentId);

    // Generate remediation steps
    const remediationSteps = this.generateRemediationPlan(rootCause, findings);

    // Extract lessons learned
    const lessonsLearned = this.extractLessons(rootCause, findings);

    return {
      incidentId,
      scope,
      status: scope === "deep_dive" ? "Complete" : "In Progress",
      severity,
      startTime,
      timeline,
      findings,
      evidenceChain,
      rootCause,
      containmentActions,
      remediationSteps,
      lessonsLearned,
    };
  }

  private determineSeverity(incidentId: string): string {
    // Simulate severity determination based on incident characteristics
    const rand = Math.random();
    if (rand > 0.8) return "Critical";
    if (rand > 0.5) return "High";
    if (rand > 0.2) return "Medium";
    return "Low";
  }

  private reconstructTimeline(incidentId: string, scope: string): InvestigationTimeline {
    const now = Date.now();
    const dwellTime = Math.floor(Math.random() * 720) + 24; // 24-744 hours (1-31 days)
    const firstCompromise = new Date(now - dwellTime * 3600000).toISOString();
    const lastActivity = new Date(now - Math.random() * 3600000).toISOString();

    const events: TimelineEvent[] = [
      {
        timestamp: firstCompromise,
        eventType: "Initial Compromise",
        source: "Firewall Logs",
        description: "Suspicious authentication attempt from external IP 203.0.113.42",
        severity: "Medium",
        correlatedEvents: ["EVT-001", "EVT-003"],
      },
      {
        timestamp: new Date(now - (dwellTime - 2) * 3600000).toISOString(),
        eventType: "Persistence Established",
        source: "EDR Alert",
        description: "Registry modification detected - Run key created for suspicious executable",
        severity: "High",
        correlatedEvents: ["EVT-004"],
      },
      {
        timestamp: new Date(now - (dwellTime - 48) * 3600000).toISOString(),
        eventType: "Credential Access",
        source: "SIEM",
        description: "LSASS memory access by non-system process",
        severity: "Critical",
        correlatedEvents: ["EVT-005", "EVT-006"],
      },
      {
        timestamp: new Date(now - (dwellTime - 72) * 3600000).toISOString(),
        eventType: "Lateral Movement",
        source: "Network Monitor",
        description: "Unusual SMB traffic between workstations",
        severity: "High",
        correlatedEvents: ["EVT-007", "EVT-008"],
      },
      {
        timestamp: new Date(now - 12 * 3600000).toISOString(),
        eventType: "Data Exfiltration Attempt",
        source: "DLP",
        description: "Large outbound data transfer to cloud storage service",
        severity: "Critical",
        correlatedEvents: ["EVT-009"],
      },
      {
        timestamp: lastActivity,
        eventType: "Detection & Containment",
        source: "SOC",
        description: "Threat detected and containment measures initiated",
        severity: "Informational",
        correlatedEvents: [],
      },
    ];

    const attackPath: AttackPathNode[] = [
      {
        step: 1,
        timestamp: firstCompromise,
        action: "Initial Access via exploited VPN vulnerability",
        source: "203.0.113.42",
        target: "VPN Gateway (10.0.1.5)",
        technique: "Exploit Public-Facing Application",
        mitreId: "T1190",
      },
      {
        step: 2,
        timestamp: new Date(now - (dwellTime - 1) * 3600000).toISOString(),
        action: "Establish persistence via registry Run key",
        source: "VPN Gateway",
        target: "WORKSTATION-001 (10.0.20.100)",
        technique: "Boot or Logon Autostart Execution",
        mitreId: "T1547.001",
      },
      {
        step: 3,
        timestamp: new Date(now - (dwellTime - 48) * 3600000).toISOString(),
        action: "Dump credentials from LSASS",
        source: "WORKSTATION-001",
        target: "LSASS.EXE",
        technique: "OS Credential Dumping",
        mitreId: "T1003.001",
      },
      {
        step: 4,
        timestamp: new Date(now - (dwellTime - 72) * 3600000).toISOString(),
        action: "Lateral movement using stolen credentials",
        source: "WORKSTATION-001",
        target: "FILESERVER-001 (10.0.10.50)",
        technique: "Remote Services: SMB",
        mitreId: "T1021.002",
      },
      {
        step: 5,
        timestamp: new Date(now - 12 * 3600000).toISOString(),
        action: "Exfiltrate sensitive data",
        source: "FILESERVER-001",
        target: "cloud-storage.attacker.com",
        technique: "Exfiltration Over Web Service",
        mitreId: "T1567.002",
      },
    ];

    return {
      events,
      reconstructedAttackPath: attackPath,
      firstCompromise,
      lastActivity,
      dwellTime,
    };
  }

  private collectFindings(incidentId: string, scope: string): Finding[] {
    const findings: Finding[] = [
      {
        id: "FIND-001",
        category: "Initial Access",
        description: "Unpatched VPN gateway (CVE-2023-XXXXX) exploited for initial access",
        severity: "Critical",
        confidence: 0.95,
        supportingEvidence: ["EVD-001", "EVD-002", "EVD-005"],
      },
      {
        id: "FIND-002",
        category: "Credential Compromise",
        description: "Domain administrator credentials compromised via LSASS dumping",
        severity: "Critical",
        confidence: 0.92,
        supportingEvidence: ["EVD-003", "EVD-007"],
      },
      {
        id: "FIND-003",
        category: "Lateral Movement",
        description: "Attacker moved laterally across 15 systems using stolen credentials",
        severity: "High",
        confidence: 0.88,
        supportingEvidence: ["EVD-004", "EVD-008"],
      },
      {
        id: "FIND-004",
        category: "Data Exfiltration",
        description: "Approximately 2.5 GB of sensitive data exfiltrated to external cloud storage",
        severity: "Critical",
        confidence: 0.85,
        supportingEvidence: ["EVD-006", "EVD-009"],
      },
      {
        id: "FIND-005",
        category: "Detection Gap",
        description: "Threat remained undetected for 28 days due to insufficient monitoring",
        severity: "High",
        confidence: 0.90,
        supportingEvidence: ["EVD-010"],
      },
    ];

    if (scope === "deep_dive") {
      findings.push(
        {
          id: "FIND-006",
          category: "TTPs",
          description: "Attack patterns consistent with APT29 (Cozy Bear) tradecraft",
          severity: "High",
          confidence: 0.75,
          supportingEvidence: ["EVD-011", "EVD-012"],
        },
        {
          id: "FIND-007",
          category: "Control Failure",
          description: "MFA not enforced on VPN access for administrative accounts",
          severity: "High",
          confidence: 1.0,
          supportingEvidence: ["EVD-013"],
        }
      );
    }

    return findings;
  }

  private collectEvidence(incidentId: string, scope: string): Evidence[] {
    const evidence: Evidence[] = [
      {
        id: "EVD-001",
        type: "Network Traffic Capture",
        source: "Firewall (10.0.1.1)",
        collectionTime: new Date().toISOString(),
        hash: "a1b2c3d4e5f6789012345678901234567890123456789012345678901234",
        custodyChain: [
          {
            timestamp: new Date().toISOString(),
            handler: "SOC Analyst - J. Smith",
            action: "Collected",
            location: "Evidence Locker - Slot A1",
          },
        ],
        analysis: "PCAP shows exploitation attempts targeting CVE-2023-XXXXX on VPN gateway",
      },
      {
        id: "EVD-002",
        type: "System Logs",
        source: "VPN Gateway",
        collectionTime: new Date().toISOString(),
        hash: "b2c3d4e5f6789012345678901234567890123456789012345678901234a1",
        custodyChain: [
          {
            timestamp: new Date().toISOString(),
            handler: "IR Team - M. Johnson",
            action: "Collected",
            location: "Evidence Locker - Slot A2",
          },
        ],
        analysis: "Authentication logs show successful login after failed exploitation attempts",
      },
      {
        id: "EVD-003",
        type: "Memory Dump",
        source: "WORKSTATION-001",
        collectionTime: new Date().toISOString(),
        hash: "c3d4e5f6789012345678901234567890123456789012345678901234a1b2",
        custodyChain: [
          {
            timestamp: new Date().toISOString(),
            handler: "Forensics - A. Williams",
            action: "Acquired",
            location: "Forensics Lab - Station 3",
          },
        ],
        analysis: "Memory contains remnants of credential dumping tools (Mimikatz signatures)",
      },
      {
        id: "EVD-004",
        type: "Network Flow Data",
        source: "Core Switch",
        collectionTime: new Date().toISOString(),
        hash: "d4e5f6789012345678901234567890123456789012345678901234a1b2c3",
        custodyChain: [
          {
            timestamp: new Date().toISOString(),
            handler: "Network Team - R. Davis",
            action: "Exported",
            location: "Evidence Locker - Slot B1",
          },
        ],
        analysis: "NetFlow data confirms lateral movement pattern via SMB protocol",
      },
    ];

    return evidence;
  }

  private analyzeRootCause(findings: Finding[], timeline: InvestigationTimeline): RootCause {
    return {
      primaryCause: "Exploitation of unpatched VPN gateway vulnerability (CVE-2023-XXXXX)",
      contributingFactors: [
        "Delayed patch management process (vulnerability known for 90+ days)",
        "Lack of MFA on VPN access for privileged accounts",
        "Insufficient network segmentation allowing lateral movement",
        "Inadequate log monitoring and alerting configuration",
        "Overly permissive domain admin account usage",
      ],
      vulnerabilitiesExploited: [
        "CVE-2023-XXXXX - VPN Gateway Remote Code Execution",
        "Weak credential policies allowing LSASS dumping",
        "Unrestricted SMB access between network segments",
      ],
      controlFailures: [
        "Patch Management - Critical vulnerability not patched within SLA",
        "Access Control - No MFA on administrative VPN access",
        "Network Segmentation - Flat network allowed unrestricted lateral movement",
        "Monitoring - Insufficient visibility into authentication and network activity",
        "Privileged Access Management - Domain admin used for routine tasks",
      ],
    };
  }

  private documentContainment(incidentId: string): ContainmentAction[] {
    return [
      {
        action: "Isolated affected workstation (WORKSTATION-001) from network",
        timestamp: new Date(Date.now() - 3600000).toISOString(),
        implementedBy: "SOC Team",
        effectiveness: "High",
        impactOnOperations: "Minimal - single user impacted",
      },
      {
        action: "Disabled compromised domain admin account",
        timestamp: new Date(Date.now() - 3300000).toISOString(),
        implementedBy: "IT Security",
        effectiveness: "High",
        impactOnOperations: "Low - backup admin accounts available",
      },
      {
        action: "Blocked external IP 203.0.113.42 at perimeter firewall",
        timestamp: new Date(Date.now() - 3000000).toISOString(),
        implementedBy: "Network Team",
        effectiveness: "Medium",
        impactOnOperations: "None",
      },
      {
        action: "Applied emergency patch to VPN gateway",
        timestamp: new Date(Date.now() - 1800000).toISOString(),
        implementedBy: "Network Team",
        effectiveness: "High",
        impactOnOperations: "Moderate - 15 minute service interruption",
      },
      {
        action: "Forced password reset for all users with VPN access",
        timestamp: new Date(Date.now() - 900000).toISOString(),
        implementedBy: "IT Security",
        effectiveness: "High",
        impactOnOperations: "High - user support requests increased significantly",
      },
    ];
  }

  private generateRemediationPlan(rootCause: RootCause, findings: Finding[]): RemediationStep[] {
    return [
      {
        step: 1,
        action: "Complete forensic analysis and evidence preservation",
        priority: "Critical",
        estimatedEffort: "8 hours",
        status: "In Progress",
        assignedTo: "Forensics Team",
      },
      {
        step: 2,
        action: "Implement emergency patches for all VPN gateways",
        priority: "Critical",
        estimatedEffort: "4 hours",
        status: "Complete",
        assignedTo: "Network Team",
      },
      {
        step: 3,
        action: "Enable MFA for all VPN and administrative access",
        priority: "Critical",
        estimatedEffort: "24 hours",
        status: "In Progress",
        assignedTo: "IT Security",
      },
      {
        step: 4,
        action: "Conduct full credential rotation for all privileged accounts",
        priority: "High",
        estimatedEffort: "16 hours",
        status: "Planned",
        assignedTo: "IAM Team",
      },
      {
        step: 5,
        action: "Implement network segmentation to isolate critical assets",
        priority: "High",
        estimatedEffort: "80 hours",
        status: "Planned",
        assignedTo: "Network Architecture",
      },
      {
        step: 6,
        action: "Deploy enhanced logging and monitoring for VPN and authentication events",
        priority: "High",
        estimatedEffort: "40 hours",
        status: "Planned",
        assignedTo: "SOC Team",
      },
      {
        step: 7,
        action: "Conduct security awareness training on phishing and credential security",
        priority: "Medium",
        estimatedEffort: "Ongoing",
        status: "Planned",
        assignedTo: "Security Awareness Team",
      },
      {
        step: 8,
        action: "Review and update incident response playbooks based on lessons learned",
        priority: "Medium",
        estimatedEffort: "16 hours",
        status: "Planned",
        assignedTo: "IR Team Lead",
      },
    ];
  }

  private extractLessons(rootCause: RootCause, findings: Finding[]): string[] {
    return [
      "Patch management SLAs must be strictly enforced, especially for internet-facing systems",
      "MFA should be mandatory for all remote access, with no exceptions for privileged accounts",
      "Network segmentation is critical to limit blast radius and prevent lateral movement",
      "Enhanced monitoring and alerting are essential for early threat detection",
      "Privileged access should follow principle of least privilege and just-in-time access",
      "Regular tabletop exercises help identify gaps in incident response procedures",
      "Threat intelligence integration can provide early warning of targeted attack campaigns",
      "Automated containment actions can significantly reduce dwell time and impact",
    ];
  }

  async generateReport(
    reportType: string,
    incidentIds: string[],
    includeRecommendations: boolean,
    mode?: string,
    context?: ExecutionContext
  ): Promise<SecurityReport> {
    const reportId = `RPT-${Date.now()}`;
    const generatedDate = new Date().toISOString();

    const incidents = this.summarizeIncidents(incidentIds);
    const riskAssessment = this.performRiskAssessment(incidents);
    const recommendations = includeRecommendations ? this.generateRecommendations(incidents) : [];
    const metrics = this.calculateMetrics(incidents);
    const appendices = this.generateAppendices(reportType);
    const contextLabel = mode || reportType;
    const scorecard = this.buildScorecard(contextLabel, incidents, metrics);
    const facilitationKit = this.buildFacilitationKit(contextLabel, incidents);
    const executiveDashboard = this.buildExecutiveDashboard(riskAssessment, metrics);
    const maturityRoadmap = this.buildMaturityRoadmap();
    const procurementBrief = this.buildProcurementBrief();

    const executiveSummary = this.createExecutiveSummary(reportType, incidents, riskAssessment);

    const report: SecurityReport = {
      reportId,
      reportType,
      generatedDate,
      executiveSummary,
      incidents,
      riskAssessment,
      recommendations,
      metrics,
      appendices,
      scorecard,
      facilitationKit,
      executiveDashboard,
      maturityRoadmap,
      procurementBrief,
    };

    const enriched: SecurityReport = {
      ...report,
      provenance: context?.provenance,
    };

    this.reports.set(reportId, enriched);
    return enriched;
  }

  private summarizeIncidents(incidentIds: string[]): IncidentSummary[] {
    // If no specific incidents provided, create sample incidents
    if (incidentIds.length === 0) {
      return [
        {
          incidentId: "INC-2024-001",
          title: "Ransomware Attack via Phishing",
          severity: "Critical",
          status: "Resolved",
          brief: "Ransomware deployed via phishing email, 50+ systems encrypted, restored from backups",
        },
        {
          incidentId: "INC-2024-002",
          title: "APT Intrusion and Data Exfiltration",
          severity: "Critical",
          status: "Under Investigation",
          brief: "Advanced persistent threat gained access via VPN vulnerability, exfiltrated sensitive data",
        },
        {
          incidentId: "INC-2024-003",
          title: "DDoS Attack on Public Services",
          severity: "High",
          status: "Resolved",
          brief: "Multi-vector DDoS attack disrupted services for 6 hours, mitigated via CDN",
        },
      ];
    }

    return incidentIds.map((id) => {
      const investigation = this.investigations.get(id);
      return {
        incidentId: id,
        title: investigation ? `Security Incident - ${investigation.severity}` : "Unknown Incident",
        severity: investigation?.severity || "Unknown",
        status: investigation?.status || "Unknown",
        brief: investigation ? this.generateBrief(investigation) : "No details available",
      };
    });
  }

  private generateBrief(investigation: IncidentInvestigation): string {
    const keyFindings = investigation.findings.slice(0, 2);
    return `${keyFindings.map((f) => f.description).join("; ")}. Investigation ${investigation.status.toLowerCase()}.`;
  }

  private performRiskAssessment(incidents: IncidentSummary[]): RiskAssessment {
    const criticalCount = incidents.filter((i) => i.severity === "Critical").length;
    const overallRiskLevel = criticalCount > 2 ? "High" : criticalCount > 0 ? "Elevated" : "Moderate";

    const riskFactors: RiskFactor[] = [
      {
        factor: "Unpatched Systems",
        likelihood: "High",
        impact: "Critical",
        riskScore: 9.0,
        mitigation: "Implement automated patch management with 30-day SLA for critical vulnerabilities",
      },
      {
        factor: "Weak Authentication Controls",
        likelihood: "Medium",
        impact: "High",
        riskScore: 7.5,
        mitigation: "Enforce MFA across all remote access and privileged accounts",
      },
      {
        factor: "Insufficient Network Segmentation",
        likelihood: "High",
        impact: "High",
        riskScore: 8.5,
        mitigation: "Redesign network architecture with micro-segmentation and zero-trust principles",
      },
      {
        factor: "Limited Security Monitoring",
        likelihood: "High",
        impact: "Medium",
        riskScore: 7.0,
        mitigation: "Deploy comprehensive SIEM with 24/7 SOC monitoring and automated response",
      },
      {
        factor: "Insider Threats",
        likelihood: "Low",
        impact: "High",
        riskScore: 5.5,
        mitigation: "Implement User Behavior Analytics (UBA) and Data Loss Prevention (DLP)",
      },
    ];

    return {
      overallRiskLevel,
      riskFactors,
      threatLandscape: "Current threat landscape shows increased APT activity targeting our industry sector. Ransomware-as-a-Service (RaaS) continues to evolve with more sophisticated tactics. Supply chain attacks remain a significant concern.",
      vulnerabilityPosture: "Organization has moderate vulnerability exposure with several critical gaps in patch management and access controls. Internet-facing assets require immediate attention. Internal systems show aging software components with known vulnerabilities.",
    };
  }

  private generateRecommendations(incidents: IncidentSummary[]): Recommendation[] {
    return [
      {
        priority: "Critical",
        category: "Vulnerability Management",
        recommendation: "Implement automated vulnerability scanning and patch management across all assets",
        rationale: "Multiple incidents resulted from exploitation of known, patchable vulnerabilities",
        estimatedCost: "$150K - $300K (tooling and resources)",
        timeframe: "0-30 days",
      },
      {
        priority: "Critical",
        category: "Identity & Access Management",
        recommendation: "Deploy MFA for all remote access and privileged accounts",
        rationale: "Credential compromise was primary attack vector in recent incidents",
        estimatedCost: "$50K - $100K (MFA solution and integration)",
        timeframe: "0-30 days",
      },
      {
        priority: "High",
        category: "Network Security",
        recommendation: "Redesign network with zero-trust architecture and micro-segmentation",
        rationale: "Lateral movement was unimpeded due to flat network architecture",
        estimatedCost: "$500K - $1M (architecture redesign and implementation)",
        timeframe: "30-180 days",
      },
      {
        priority: "High",
        category: "Security Operations",
        recommendation: "Enhance SIEM capabilities and establish 24/7 SOC operations",
        rationale: "Mean time to detect (MTTD) averaged 28 days, far exceeding industry benchmarks",
        estimatedCost: "$400K - $800K annually (SOC staffing and tooling)",
        timeframe: "30-90 days",
      },
      {
        priority: "High",
        category: "Endpoint Security",
        recommendation: "Deploy next-generation EDR with automated response capabilities",
        rationale: "Current endpoint protection failed to detect sophisticated threats",
        estimatedCost: "$200K - $400K (EDR platform and deployment)",
        timeframe: "30-60 days",
      },
      {
        priority: "Medium",
        category: "Data Protection",
        recommendation: "Implement Data Loss Prevention (DLP) controls across all egress points",
        rationale: "Data exfiltration went undetected until post-incident analysis",
        estimatedCost: "$150K - $300K (DLP solution)",
        timeframe: "60-120 days",
      },
      {
        priority: "Medium",
        category: "Backup & Recovery",
        recommendation: "Enhance backup strategy with immutable, air-gapped copies",
        rationale: "Ransomware targeted backup systems, limiting recovery options",
        estimatedCost: "$100K - $200K (backup infrastructure)",
        timeframe: "30-90 days",
      },
      {
        priority: "Medium",
        category: "Security Awareness",
        recommendation: "Launch comprehensive security awareness program with phishing simulations",
        rationale: "User interactions with malicious content initiated multiple incidents",
        estimatedCost: "$50K - $100K annually (training platform and content)",
        timeframe: "0-60 days",
      },
      {
        priority: "Low",
        category: "Incident Response",
        recommendation: "Develop and regularly test incident response playbooks",
        rationale: "Inconsistent response procedures resulted in delayed containment",
        estimatedCost: "$30K - $60K (IR consulting and tabletop exercises)",
        timeframe: "60-90 days",
      },
      {
        priority: "Low",
        category: "Threat Intelligence",
        recommendation: "Integrate threat intelligence feeds with security tools",
        rationale: "Known malicious indicators were not blocked by security controls",
        estimatedCost: "$50K - $100K annually (threat intelligence services)",
        timeframe: "30-60 days",
      },
    ];
  }

  private calculateMetrics(incidents: IncidentSummary[]): SecurityMetrics {
    return {
      mttr: 18.5, // Mean Time To Respond
      mttd: 168.0, // Mean Time To Detect (7 days)
      incidentCount: incidents.length,
      criticalIncidents: incidents.filter((i) => i.severity === "Critical").length,
      detectionRate: 65.0, // Percentage of threats detected by security controls
      falsePositiveRate: 12.5, // Percentage of alerts that were false positives
    };
  }

  private generateAppendices(reportType: string): Appendix[] {
    const appendices: Appendix[] = [
      {
        title: "Appendix A: MITRE ATT&CK Mapping",
        content: `
Techniques observed in incidents:
- T1190: Exploit Public-Facing Application
- T1566: Phishing
- T1078: Valid Accounts
- T1003: OS Credential Dumping
- T1021: Remote Services
- T1486: Data Encrypted for Impact
- T1567: Exfiltration Over Web Service

Detailed mapping available in incident investigation reports.`,
      },
      {
        title: "Appendix B: Indicators of Compromise (IOCs)",
        content: `
IP Addresses:
- 203.0.113.42 (C2 Server)
- 198.51.100.73 (Exfiltration Destination)

Domains:
- mal1c10us-c2-server.xyz
- cloud-storage.attacker.com

File Hashes (SHA256):
- a1b2c3d4e5f6789012345678901234567890123456789012345678901234
- b2c3d4e5f6789012345678901234567890123456789012345678901234a1

All IOCs have been shared with industry partners via ISAC.`,
      },
      {
        title: "Appendix C: Compliance Impact",
        content: `
Regulatory Requirements Affected:
- GDPR: Personal data potentially compromised, notification required within 72 hours
- HIPAA: Protected health information accessed, breach notification procedures initiated
- PCI DSS: Cardholder data environment compromised, forensic investigation mandated
- SOX: Financial systems impacted, additional audit procedures required

Legal counsel and compliance teams engaged for regulatory response.`,
      },
    ];

    if (reportType === "executive") {
      appendices.push({
        title: "Appendix D: Financial Impact Analysis",
        content: `
Direct Costs:
- Incident response and forensics: $250K
- System restoration and recovery: $180K
- Legal and compliance: $150K
- Notification and credit monitoring: $75K

Indirect Costs:
- Business disruption: $500K (estimated)
- Reputational damage: Moderate to Severe
- Customer churn risk: 5-10% (estimated)
- Regulatory fines: Pending (potential $2M-$5M)

Total Estimated Impact: $1.2M - $1.5M (excluding potential fines)`,
      });
    }

    return appendices;
  }

  private buildScorecard(
    reportType: string,
    incidents: IncidentSummary[],
    metrics: SecurityMetrics
  ): ScorecardOverview {
    const criticalIncidents = incidents.filter((incident) => incident.severity === "Critical");
    const blueTeamLessons = [
      "Automate credential reset workflow to reduce containment lag",
      "Strengthen log retention to support forensics",
      "Instrument privileged activity dashboards for real-time review",
    ];

    return {
      exerciseSummary: `${reportType.toUpperCase()} review covers ${incidents.length} incidents with ${criticalIncidents.length} critical cases; current mean detection latency is ${metrics.mttd}h and containment occurs in ${metrics.mttr}h on average.`,
      metrics: {
        detectionLatencyHours: metrics.mttd,
        containmentTimeHours: metrics.mttr,
        eradicationTimeHours: Math.round(metrics.mttr * 1.4 * 10) / 10,
      },
      redTeam: {
        category: "Red Team",
        detectionLatency: `${metrics.mttd}h (goal < 12h)`,
        containmentPerformance: `${metrics.mttr}h to trigger purple-team handoff`,
        lessonsLearned: [
          "Adaptive playbooks mapped to real adversaries increase realism",
          "Need faster change control approvals to simulate exploit weaponisation",
          "Document command-chain outputs for future automation",
        ],
        nextSteps: [
          "Publish updated adversary profiles with sector overlays",
          "Integrate CyberSim command-chain exports into red-team wiki",
        ],
      },
      blueTeam: {
        category: "Blue Team",
        detectionLatency: `${metrics.mttd}h to first detection event`,
        containmentPerformance: `${metrics.mttr}h containment, ${Math.round(metrics.mttr * 1.2)}h eradication`,
        lessonsLearned: blueTeamLessons,
        nextSteps: [
          "Deploy detection artifacts supplied in network analysis",
          "Run tabletop focusing on DNS telemetry gaps",
          "Align SIEM dashboards with MITRE heatmap",
        ],
      },
      purpleTeam: {
        category: "Purple Team",
        detectionLatency: `${Math.round(metrics.mttd / 2)}h in guided exercises`,
        containmentPerformance: "Joint containment achieved in < 10h during facilitated sessions",
        lessonsLearned: [
          "Joint runbooks accelerate response alignment",
          "Need pre-approved automation hooks for containment",
        ],
        nextSteps: [
          "Schedule monthly purple drills using facilitation kit",
          "Publish cross-team success metrics to leadership dashboard",
        ],
      },
    };
  }

  private buildFacilitationKit(
    reportType: string,
    incidents: IncidentSummary[]
  ): FacilitationKit {
    const primaryIncident = incidents[0] || {
      incidentId: "INC-TRAIN-000",
      title: "Simulated Incident",
      severity: "High",
      status: "Planned",
      brief: "Synthetic tabletop scenario",
    };

    return {
      kickoffPrompt:
        "You are facilitating a joint red/blue exercise in an authorised lab. Emphasise defensive learning outcomes and ensure all actions remain simulated.",
      scenarioSeed: `Invoke create_scenario with adversary_profile=apt29, sector='${primaryIncident.title.toLowerCase().includes("ransomware") ? "finance" : "enterprise"}', difficulty='advanced'.`,
      teleprompterNotes: [
        "Frame objectives: dwell time reduction, containment coordination, executive storytelling",
        "Reinforce safety guardrails and simulated payload policy",
        "Observe for detection gaps matching MITRE heatmap",
        "Capture action items live for after-action review",
      ],
      agenda: [
        {
          phase: "Kickoff & Context",
          durationMinutes: 10,
          objective: "Align participants on scenario boundaries and goals",
          cues: ["Outline authorised lab scope", "Confirm comms channels"],
        },
        {
          phase: "Adversary Simulation",
          durationMinutes: 20,
          objective: "Run command-chain walk-through from create_scenario + simulate_attack",
          cues: ["Highlight pseudo commands", "Capture detection opportunities"],
        },
        {
          phase: "Blue-Team Response",
          durationMinutes: 20,
          objective: "Execute detection artifacts and triage runbooks",
          cues: ["Map alerts to MITRE heatmap", "Record timing metrics"],
        },
        {
          phase: "Executive Debrief",
          durationMinutes: 10,
          objective: "Summarise impact, risk, and roadmap for leadership",
          cues: ["Use executive dashboard talking points", "Review next steps"],
        },
      ],
    };
  }

  private buildExecutiveDashboard(
    riskAssessment: RiskAssessment,
    metrics: SecurityMetrics
  ): ExecutiveDashboard {
    return {
      riskHeadline: `Risk posture is ${riskAssessment.overallRiskLevel}; dwell time averages ${metrics.mttd}h with containment in ${metrics.mttr}h.`,
      downtimeEstimateHours: 48,
      financialExposureMillions: 4.2,
      customerImpact: "Customer communications triggered for high-risk incidents; retention risk currently 5-10%",
      heatmap: [
        {
          dimension: "Identity & Access",
          status: "Critical",
          notes: "MFA coverage at 45% for privileged accounts",
        },
        {
          dimension: "Detection & Response",
          status: "At Risk",
          notes: "MTTD exceeds 24h benchmark; automation backlog persists",
        },
        {
          dimension: "Resilience",
          status: "On Track",
          notes: "Backups restored within RTO; need immutable copies",
        },
        {
          dimension: "Governance",
          status: "At Risk",
          notes: "Policy updates pending for tabletop learnings",
        },
      ],
      nextBoardActions: [
        "Approve funding for vulnerability management automation",
        "Mandate organisation-wide MFA completion by next quarter",
        "Track purple-team metrics in quarterly risk committee",
      ],
    };
  }

  private buildMaturityRoadmap(): MaturityRoadmap {
    return {
      frameworkAlignment: [
        {
          framework: "NIST CSF",
          currentLevel: "Tier 2 - Risk Informed",
          targetLevel: "Tier 3 - Repeatable",
          nextSteps: [
            "Formalise detection engineering lifecycle",
            "Automate incident response evidence collection",
            "Integrate CyberSim exercises into risk register",
          ],
        },
        {
          framework: "CMMC 2.0",
          currentLevel: "Level 1",
          targetLevel: "Level 2",
          nextSteps: [
            "Implement continuous monitoring for controlled unclassified information",
            "Document role-based response playbooks",
            "Validate supply-chain security controls with CyberSim benchmarks",
          ],
        },
        {
          framework: "ISO 27001",
          currentLevel: "In Progress",
          targetLevel: "Certified",
          nextSteps: [
            "Complete risk treatment plan for identity controls",
            "Update statement of applicability with purple-team outcomes",
          ],
        },
      ],
      milestones: [
        {
          quarter: "Q1",
          theme: "Detection Engineering Sprint",
          owner: "SOC Manager",
          deliverables: [
            "Deploy Sigma and Splunk content to production",
            "Launch weekly threat hunting alignment meeting",
          ],
        },
        {
          quarter: "Q2",
          theme: "Automation & SOAR",
          owner: "Security Automation Lead",
          deliverables: [
            "Integrate CyberSim HTTP bridge into SOAR",
            "Automate containment workflows for ransomware playbooks",
          ],
        },
        {
          quarter: "Q3",
          theme: "Governance & Training",
          owner: "CISO",
          deliverables: [
            "Publish updated policy & ethics addendum",
            "Run executive tabletop using facilitation kit",
          ],
        },
      ],
    };
  }

  private buildProcurementBrief(): ProcurementBrief {
    return {
      summary:
        "CyberSim Pro provides regulated organisations with auditable adversary simulations, adaptive detection artefacts, and governance collateral sufficient for procurement review.",
      faqs: [
        {
          question: "Does CyberSim Pro operate only in lab environments?",
          answer: "Yes. The platform enforces simulated payloads and supports stdio or HTTP bridges inside isolated labs or sandboxes.",
        },
        {
          question: "How are logs captured for compliance?",
          answer: "All tool invocations are written to append-only JSONL audit logs with timestamps, sanitized arguments, and termination reasons.",
        },
        {
          question: "What integrations exist for existing SOC tooling?",
          answer: "Detection artefacts include ready-to-deploy Sigma, Splunk, and Sentinel content; integration hooks cover SOAR connectors and APIs.",
        },
      ],
      legalConsiderations: [
        "Capability restricted to authorised red/blue team training as defined in usage policy",
        "Supports evidence retention requirements (PCI DSS, HIPAA, SOX) via structured audit logging",
        "Includes policy & ethics guide aligning with acceptable use and regulatory safeguards",
      ],
      riskControls: [
        "Role-based prompt templates enforce defensive framing",
        "Stop_simulation kill-switch with immutable logging",
        "Environment variable controls for API key enforcement and IP allow lists",
      ],
    };
  }

  private createExecutiveSummary(
    reportType: string,
    incidents: IncidentSummary[],
    riskAssessment: RiskAssessment
  ): string {
    const criticalIncidents = incidents.filter((i) => i.severity === "Critical").length;
    
    return `
EXECUTIVE SUMMARY

This ${reportType} report covers ${incidents.length} security incident${incidents.length !== 1 ? "s" : ""} investigated during the reporting period, including ${criticalIncidents} critical-severity incident${criticalIncidents !== 1 ? "s" : ""}.

KEY FINDINGS:
- Overall organizational risk level: ${riskAssessment.overallRiskLevel}
- Primary attack vectors: Unpatched vulnerabilities, credential compromise, and phishing
- Average time to detect threats: 7 days (industry benchmark: <24 hours)
- Average time to respond: 18.5 hours (industry benchmark: <6 hours)

IMPACT ASSESSMENT:
The incidents resulted in:
- Unauthorized access to sensitive data repositories
- Temporary disruption of critical business services
- Potential compliance violations requiring regulatory notification
- Estimated financial impact of $1.2M - $1.5M

ROOT CAUSES:
Analysis identified systemic security gaps:
1. Inadequate patch management processes
2. Lack of multi-factor authentication on critical systems
3. Insufficient network segmentation enabling lateral movement
4. Limited security monitoring and threat detection capabilities
5. Weak privileged access management controls

RECOMMENDATIONS:
Immediate action required in three critical areas:
1. Deploy MFA across all remote and privileged access (0-30 days)
2. Implement automated vulnerability and patch management (0-30 days)
3. Establish 24/7 security operations center with enhanced SIEM (30-90 days)

Additional medium-term improvements focus on network architecture modernization, endpoint security enhancement, and data protection controls.

CONCLUSION:
While incident response was ultimately successful, significant security gaps enabled these breaches. Implementation of recommended controls will substantially reduce organizational risk and improve security posture to industry best practices.

Detailed findings, evidence, and recommendations follow in subsequent sections.
`;
  }

  getInvestigation(incidentId: string): IncidentInvestigation | undefined {
    return this.investigations.get(incidentId);
  }

  getReport(reportId: string): SecurityReport | undefined {
    return this.reports.get(reportId);
  }

  listInvestigations(): IncidentInvestigation[] {
    return Array.from(this.investigations.values());
  }
}
