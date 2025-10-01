export type ControlStatus = "operational" | "in-progress" | "planned";

export interface ControlDefinition {
  id: string;
  domain: string;
  description: string;
  status: ControlStatus;
  evidence: string[];
  owners: string[];
  relatedComponents: string[];
  frameworks: Array<{
    program: "SOC2" | "ISO27001" | "NISTCSF" | "HIPAA";
    reference: string;
  }>;
}

export const controlCatalog: ControlDefinition[] = [
  {
    id: "CM-01",
    domain: "Change Management",
    description: "All production changes require peer review and automated build/test validation before deployment.",
    status: "operational",
    evidence: [
      "GitHub PR reviews",
      "CI build logs",
      "deployment change tickets"
    ],
    owners: ["Engineering"],
    relatedComponents: ["src/index.ts", "package.json", "tsconfig.json"],
    frameworks: [
      { program: "SOC2", reference: "CC8.1" },
      { program: "ISO27001", reference: "A.8.32" },
      { program: "NISTCSF", reference: "PR.IP-3" }
    ]
  },
  {
    id: "CM-02",
    domain: "Change Management",
    description: "Emergency production changes are logged and reviewed retroactively within 48 hours.",
    status: "in-progress",
    evidence: ["PagerDuty incident reviews", "post-incident reports"],
    owners: ["Engineering Ops"],
    relatedComponents: ["docs/COMPLIANCE_ROADMAP.md"],
    frameworks: [
      { program: "SOC2", reference: "CC8.1" },
      { program: "ISO27001", reference: "A.8.23" }
    ]
  },
  {
    id: "VM-01",
    domain: "Vulnerability Management",
    description: "Weekly dependency scanning and backlog tracking for remediation of critical vulnerabilities.",
    status: "operational",
    evidence: ["npm audit reports", "Snyk dashboard"],
    owners: ["Security Engineering"],
    relatedComponents: ["package.json", "package-lock.json"],
    frameworks: [
      { program: "SOC2", reference: "CC7.1" },
      { program: "ISO27001", reference: "A.8.8" },
      { program: "NISTCSF", reference: "DE.CM-8" }
    ]
  },
  {
    id: "VM-02",
    domain: "Vulnerability Management",
    description: "Quarterly penetration testing and threat modeling exercises inform backlog prioritisation.",
    status: "planned",
    evidence: ["Pen test reports", "threat model updates"],
    owners: ["Security Engineering"],
    relatedComponents: ["docs/COMPLIANCE_ROADMAP.md"],
    frameworks: [
      { program: "SOC2", reference: "CC7.1" },
      { program: "ISO27001", reference: "A.8.20" }
    ]
  },
  {
    id: "BR-01",
    domain: "Backup & Recovery",
    description: "Automated backups with encrypted off-site copies and documented restore procedures.",
    status: "planned",
    evidence: ["Backup job logs", "restore drill runbooks"],
    owners: ["Platform Ops"],
    relatedComponents: ["docs/COMPLIANCE_ROADMAP.md"],
    frameworks: [
      { program: "SOC2", reference: "CC7.4" },
      { program: "ISO27001", reference: "A.8.13" },
      { program: "NISTCSF", reference: "PR.IP-4" }
    ]
  },
  {
    id: "BR-02",
    domain: "Backup & Recovery",
    description: "Semi-annual disaster recovery exercises validate RTO/RPO targets and communication plans.",
    status: "planned",
    evidence: ["DR exercise reports", "executive summaries"],
    owners: ["Platform Ops"],
    relatedComponents: ["docs/COMPLIANCE_ROADMAP.md"],
    frameworks: [
      { program: "SOC2", reference: "CC7.4" },
      { program: "ISO27001", reference: "A.5.29" },
      { program: "NISTCSF", reference: "PR.IP-9" }
    ]
  },
  {
    id: "AM-01",
    domain: "Access Management",
    description: "Mandatory SSO with MFA, role-based access, and JIT elevation for production systems.",
    status: "operational",
    evidence: [
      "Identity gateway audit logs",
      "Weekly audit seal workflow",
      "SCIM provisioning change reports"
    ],
    owners: ["IT Security"],
    relatedComponents: [
      "docs/COMPLIANCE_ROADMAP.md",
      "docs/SSO_SCIM_DESIGN.md",
      "src/httpServer.ts",
      "src/identity/authGateway.ts",
      "src/identity/scimProvisioner.ts",
      "config/role-mappings.example.json"
    ],
    frameworks: [
      { program: "SOC2", reference: "CC6.2" },
      { program: "ISO27001", reference: "A.5.15" },
      { program: "NISTCSF", reference: "PR.AC-1" },
      { program: "HIPAA", reference: "164.312(d)" }
    ]
  },
  {
    id: "AU-01",
    domain: "Audit & Logging",
    description: "Immutable audit logging with hash chaining and HMAC signing plus sealed export bundles for regulators.",
    status: "operational",
    evidence: ["logs/seals/", "generate_validation_report output"],
    owners: ["Platform Ops"],
    relatedComponents: [
      "src/utils/auditLogger.ts",
      "src/utils/validationReport.ts",
      "src/cli/exportAuditSeal.ts",
      "README.md"
    ],
    frameworks: [
      { program: "SOC2", reference: "CC7.2" },
      { program: "ISO27001", reference: "A.8.16" },
      { program: "NISTCSF", reference: "DE.AE-3" },
      { program: "HIPAA", reference: "164.312(b)" }
    ]
  }
];
