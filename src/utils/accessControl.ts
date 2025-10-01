import fs from "fs";
import path from "path";

export interface OperatorContext {
  id?: string;
  role?: string;
  approvals?: string[];
}

interface RolePolicy {
  allowedTools: string[];
}

interface AccessPolicy {
  roles: Record<string, RolePolicy>;
  restrictedTools: string[];
}

const DEFAULT_POLICY: AccessPolicy = {
  roles: {
    analyst: { allowedTools: ["create_scenario", "analyze_network", "investigate_incident", "forensics_analysis", "generate_report", "list_metrics", "export_controls"] },
    controller: { allowedTools: ["create_scenario", "simulate_attack", "analyze_network", "investigate_incident", "forensics_analysis", "generate_report", "stop_simulation", "replay_telemetry", "list_metrics", "export_controls", "sync_risk_register", "generate_validation_report"] },
    auditor: { allowedTools: ["generate_report", "generate_validation_report", "list_metrics"] },
    ciso: { allowedTools: ["*" ] },
  },
  restrictedTools: ["simulate_attack", "stop_simulation", "replay_telemetry"],
};

function loadPolicy(): AccessPolicy {
  const configPath = process.env.CYBERSIM_RBAC_CONFIG;
  if (configPath) {
    try {
      const resolved = path.resolve(configPath);
      const raw = fs.readFileSync(resolved, "utf8");
      const parsed = JSON.parse(raw) as AccessPolicy;
      return parsed;
    } catch (error) {
      console.warn(`[cybersim-pro] Failed to load RBAC config: ${error}`);
    }
  }
  return DEFAULT_POLICY;
}

export class AccessControl {
  private policy: AccessPolicy;
  private approvalToken: string | undefined;

  constructor() {
    this.policy = loadPolicy();
    this.approvalToken = process.env.CYBERSIM_APPROVAL_TOKEN?.trim();
  }

  enforce(tool: string, operator: OperatorContext | undefined, approvalToken?: string): void {
    const policy = this.policy;
    const restricted = policy.restrictedTools.includes(tool);

    if (!restricted && !policy.roles) {
      return;
    }

    const role = operator?.role || "analyst";
    const rolePolicy = policy.roles[role];

    if (!rolePolicy) {
      throw new Error(`Access denied: role "${role}" is not recognised for tool ${tool}`);
    }

    if (!this.isToolAllowed(tool, rolePolicy.allowedTools)) {
      throw new Error(`Access denied: role "${role}" is not permitted to run ${tool}`);
    }

    if (restricted && this.approvalToken) {
      if (!approvalToken || approvalToken !== this.approvalToken) {
        throw new Error("Access denied: approval token missing or invalid for restricted tool");
      }
    }
  }

  private isToolAllowed(tool: string, allowed: string[]): boolean {
    if (allowed.includes("*")) {
      return true;
    }
    return allowed.includes(tool);
  }
}
