import { IncidentInvestigation, IncidentSummary } from "../managers/incidentResponseManager.js";

export type RiskSystem = "servicenow" | "archer" | "onetrust" | "custom";

export interface RiskSyncRequest {
  system: RiskSystem;
  incident: IncidentSummary | undefined;
  investigation: IncidentInvestigation | undefined;
  priority?: string;
  owner?: string;
  dueDate?: string;
}

export interface RiskSyncPayload {
  targetSystem: RiskSystem;
  endpoint: string;
  method: string;
  body: Record<string, unknown>;
  instructions: string[];
}

const ENDPOINT_HINTS: Record<RiskSystem, string> = {
  servicenow: "/api/now/table/risk_register",
  archer: "/api/core/risk-register",
  onetrust: "/api/risk-register/items",
  custom: "/risk/register",
};

export function buildRiskPayload(request: RiskSyncRequest): RiskSyncPayload {
  const { system, incident, investigation, priority, owner, dueDate } = request;

  const body: Record<string, unknown> = {
    title: incident?.title || "CyberSim Pro Risk Item",
    description: incident?.brief || "Generated from CyberSim Pro exercise",
    status: incident?.status || "Open",
    severity: incident?.severity || "Unknown",
    priority: priority || "High",
    owner: owner || "CISO",
    dueDate,
    references: {
      incidentId: incident?.incidentId,
      investigationId: investigation?.incidentId,
    },
    recommendations: investigation?.remediationSteps?.map((step) => step.action),
  };

  const instructions: string[] = [
    "Authenticate with the target system using service credentials.",
    `POST the payload to ${ENDPOINT_HINTS[system]}.`,
    "Link returned record ID back into CyberSim Pro evidence repository.",
  ];

  return {
    targetSystem: system,
    endpoint: ENDPOINT_HINTS[system],
    method: "POST",
    body,
    instructions,
  };
}
