import { createServer, IncomingMessage, ServerResponse } from "http";
import { SecurityScenarioManager } from "./scenarios/scenarioManager.js";
import type { SecurityScenario } from "./scenarios/scenarioManager.js";
import { NetworkSimulator } from "./simulators/networkSimulator.js";
import type { NetworkAnalysisResult } from "./simulators/networkSimulator.js";
import { ThreatSimulator } from "./simulators/threatSimulator.js";
import type { AttackSimulationResult } from "./simulators/threatSimulator.js";
import { IncidentResponseManager } from "./managers/incidentResponseManager.js";
import type { IncidentInvestigation, IncidentSummary } from "./managers/incidentResponseManager.js";
import { ForensicsAnalyzer } from "./analyzers/forensicsAnalyzer.js";
import { AuditLogger } from "./utils/auditLogger.js";
import { AccessControl, OperatorContext } from "./utils/accessControl.js";
import { MetricsTracker } from "./utils/metricsTracker.js";
import { ControlFeed, ControlRecommendation } from "./utils/controlFeed.js";
import { replayTelemetry, TelemetryEvent } from "./utils/telemetryAnalyzer.js";
import { buildRiskPayload, RiskSystem } from "./utils/riskSync.js";
import { generateValidationDigest } from "./utils/validationReport.js";

type Json = Record<string, any> | any[] | string | number | boolean | null;

function readJson(req: IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(Buffer.from(c)));
    req.on("end", () => {
      if (chunks.length === 0) return resolve({});
      try {
        const text = Buffer.concat(chunks).toString("utf8");
        resolve(text ? JSON.parse(text) : {});
      } catch (e) {
        reject(new Error("Invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

function send(res: ServerResponse, status: number, body: Json, headers: Record<string, string> = {}): void {
  const payload = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    ...headers,
  });
  res.end(payload);
}

const scenarioManager = new SecurityScenarioManager();
const networkSimulator = new NetworkSimulator();
const threatSimulator = new ThreatSimulator();
const incidentManager = new IncidentResponseManager();
const forensicsAnalyzer = new ForensicsAnalyzer();
const auditLogger = new AuditLogger();
const accessControl = new AccessControl();
const metricsTracker = new MetricsTracker();
const controlFeed = new ControlFeed();

const PORT = Number(process.env.PORT || 8787);
const API_KEY = (process.env.CYBERSIM_API_KEY || "").trim();
const IP_ALLOW = (process.env.CYBERSIM_IP_ALLOW || "").trim();

const allowedIps = new Set(
  IP_ALLOW
    ? IP_ALLOW.split(",").map((s) => s.trim()).filter(Boolean)
    : []
);

function normalizeIp(ip: string | undefined): string | undefined {
  if (!ip) return undefined;
  // Handle IPv6-mapped IPv4 addresses: ::ffff:127.0.0.1
  if (ip.startsWith("::ffff:")) return ip.replace("::ffff:", "");
  return ip;
}

function checkIpAllowed(req: IncomingMessage): boolean {
  if (allowedIps.size === 0) return true;
  const remote = normalizeIp((req.socket as any).remoteAddress);
  if (!remote) return false;
  if (remote === "::1" || remote === "127.0.0.1") {
    if (allowedIps.has("local") || allowedIps.has("127.0.0.1") || allowedIps.has("::1")) return true;
  }
  return allowedIps.has(remote);
}

function checkApiKey(req: IncomingMessage): boolean {
  if (!API_KEY) return true;
  const auth = req.headers["authorization"] || req.headers["Authorization" as any];
  if (!auth || Array.isArray(auth)) return false;
  const expected = `Bearer ${API_KEY}`;
  return auth === expected;
}

const server = createServer(async (req, res) => {
  try {
    // CORS preflight
    if (req.method === "OPTIONS") {
      res.writeHead(204, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Max-Age": "86400",
      });
      return res.end();
    }

    const url = new URL(req.url || "/", `http://${req.headers.host}`);
    const path = url.pathname.replace(/\/$/, "");

    if (req.method === "GET" && path === "/health") {
      return send(res, 200, { status: "ok" });
    }

    if (req.method === "GET" && (path === "/openapi.yaml" || path === "/openapi.yml")) {
      // Simple static pointer; serve minimal instructions
      return send(res, 200, { hint: "Serve the repository file http-openapi.yaml over HTTP in production." });
    }

    if (req.method === "POST" && path.startsWith("/tool/")) {
      if (!checkIpAllowed(req)) {
        return send(res, 403, { error: "Forbidden: IP not allowed" });
      }
      if (!checkApiKey(req)) {
        return send(res, 401, { error: "Unauthorized: missing or invalid Authorization header" });
      }

      const body = await readJson(req);
      const name = path.substring("/tool/".length);
      const operator = (body?.operator || body?.operator_context) as OperatorContext | undefined;
      const approvalToken = typeof body?.approval_token === "string" ? (body.approval_token as string) : undefined;
      const sanitizedArgs = JSON.parse(JSON.stringify(body || {}));
      delete sanitizedArgs.approval_token;
      delete sanitizedArgs.operator_context;
      const startedAt = Date.now();

      try {
        accessControl.enforce(name, operator, approvalToken);
      } catch (error) {
        return send(res, 403, { error: (error as Error).message });
      }

      try {
        let metadata: Record<string, unknown> | undefined;
        let out: unknown;

        switch (name) {
          case "create_scenario": {
            const { type, difficulty, environment, sector, adversary_profile, focus_cves } = body || {};
            const scenario = await scenarioManager.createScenario(type, difficulty, environment, {
              sector,
              adversaryProfile: adversary_profile,
              cveFocus: Array.isArray(focus_cves) ? focus_cves : undefined,
            });
            out = scenario;
            metadata = { scenarioId: scenario.id };
            break;
          }
          case "simulate_attack": {
            const { attack_type, target, intensity = "medium" } = body || {};
            const result = await threatSimulator.simulateAttack(attack_type, target, intensity);
            await metricsTracker.record("simulate_attack", {
              simulationId: result.simulationId,
              attackType: result.attackType,
              target: result.target,
              detectionRate: result.detectionRate,
              intensity: result.intensity,
            });
            out = result;
            metadata = { simulationId: result.simulationId };
            break;
          }
          case "analyze_network": {
            const { network_segment, duration = 10, focus = ["anomalies"] } = body || {};
            const result = await networkSimulator.analyzeNetwork(network_segment, Number(duration), focus);
            await captureControlsFromNetwork(controlFeed, result);
            out = result;
            metadata = { segmentId: result.segmentId };
            break;
          }
          case "investigate_incident": {
            const { incident_id, scope = "initial" } = body || {};
            const result = await incidentManager.investigateIncident(incident_id, scope);
            out = result;
            metadata = { incidentId: result.incidentId };
            break;
          }
          case "forensics_analysis": {
            const { artifact_type, system_id, analysis_depth = "standard" } = body || {};
            const result = await forensicsAnalyzer.analyzeArtifact(artifact_type, system_id, analysis_depth);
            out = result;
            metadata = { systemId: system_id, artifactType: artifact_type };
            break;
          }
          case "generate_report": {
            const { report_type, incident_ids = [], include_recommendations = true, mode } = body || {};
            const result = await incidentManager.generateReport(report_type, incident_ids, !!include_recommendations, mode);
            await metricsTracker.record("generate_report", {
              reportId: result.reportId,
              reportType: result.reportType,
              detectionLatencyHours: result.metrics.mttd,
              containmentTimeHours: result.metrics.mttr,
              incidentCount: result.metrics.incidentCount,
            });
            out = result;
            metadata = { reportId: result.reportId, reportType: result.reportType };
            break;
          }
          case "stop_simulation": {
            const { simulation_id, reason } = body || {};
            if (simulation_id) {
              const result = threatSimulator.stopSimulation(simulation_id, reason);
              if (!result) {
                return send(res, 404, { error: `No active simulation found for id ${simulation_id}` });
              }
              out = { message: `Simulation ${simulation_id} terminated`, simulation: result };
              metadata = { simulationId: simulation_id };
            } else {
              const terminated = threatSimulator.stopAllSimulations(reason);
              out = {
                message: terminated.length ? `Terminated ${terminated.length} simulations` : "No active simulations to terminate",
                simulations: terminated,
              };
              metadata = { terminatedCount: terminated.length };
            }
            break;
          }
          case "replay_telemetry": {
            const simulationId: string = body?.simulation_id;
            const scenarioId: string | undefined = body?.scenario_id;
            const simulation = threatSimulator.getSimulation(simulationId);
            if (!simulation) {
              return send(res, 404, { error: `No active simulation found for id ${simulationId}` });
            }
            const scenario = scenarioId ? scenarioManager.getScenario(scenarioId) : undefined;
            const telemetry = normaliseTelemetry(body);
            const result = replayTelemetry({ simulation, scenario, telemetry });
            const recs = createRecommendationsFromTelemetry(simulation, result.detectionGaps);
            await controlFeed.capture(recs);
            await metricsTracker.record("replay_telemetry", {
              simulationId,
              totalEvents: result.totalEvents,
              matchedTechniques: result.matchedTechniques.length,
              detectionGaps: result.detectionGaps.length,
            });
            out = result;
            metadata = { simulationId, detectionGaps: result.detectionGaps.length };
            break;
          }
          case "list_metrics": {
            out = await metricsTracker.summarize();
            metadata = { tool: "list_metrics" };
            break;
          }
          case "export_controls": {
            const result = await controlFeed.export();
            out = result;
            metadata = { controlCount: result.length };
            break;
          }
          case "sync_risk_register": {
            const system = body?.system as RiskSystem;
            const incidentId = body?.incident_id as string;
            const investigations = incidentManager.listInvestigations();
            const investigation = investigations.find((item) => item.incidentId === incidentId);
            const incidentSummary = buildIncidentSummary(incidentId, investigation);
            const payload = buildRiskPayload({
              system,
              incident: incidentSummary,
              investigation,
              priority: body?.priority,
              owner: body?.owner,
              dueDate: body?.due_date,
            });
            out = payload;
            metadata = { system, incidentId };
            break;
          }
          case "generate_validation_report": {
            const result = await generateValidationDigest(auditLogger.getLogFilePath());
            out = result;
            metadata = { totalEntries: result.totalEntries };
            break;
          }
          default:
            return send(res, 404, { error: `Unknown tool: ${name}` });
        }

        await auditLogger.log({
          timestamp: new Date().toISOString(),
          tool: name,
          status: "success",
          durationMs: Date.now() - startedAt,
          arguments: sanitizedArgs,
          metadata: {
            ...metadata,
            operatorId: operator?.id,
            operatorRole: operator?.role,
          },
        });

        const responseBody = (out ?? null) as Json;
        return send(res, 200, responseBody);
      } catch (error) {
        await auditLogger.log({
          timestamp: new Date().toISOString(),
          tool: name,
          status: "error",
          durationMs: Date.now() - startedAt,
          arguments: sanitizedArgs,
          errorMessage: error instanceof Error ? error.message : String(error),
        });
        throw error;
      }
    }

    return send(res, 404, { error: "Not found" });
  } catch (err: any) {
    const message = err instanceof Error ? err.message : String(err);
    return send(res, 400, { error: message });
  }
});

server.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.error(`[cybersim-pro] HTTP bridge listening on :${PORT}`);
});

function normaliseTelemetry(body: any): TelemetryEvent[] {
  if (Array.isArray(body?.telemetry)) {
    return body.telemetry as TelemetryEvent[];
  }
  if (typeof body?.telemetry_base64 === "string") {
    try {
      const decoded = Buffer.from(body.telemetry_base64, "base64").toString("utf8");
      const parsed = JSON.parse(decoded);
      if (Array.isArray(parsed)) {
        return parsed as TelemetryEvent[];
      }
    } catch (error) {
      throw new Error(`Failed to decode telemetry_base64: ${error}`);
    }
  }
  return [];
}

async function captureControlsFromNetwork(feed: ControlFeed, result: NetworkAnalysisResult): Promise<void> {
  const recommendations: ControlRecommendation[] = [];

  result.detectionArtifacts.sigma?.forEach((rule) => {
    recommendations.push({
      id: rule.id,
      title: rule.title,
      category: "detection",
      description: rule.description,
      source: "sigma",
      priority: "high",
      payload: { query: rule.query, segmentId: result.segmentId, tags: rule.tags },
    });
  });

  result.detectionArtifacts.splunk?.forEach((rule) => {
    recommendations.push({
      id: rule.id,
      title: rule.title,
      category: "detection",
      description: rule.description,
      source: "splunk",
      priority: "high",
      payload: { query: rule.query, tags: rule.tags },
    });
  });

  result.detectionArtifacts.kql?.forEach((rule) => {
    recommendations.push({
      id: rule.id,
      title: rule.title,
      category: "detection",
      description: rule.description,
      source: "sentinel",
      priority: "high",
      payload: { query: rule.query, tags: rule.tags },
    });
  });

  result.gapAnalysis?.forEach((gap, index) => {
    recommendations.push({
      id: `gap-${index}-${result.segmentId}`,
      title: `Address detection gap: ${gap.area}`,
      category: "gap",
      description: gap.description,
      source: "gap-analysis",
      priority: gap.severity,
      payload: { recommendations: gap.recommendations },
    });
  });

  result.integrationHooks?.forEach((hook) => {
    recommendations.push({
      id: `integration-${hook.platform}-${result.segmentId}`,
      title: `Deploy automation hook - ${hook.platform}`,
      category: "automation",
      description: hook.description,
      source: "integration",
      priority: "medium",
      payload: { configuration: hook.configuration, samplePayload: hook.samplePayload },
    });
  });

  await feed.capture(recommendations);
}

function createRecommendationsFromTelemetry(
  simulation: AttackSimulationResult,
  detectionGaps: string[]
): ControlRecommendation[] {
  return detectionGaps.map((gap, index) => ({
    id: `telemetry-gap-${simulation.simulationId}-${index}`,
    title: `Create detection for ${gap}`,
    category: "telemetry-gap",
    description: `Simulation ${simulation.simulationId} identified missing telemetry coverage for ${gap}.`,
    source: "telemetry-replay",
    priority: "high",
    payload: {
      simulationId: simulation.simulationId,
      detectionGap: gap,
    },
  }));
}

function buildIncidentSummary(
  incidentId: string,
  investigation: IncidentInvestigation | undefined
): IncidentSummary {
  if (investigation) {
    return {
      incidentId,
      title: `Security Incident - ${investigation.severity}`,
      severity: investigation.severity,
      status: investigation.status,
      brief: investigation.findings.slice(0, 2).map((f) => f.description).join("; ") || "CyberSim incident summary",
    };
  }

  return {
    incidentId,
    title: "CyberSim Pro Incident",
    severity: "Unknown",
    status: "Open",
    brief: "Incident details not yet captured in CyberSim Pro",
  };
}
