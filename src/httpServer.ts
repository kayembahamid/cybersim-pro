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
import { buildExecutionContext } from "./utils/executionContext.js";
import type { ExecutionContext } from "./utils/executionContext.js";
import { replayTelemetry, TelemetryEvent } from "./utils/telemetryAnalyzer.js";
import { buildRiskPayload, RiskSystem } from "./utils/riskSync.js";
import { generateValidationDigest } from "./utils/validationReport.js";
import { loadIdentityConfig } from "./identity/identityConfig.js";
import { RoleMapper } from "./identity/roleMapper.js";
import { AuthGateway, IdentitySession } from "./identity/authGateway.js";
import { ScimProvisioner, ScimGroup, ScimUser } from "./identity/scimProvisioner.js";

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

function readBodyText(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk) => {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    });
    req.on("end", () => {
      resolve(Buffer.concat(chunks).toString("utf8"));
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

function sendXml(res: ServerResponse, status: number, xml: string): void {
  res.writeHead(status, {
    "Content-Type": "application/xml; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
  });
  res.end(xml);
}

function extractSessionToken(req: IncomingMessage, body: any): string | undefined {
  const headerValue = req.headers["x-cybersim-session"] || req.headers["X-Cybersim-Session" as any];
  if (typeof headerValue === "string" && headerValue.trim()) {
    return headerValue.trim();
  }
  if (Array.isArray(headerValue)) {
    const token = headerValue.find((value) => typeof value === "string" && value.trim());
    if (token) {
      return token.trim();
    }
  }
  if (typeof body?.session_token === "string" && body.session_token.trim()) {
    return body.session_token.trim();
  }
  if (typeof body?.sessionToken === "string" && body.sessionToken.trim()) {
    return body.sessionToken.trim();
  }
  return undefined;
}

function mergeOperatorContext(
  operator: OperatorContext | undefined,
  session: IdentitySession | null
): OperatorContext | undefined {
  const combinedApprovals = new Set<string>();
  (operator?.approvals ?? []).forEach((value) => combinedApprovals.add(value));
  (session?.approvals ?? []).forEach((value) => combinedApprovals.add(value));

  const merged: OperatorContext = {
    id: operator?.id ?? session?.userId,
    role: operator?.role ?? session?.roles?.[0],
    approvals: combinedApprovals.size > 0 ? Array.from(combinedApprovals) : undefined,
  };

  if (!merged.id && !merged.role && !merged.approvals) {
    return operator;
  }

  return merged;
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
const identityConfig = loadIdentityConfig();
const roleMapper = new RoleMapper(identityConfig.roleMappingsPath);
const authGateway = new AuthGateway(identityConfig.sso, roleMapper, auditLogger);
const scimProvisioner = new ScimProvisioner(identityConfig.scim, auditLogger);

const PORT = Number(process.env.PORT || 8787);
const API_KEY = (process.env.CYBERSIM_API_KEY || "").trim();
const IP_ALLOW = (process.env.CYBERSIM_IP_ALLOW || "").trim();
const SCIM_BEARER = (identityConfig.scim?.bearerToken || process.env.CYBERSIM_SCIM_TOKEN || "").trim();

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

function extractBearerToken(req: IncomingMessage): string | undefined {
  const auth = req.headers["authorization"] || req.headers["Authorization" as any];
  if (!auth || Array.isArray(auth)) return undefined;
  if (!auth.startsWith("Bearer ")) return undefined;
  return auth.slice("Bearer ".length).trim();
}

function checkScimAuth(req: IncomingMessage): boolean {
  if (!SCIM_BEARER) {
    return false;
  }
  const token = extractBearerToken(req);
  return token === SCIM_BEARER;
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

    if (req.method === "GET" && path === "/api/sso/metadata") {
      const metadata = authGateway.getSamlMetadata();
      if (!metadata) {
        return send(res, 404, { error: "SAML metadata not available" });
      }
      return sendXml(res, 200, metadata);
    }

    if (req.method === "POST" && path === "/api/sso/assert") {
      if (!authGateway.isEnabled()) {
        return send(res, 404, { error: "SSO gateway not configured" });
      }
      try {
        const contentType = String(req.headers["content-type"] || "");
        let samlResponse: string | undefined;
        if (contentType.includes("application/x-www-form-urlencoded")) {
          const text = await readBodyText(req);
          const params = new URLSearchParams(text);
          samlResponse = params.get("SAMLResponse") ?? undefined;
        } else {
          const body = await readJson(req);
          samlResponse = body?.SAMLResponse || body?.samlResponse;
        }
        if (!samlResponse) {
          return send(res, 400, { error: "Missing SAMLResponse" });
        }
        const session = await authGateway.handleSamlResponse(samlResponse);
        return send(res, 200, serializeSession(session));
      } catch (error) {
        return send(res, 400, { error: (error as Error).message });
      }
    }

    if (req.method === "POST" && path === "/api/auth/oidc/callback") {
      if (!authGateway.isEnabled()) {
        return send(res, 404, { error: "SSO gateway not configured" });
      }
      try {
        const body = await readJson(req);
        const idToken = body?.id_token || body?.idToken;
        if (typeof idToken !== "string") {
          return send(res, 400, { error: "Missing id_token" });
        }
        const session = await authGateway.handleOidcCallback(idToken);
        return send(res, 200, serializeSession(session));
      } catch (error) {
        return send(res, 400, { error: (error as Error).message });
      }
    }

    if (req.method === "GET" && path === "/api/auth/session") {
      const token = extractBearerToken(req);
      const session = authGateway.getSession(token);
      if (!session) {
        return send(res, 401, { error: "Invalid or expired session" });
      }
      return send(res, 200, serializeSession(session));
    }

    if (path.startsWith("/api/scim/")) {
      if (!scimProvisioner.isEnabled()) {
        return send(res, 404, { error: "SCIM provisioning disabled" });
      }
      if (!SCIM_BEARER) {
        return send(res, 503, { error: "SCIM bearer token not configured" });
      }
      if (!checkScimAuth(req)) {
        return send(res, 401, { error: "Unauthorized" });
      }
      await handleScimRequest(req, res, path, url.searchParams);
      return;
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
      const sessionToken = extractSessionToken(req, body);
      let identitySession: IdentitySession | null = null;
      if (sessionToken) {
        identitySession = authGateway.getSession(sessionToken);
        if (!identitySession) {
          return send(res, 401, { error: "Invalid or expired identity session" });
        }
      }

      const operatorInput = (body?.operator || body?.operator_context) as OperatorContext | undefined;
      const effectiveOperator = mergeOperatorContext(operatorInput, identitySession);
      const approvalToken = typeof body?.approval_token === "string" ? (body.approval_token as string) : undefined;
      const sanitizedArgs = JSON.parse(JSON.stringify(body || {}));
      delete sanitizedArgs.approval_token;
      delete sanitizedArgs.operator_context;
      delete sanitizedArgs.operator;
      delete sanitizedArgs.session_token;
      delete sanitizedArgs.sessionToken;
      const startedAt = Date.now();
      const executionContext = buildExecutionContext(effectiveOperator, identitySession);
      const actorId = executionContext.actorId ?? operatorInput?.id;

      try {
        accessControl.enforce(name, effectiveOperator, approvalToken, identitySession);
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
            }, executionContext);
            out = scenario;
            metadata = { scenarioId: scenario.id, executedBy: actorId };
            break;
          }
          case "simulate_attack": {
            const { attack_type, target, intensity = "medium" } = body || {};
            const result = await threatSimulator.simulateAttack(attack_type, target, intensity, executionContext);
            await metricsTracker.record("simulate_attack", {
              simulationId: result.simulationId,
              attackType: result.attackType,
              target: result.target,
              detectionRate: result.detectionRate,
              intensity: result.intensity,
              executedBy: actorId,
            }, executionContext.provenance);
            out = result;
            metadata = { simulationId: result.simulationId };
            break;
          }
          case "analyze_network": {
            const { network_segment, duration = 10, focus = ["anomalies"] } = body || {};
            const result = await networkSimulator.analyzeNetwork(
              network_segment,
              Number(duration),
              focus,
              executionContext
            );
            await captureControlsFromNetwork(controlFeed, result, executionContext);
            out = result;
            metadata = { segmentId: result.segmentId, executedBy: actorId };
            break;
          }
          case "investigate_incident": {
            const { incident_id, scope = "initial" } = body || {};
            const result = await incidentManager.investigateIncident(incident_id, scope, executionContext);
            out = result;
            metadata = { incidentId: result.incidentId, executedBy: actorId };
            break;
          }
          case "forensics_analysis": {
            const { artifact_type, system_id, analysis_depth = "standard" } = body || {};
            const result = await forensicsAnalyzer.analyzeArtifact(
              artifact_type,
              system_id,
              analysis_depth,
              executionContext
            );
            out = result;
            metadata = { systemId: system_id, artifactType: artifact_type, executedBy: actorId };
            break;
          }
          case "generate_report": {
            const { report_type, incident_ids = [], include_recommendations = true, mode } = body || {};
            const result = await incidentManager.generateReport(
              report_type,
              incident_ids,
              !!include_recommendations,
              mode,
              executionContext
            );
            await metricsTracker.record("generate_report", {
              reportId: result.reportId,
              reportType: result.reportType,
              detectionLatencyHours: result.metrics.mttd,
              containmentTimeHours: result.metrics.mttr,
              incidentCount: result.metrics.incidentCount,
              executedBy: actorId,
            }, executionContext.provenance);
            out = result;
            metadata = { reportId: result.reportId, reportType: result.reportType, executedBy: actorId };
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
              metadata = { simulationId: simulation_id, executedBy: actorId };
            } else {
              const terminated = threatSimulator.stopAllSimulations(reason);
              out = {
                message: terminated.length ? `Terminated ${terminated.length} simulations` : "No active simulations to terminate",
                simulations: terminated,
              };
              metadata = { terminatedCount: terminated.length, executedBy: actorId };
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
            const recs = createRecommendationsFromTelemetry(simulation, result.detectionGaps, executionContext);
            await controlFeed.capture(recs);
            await metricsTracker.record("replay_telemetry", {
              simulationId,
              totalEvents: result.totalEvents,
              matchedTechniques: result.matchedTechniques.length,
              detectionGaps: result.detectionGaps.length,
              executedBy: actorId,
            }, executionContext.provenance);
            out = result;
            metadata = { simulationId, detectionGaps: result.detectionGaps.length, executedBy: actorId };
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

        const auditMetadata = {
          ...metadata,
          operatorId: executionContext.actorId ?? operatorInput?.id,
          operatorRole: executionContext.actorRole ?? operatorInput?.role,
          identityUserId: executionContext.identity?.userId,
          identityRoles: executionContext.identity?.roles,
          identityProtocol: executionContext.identity?.protocol,
          identityMfaSatisfied: executionContext.identity?.mfaSatisfied,
          provenance: executionContext.provenance,
        };

        await auditLogger.log({
          timestamp: new Date().toISOString(),
          tool: name,
          status: "success",
          durationMs: Date.now() - startedAt,
          arguments: sanitizedArgs,
          metadata: auditMetadata,
        });

        const responseBody = (out ?? null) as Json;
        return send(res, 200, responseBody);
      } catch (error) {
        const errorMetadata = {
          operatorId: executionContext.actorId ?? operatorInput?.id,
          operatorRole: executionContext.actorRole ?? operatorInput?.role,
          identityUserId: executionContext.identity?.userId,
          identityRoles: executionContext.identity?.roles,
          identityProtocol: executionContext.identity?.protocol,
          identityMfaSatisfied: executionContext.identity?.mfaSatisfied,
          provenance: executionContext.provenance,
        };

        await auditLogger.log({
          timestamp: new Date().toISOString(),
          tool: name,
          status: "error",
          durationMs: Date.now() - startedAt,
          arguments: sanitizedArgs,
          errorMessage: error instanceof Error ? error.message : String(error),
          metadata: errorMetadata,
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

function serializeSession(session: IdentitySession): Record<string, unknown> {
  return {
    token: session.token,
    userId: session.userId,
    email: session.email,
    roles: session.roles,
    approvals: session.approvals,
    groups: session.groups,
    requiresMfa: session.requiresMfa,
    mfaSatisfied: session.mfaSatisfied,
    protocol: session.protocol,
    issuedAt: session.issuedAt.toISOString(),
    expiresAt: session.expiresAt.toISOString(),
  };
}

async function handleScimRequest(
  req: IncomingMessage,
  res: ServerResponse,
  path: string,
  query: URLSearchParams
): Promise<void> {
  if (!scimProvisioner.isEnabled()) {
    return send(res, 404, { error: "SCIM provisioning disabled" });
  }

  const segments = path.split("/").filter(Boolean);
  const resource = (segments[3] || "").toLowerCase();
  const identifier = segments[4];
  const baseLocation = scimProvisioner.getBaseUrl();

  switch (resource) {
    case "users": {
      if (req.method === "GET" && !identifier) {
        const users = scimProvisioner.listUsers();
        const resources = users.map((user) => buildUserResource(user, baseLocation, req));
        return send(res, 200, buildScimListResponse(resources, query));
      }

      if (req.method === "POST") {
        const body = await readJson(req);
        const user = scimProvisioner.upsertUser(normaliseScimUserInput(body), "scim");
        const resource = buildUserResource(user, baseLocation, req);
        res.setHeader("Location", resource.meta?.location ?? "");
        return send(res, 201, resource);
      }

      if (identifier && req.method === "GET") {
        const user = scimProvisioner.getUser(identifier);
        if (!user) {
          return send(res, 404, { error: "User not found" });
        }
        return send(res, 200, buildUserResource(user, baseLocation, req));
      }

      if (identifier && req.method === "PATCH") {
        const existing = scimProvisioner.getUser(identifier);
        if (!existing) {
          return send(res, 404, { error: "User not found" });
        }
        const body = await readJson(req);
        applyUserPatch(existing, body);
        const updated = scimProvisioner.upsertUser(existing, "scim");
        return send(res, 200, buildUserResource(updated, baseLocation, req));
      }

      if (identifier && req.method === "DELETE") {
        const user = scimProvisioner.deactivateUser(identifier, "scim");
        if (!user) {
          return send(res, 404, { error: "User not found" });
        }
        return send(res, 200, buildUserResource(user, baseLocation, req));
      }

      break;
    }

    case "groups": {
      if (req.method === "GET" && !identifier) {
        const groups = scimProvisioner.listGroups();
        const resources = groups.map((group) => buildGroupResource(group, baseLocation, req));
        return send(res, 200, buildScimListResponse(resources, query));
      }

      if (req.method === "POST") {
        const body = await readJson(req);
        const group = scimProvisioner.upsertGroup(normaliseScimGroupInput(body), "scim");
        const resource = buildGroupResource(group, baseLocation, req);
        res.setHeader("Location", resource.meta?.location ?? "");
        return send(res, 201, resource);
      }

      if (identifier && req.method === "GET") {
        const group = scimProvisioner.getGroup(identifier);
        if (!group) {
          return send(res, 404, { error: "Group not found" });
        }
        return send(res, 200, buildGroupResource(group, baseLocation, req));
      }

      if (identifier && req.method === "PATCH") {
        const existing = scimProvisioner.getGroup(identifier);
        if (!existing) {
          return send(res, 404, { error: "Group not found" });
        }
        const body = await readJson(req);
        applyGroupPatch(existing, body);
        const updated = scimProvisioner.upsertGroup(existing, "scim");
        return send(res, 200, buildGroupResource(updated, baseLocation, req));
      }

      if (identifier && req.method === "DELETE") {
        scimProvisioner.removeGroup(identifier, "scim");
        res.writeHead(204);
        res.end();
        return;
      }

      break;
    }
  }

  return send(res, 404, { error: "Unsupported SCIM endpoint" });
}

function buildScimListResponse(resources: any[], query: URLSearchParams) {
  const startIndex = Number(query.get("startIndex") || "1");
  const itemsPerPage = Number(query.get("count") || resources.length || 0);
  return {
    schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
    totalResults: resources.length,
    startIndex,
    itemsPerPage,
    Resources: resources,
  };
}

function buildUserResource(user: ScimUser, baseLocation: string | undefined, req: IncomingMessage) {
  const base = baseLocation || deriveBaseUrl(req);
  return {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    id: user.id,
    userName: user.userName,
    active: user.active,
    emails: user.emails,
    groups: user.groups,
    meta: {
      resourceType: "User",
      location: base ? `${base}/Users/${user.id}` : undefined,
    },
  };
}

function buildGroupResource(group: ScimGroup, baseLocation: string | undefined, req: IncomingMessage) {
  const base = baseLocation || deriveBaseUrl(req);
  return {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    id: group.id,
    displayName: group.displayName,
    members: group.members,
    meta: {
      resourceType: "Group",
      location: base ? `${base}/Groups/${group.id}` : undefined,
    },
  };
}

function normaliseScimUserInput(input: any): Partial<ScimUser> & { userName: string } {
  const id = typeof input?.id === "string" ? input.id : undefined;
  const emails = Array.isArray(input?.emails)
    ? input.emails
        .filter((item: any) => typeof item?.value === "string")
        .map((item: any) => ({ value: item.value as string, primary: Boolean(item?.primary) }))
    : undefined;
  const groups = parseGroupRefs(input?.groups);
  const result: Partial<ScimUser> & { userName: string } = {
    userName: String(input?.userName ?? input?.username ?? input?.displayName ?? "user"),
    active: input?.active !== undefined ? Boolean(input.active) : true,
    emails,
    groups,
    raw: typeof input === "object" ? input : {},
  };
  if (id) {
    result.id = id;
  }
  return result;
}

function normaliseScimGroupInput(input: any): Partial<ScimGroup> & { displayName: string } {
  const id = typeof input?.id === "string" ? input.id : undefined;
  const members = parseMemberRefs(input?.members);
  const result: Partial<ScimGroup> & { displayName: string } = {
    displayName: String(input?.displayName ?? input?.name ?? "group"),
    members,
    raw: typeof input === "object" ? input : {},
  };
  if (id) {
    result.id = id;
  }
  return result;
}

function parseGroupRefs(value: any): Array<{ value: string; display?: string }> {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .filter((entry) => typeof entry?.value === "string")
    .map((entry) => ({ value: entry.value as string, display: typeof entry?.display === "string" ? entry.display : undefined }));
}

function parseMemberRefs(value: any): Array<{ value: string; display?: string }> {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .filter((entry) => typeof entry?.value === "string")
    .map((entry) => ({ value: entry.value as string, display: typeof entry?.display === "string" ? entry.display : undefined }));
}

function applyUserPatch(user: ScimUser, body: any): void {
  const operations = Array.isArray(body?.Operations) ? body.Operations : [];
  for (const operation of operations) {
    const op = String(operation?.op || operation?.operation || "").toLowerCase();
    if (op === "replace") {
      if (typeof operation?.path === "string" && operation.path.toLowerCase() === "active") {
        user.active = Boolean(operation?.value);
      } else if (operation?.value && typeof operation.value === "object" && "active" in operation.value) {
        user.active = Boolean(operation.value.active);
      }
    }
    if (op === "add" && typeof operation?.path === "string" && operation.path.toLowerCase() === "groups") {
      const additions = parseGroupRefs(operation.value);
      const existing = user.groups ?? [];
      additions.forEach((add) => {
        if (!existing.some((entry) => entry.value === add.value)) {
          existing.push(add);
        }
      });
      user.groups = existing;
    }
    if (op === "remove" && typeof operation?.path === "string" && operation.path.toLowerCase().startsWith("groups")) {
      const match = operation.path.match(/groups\[(.*)\]/i);
      if (match && user.groups) {
        const target = match[1].replace(/value eq \"/i, "").replace(/\"$/, "");
        user.groups = user.groups.filter((entry) => entry.value !== target);
      }
    }
  }
}

function applyGroupPatch(group: ScimGroup, body: any): void {
  const operations = Array.isArray(body?.Operations) ? body.Operations : [];
  for (const operation of operations) {
    const op = String(operation?.op || operation?.operation || "").toLowerCase();
    if (op === "replace" && operation?.value && typeof operation.value === "object" && Array.isArray(operation.value.members)) {
      group.members = parseMemberRefs(operation.value.members);
    }
  }
}

function deriveBaseUrl(req: IncomingMessage): string | undefined {
  const host = req.headers.host;
  if (!host) return undefined;
  const proto = typeof req.headers["x-forwarded-proto"] === "string" ? (req.headers["x-forwarded-proto"] as string) : "https";
  return `${proto}://${host}/api/scim/v2`;
}

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

async function captureControlsFromNetwork(
  feed: ControlFeed,
  result: NetworkAnalysisResult,
  context: ExecutionContext
): Promise<void> {
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
      executedBy: context.actorId,
      provenance: context.provenance,
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
      executedBy: context.actorId,
      provenance: context.provenance,
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
      executedBy: context.actorId,
      provenance: context.provenance,
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
      executedBy: context.actorId,
      provenance: context.provenance,
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
      executedBy: context.actorId,
      provenance: context.provenance,
    });
  });

  await feed.capture(recommendations);
}

function createRecommendationsFromTelemetry(
  simulation: AttackSimulationResult,
  detectionGaps: string[],
  context: ExecutionContext
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
    executedBy: context.actorId,
    provenance: context.provenance,
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
