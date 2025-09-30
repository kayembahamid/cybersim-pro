import { createServer, IncomingMessage, ServerResponse } from "http";
import { SecurityScenarioManager } from "./scenarios/scenarioManager.js";
import { NetworkSimulator } from "./simulators/networkSimulator.js";
import { ThreatSimulator } from "./simulators/threatSimulator.js";
import { IncidentResponseManager } from "./managers/incidentResponseManager.js";
import { ForensicsAnalyzer } from "./analyzers/forensicsAnalyzer.js";

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
      // Security: optional IP allowlist and Bearer token
      if (!checkIpAllowed(req)) {
        return send(res, 403, { error: "Forbidden: IP not allowed" });
      }
      if (!checkApiKey(req)) {
        return send(res, 401, { error: "Unauthorized: missing or invalid Authorization header" });
      }
      const body = await readJson(req);
      const name = path.substring("/tool/".length);

      switch (name) {
        case "create_scenario": {
          const { type, difficulty, environment } = body || {};
          const scenario = await scenarioManager.createScenario(type, difficulty, environment);
          return send(res, 200, scenario);
        }
        case "simulate_attack": {
          const { attack_type, target, intensity = "medium" } = body || {};
          const out = await threatSimulator.simulateAttack(attack_type, target, intensity);
          return send(res, 200, out);
        }
        case "analyze_network": {
          const { network_segment, duration = 10, focus = ["anomalies"] } = body || {};
          const out = await networkSimulator.analyzeNetwork(network_segment, Number(duration), focus);
          return send(res, 200, out);
        }
        case "investigate_incident": {
          const { incident_id, scope = "initial" } = body || {};
          const out = await incidentManager.investigateIncident(incident_id, scope);
          return send(res, 200, out);
        }
        case "forensics_analysis": {
          const { artifact_type, system_id, analysis_depth = "standard" } = body || {};
          const out = await forensicsAnalyzer.analyzeArtifact(artifact_type, system_id, analysis_depth);
          return send(res, 200, out);
        }
        case "generate_report": {
          const { report_type, incident_ids = [], include_recommendations = true } = body || {};
          const out = await incidentManager.generateReport(report_type, incident_ids, !!include_recommendations);
          return send(res, 200, out);
        }
        default:
          return send(res, 404, { error: `Unknown tool: ${name}` });
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
