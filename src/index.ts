import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
  CallToolResult,
  TextContent,
} from "@modelcontextprotocol/sdk/types.js";
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
import { buildExecutionContext } from "./utils/executionContext.js";
import type { ExecutionContext } from "./utils/executionContext.js";
import { MetricsTracker } from "./utils/metricsTracker.js";
import { ControlFeed, ControlRecommendation } from "./utils/controlFeed.js";
import { replayTelemetry, TelemetryEvent } from "./utils/telemetryAnalyzer.js";
import { buildRiskPayload, RiskSystem } from "./utils/riskSync.js";
import { generateValidationDigest } from "./utils/validationReport.js";

class CyberSimProServer {
  private server: Server;
  private scenarioManager: SecurityScenarioManager;
  private networkSimulator: NetworkSimulator;
  private threatSimulator: ThreatSimulator;
  private incidentManager: IncidentResponseManager;
  private forensicsAnalyzer: ForensicsAnalyzer;
  private auditLogger: AuditLogger;
  private accessControl: AccessControl;
  private metricsTracker: MetricsTracker;
  private controlFeed: ControlFeed;

  constructor() {
    this.server = new Server(
      {
        name: "cybersim-pro",
        version: "1.0.0",
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    // Initialize all components
    this.scenarioManager = new SecurityScenarioManager();
    this.networkSimulator = new NetworkSimulator();
    this.threatSimulator = new ThreatSimulator();
    this.incidentManager = new IncidentResponseManager();
    this.forensicsAnalyzer = new ForensicsAnalyzer();
    this.auditLogger = new AuditLogger();
    this.accessControl = new AccessControl();
    this.metricsTracker = new MetricsTracker();
    this.controlFeed = new ControlFeed();

    this.setupHandlers();
  }

  private setupHandlers(): void {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: this.getTools(),
    }));

    // Handle tool execution
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      const toolArgs = args || {};
      const startedAt = Date.now();
      const operator = (toolArgs.operator || toolArgs.operator_context) as OperatorContext | undefined;
      const approvalToken = typeof toolArgs.approval_token === "string" ? (toolArgs.approval_token as string) : undefined;
      try {
        this.accessControl.enforce(name, operator, approvalToken, null);
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `AccessError: ${(error as Error).message}`,
            } as TextContent,
          ],
          isError: true,
        };
      }

      const invocationArgs = { ...toolArgs, operator };
      delete (invocationArgs as Record<string, unknown>).approval_token;
      delete (invocationArgs as Record<string, unknown>).operator_context;

      const executionContext = buildExecutionContext(operator, null);

      try {
        const data = await this.executeTool(name, invocationArgs, executionContext);
        await this.auditLogger.log({
          timestamp: new Date().toISOString(),
          tool: name,
          status: "success",
          durationMs: Date.now() - startedAt,
          arguments: invocationArgs,
          metadata: {
            ...this.extractMetadata(name, data),
            operatorId: executionContext.actorId,
            operatorRole: executionContext.actorRole,
            provenance: executionContext.provenance,
          },
        });
        return this.formatResult(data);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        await this.auditLogger.log({
          timestamp: new Date().toISOString(),
          tool: name,
          status: "error",
          durationMs: Date.now() - startedAt,
          arguments: invocationArgs,
          errorMessage,
          metadata: {
            operatorId: executionContext.actorId,
            operatorRole: executionContext.actorRole,
            provenance: executionContext.provenance,
          },
        });
        return {
          content: [
            {
              type: "text",
              text: `Error: ${errorMessage}`,
            } as TextContent,
          ],
          isError: true,
        };
      }
    });
  }

  private getTools(): Tool[] {
    return [
      {
        name: "create_scenario",
        description: "Create a cybersecurity training scenario with customizable parameters",
        inputSchema: {
          type: "object",
          properties: {
            type: {
              type: "string",
              enum: ["phishing", "ransomware", "ddos", "data_breach", "insider_threat", "apt"],
              description: "Type of security scenario",
            },
            difficulty: {
              type: "string",
              enum: ["beginner", "intermediate", "advanced", "expert"],
              description: "Difficulty level",
            },
            environment: {
              type: "string",
              description: "Target environment (e.g., corporate, cloud, IoT)",
            },
            sector: {
              type: "string",
              description: "Business sector or mission domain to tailor adversary selection",
            },
            adversary_profile: {
              type: "string",
              description: "Explicit adversary profile key (e.g., apt29, fin7)",
            },
            focus_cves: {
              type: "array",
              items: { type: "string" },
              description: "List of CVE identifiers to emphasize in the scenario",
            },
          },
          required: ["type", "difficulty"],
        },
      },
      {
        name: "simulate_attack",
        description: "Simulate a cyberattack with realistic attack vectors and TTPs",
        inputSchema: {
          type: "object",
          properties: {
            attack_type: {
              type: "string",
              description: "Type of attack to simulate",
            },
            target: {
              type: "string",
              description: "Target system or network segment",
            },
            intensity: {
              type: "string",
              enum: ["low", "medium", "high", "critical"],
              description: "Attack intensity level",
            },
            operator: {
              type: "object",
              description: "Operator metadata enforcing RBAC policies",
            },
            approval_token: {
              type: "string",
              description: "Approval token required for high-impact simulations",
            },
          },
          required: ["attack_type", "target"],
        },
      },
      {
        name: "analyze_network",
        description: "Analyze network traffic and identify potential security issues",
        inputSchema: {
          type: "object",
          properties: {
            network_segment: {
              type: "string",
              description: "Network segment to analyze",
            },
            duration: {
              type: "number",
              description: "Analysis duration in minutes",
            },
            focus: {
              type: "array",
              items: { type: "string" },
              description: "Specific areas to focus on (anomalies, vulnerabilities, threats)",
            },
          },
          required: ["network_segment"],
        },
      },
      {
        name: "investigate_incident",
        description: "Conduct incident response investigation with timeline reconstruction",
        inputSchema: {
          type: "object",
          properties: {
            incident_id: {
              type: "string",
              description: "Unique incident identifier",
            },
            scope: {
              type: "string",
              enum: ["initial", "full", "deep_dive"],
              description: "Investigation scope",
            },
          },
          required: ["incident_id"],
        },
      },
      {
        name: "forensics_analysis",
        description: "Perform digital forensics analysis on system artifacts",
        inputSchema: {
          type: "object",
          properties: {
            artifact_type: {
              type: "string",
              enum: ["memory", "disk", "network", "logs", "registry"],
              description: "Type of artifact to analyze",
            },
            system_id: {
              type: "string",
              description: "System identifier",
            },
            analysis_depth: {
              type: "string",
              enum: ["quick", "standard", "comprehensive"],
              description: "Depth of forensics analysis",
            },
          },
          required: ["artifact_type", "system_id"],
        },
      },
      {
        name: "generate_report",
        description: "Generate comprehensive security assessment or incident reports",
        inputSchema: {
          type: "object",
          properties: {
            report_type: {
              type: "string",
              enum: ["incident", "vulnerability", "compliance", "executive"],
              description: "Type of report to generate",
            },
            incident_ids: {
              type: "array",
              items: { type: "string" },
              description: "Related incident IDs",
            },
            include_recommendations: {
              type: "boolean",
              description: "Include remediation recommendations",
            },
            mode: {
              type: "string",
              description: "Optional rendering mode (standard, facilitation, executive)",
              enum: ["standard", "facilitation", "executive"],
            },
          },
          required: ["report_type"],
        },
      },
      {
        name: "stop_simulation",
        description: "Manually stop one or more active simulations for safety or compliance",
        inputSchema: {
          type: "object",
          properties: {
            simulation_id: {
              type: "string",
              description: "Identifier returned by simulate_attack. If omitted, all active simulations are stopped.",
            },
            reason: {
              type: "string",
              description: "Reason for terminating the simulation (for audit logging).",
            },
            operator: {
              type: "object",
              description: "Operator context (id, role, approvals)",
            },
            approval_token: {
              type: "string",
              description: "Approval token required by governance policy (if configured).",
            },
          },
        },
      },
      {
        name: "replay_telemetry",
        description: "Replay lab telemetry (PCAP/EDR/SIEM exports) against a simulation to identify coverage gaps",
        inputSchema: {
          type: "object",
          properties: {
            simulation_id: {
              type: "string",
              description: "Simulation identifier returned by simulate_attack",
            },
            scenario_id: {
              type: "string",
              description: "Optional scenario identifier to contextualise telemetry",
            },
            telemetry: {
              type: "array",
              description: "Array of telemetry events (e.g., SIEM or EDR events)",
              items: {
                type: "object",
              },
            },
            telemetry_base64: {
              type: "string",
              description: "Base64-encoded JSON array of telemetry events (alternative to telemetry array)",
            },
            operator: {
              type: "object",
              description: "Operator context required for restricted playback",
            },
            approval_token: {
              type: "string",
            },
          },
          required: ["simulation_id"],
        },
      },
      {
        name: "list_metrics",
        description: "Summarise historical exercise metrics and readiness trends",
        inputSchema: {
          type: "object",
          properties: {},
        },
      },
      {
        name: "export_controls",
        description: "Export recommended compensating controls derived from CyberSim analyses",
        inputSchema: {
          type: "object",
          properties: {},
        },
      },
      {
        name: "sync_risk_register",
        description: "Generate payloads for updating enterprise risk registers (ServiceNow, Archer, OneTrust)",
        inputSchema: {
          type: "object",
          properties: {
            system: {
              type: "string",
              enum: ["servicenow", "archer", "onetrust", "custom"],
              description: "Target risk/governance system",
            },
            incident_id: {
              type: "string",
              description: "Incident identifier to synchronise",
            },
            priority: {
              type: "string",
            },
            owner: {
              type: "string",
            },
            due_date: {
              type: "string",
              description: "Optional due date for remediation",
            },
          },
          required: ["system", "incident_id"],
        },
      },
      {
        name: "generate_validation_report",
        description: "Produce an auditor-facing validation digest of recent CyberSim activity",
        inputSchema: {
          type: "object",
          properties: {},
        },
      },
    ];
  }

  private async executeTool(name: string, args: any, context: ExecutionContext): Promise<unknown> {
    switch (name) {
      case "create_scenario":
        return await this.handleCreateScenario(args, context);
      case "simulate_attack":
        return await this.handleSimulateAttack(args, context);
      case "analyze_network":
        return await this.handleAnalyzeNetwork(args, context);
      case "investigate_incident":
        return await this.handleInvestigateIncident(args, context);
      case "forensics_analysis":
        return await this.handleForensicsAnalysis(args, context);
      case "generate_report":
        return await this.handleGenerateReport(args, context);
      case "stop_simulation":
        return await this.handleStopSimulation(args, context);
      case "replay_telemetry":
        return await this.handleReplayTelemetry(args, context);
      case "list_metrics":
        return await this.handleListMetrics(context);
      case "export_controls":
        return await this.handleExportControls(context);
      case "sync_risk_register":
        return await this.handleSyncRiskRegister(args, context);
      case "generate_validation_report":
        return await this.handleValidationReport(context);
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }

  private formatResult(data: unknown): CallToolResult {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(data, null, 2),
        } as TextContent,
      ],
    };
  }

  private async handleCreateScenario(args: any, context: ExecutionContext): Promise<unknown> {
    return await this.scenarioManager.createScenario(
      args.type,
      args.difficulty,
      args.environment,
      {
        sector: args.sector,
        adversaryProfile: args.adversary_profile,
        cveFocus: args.focus_cves,
      },
      context
    );
  }

  private async handleSimulateAttack(args: any, context: ExecutionContext): Promise<unknown> {
    const result = await this.threatSimulator.simulateAttack(
      args.attack_type,
      args.target,
      args.intensity || "medium",
      context
    );
    await this.metricsTracker.record("simulate_attack", {
      simulationId: result.simulationId,
      attackType: result.attackType,
      target: result.target,
      detectionRate: result.detectionRate,
      intensity: result.intensity,
    }, context.provenance);
    return result;
  }

  private async handleAnalyzeNetwork(args: any, context: ExecutionContext): Promise<unknown> {
    const result = await this.networkSimulator.analyzeNetwork(
      args.network_segment,
      args.duration || 10,
      args.focus || ["anomalies"],
      context
    );
    await this.captureControlsFromNetwork(result, context);
    return result;
  }

  private async handleInvestigateIncident(args: any, context: ExecutionContext): Promise<unknown> {
    return await this.incidentManager.investigateIncident(
      args.incident_id,
      args.scope || "initial",
      context
    );
  }

  private async handleForensicsAnalysis(args: any, context: ExecutionContext): Promise<unknown> {
    return await this.forensicsAnalyzer.analyzeArtifact(
      args.artifact_type,
      args.system_id,
      args.analysis_depth || "standard",
      context
    );
  }

  private async handleGenerateReport(args: any, context: ExecutionContext): Promise<unknown> {
    const report = await this.incidentManager.generateReport(
      args.report_type,
      args.incident_ids || [],
      args.include_recommendations !== false,
      args.mode,
      context
    );
    await this.metricsTracker.record("generate_report", {
      reportId: report.reportId,
      reportType: report.reportType,
      detectionLatencyHours: report.metrics.mttd,
      containmentTimeHours: report.metrics.mttr,
      incidentCount: report.metrics.incidentCount,
    }, context.provenance);
    return report;
  }

  private async handleStopSimulation(args: any, _context: ExecutionContext): Promise<unknown> {
    const targetId: string | undefined = args.simulation_id;
    const reason: string | undefined = args.reason;

    if (targetId) {
      const result = this.threatSimulator.stopSimulation(targetId, reason);
      if (!result) {
        throw new Error(`No active simulation found for id ${targetId}`);
      }
      return {
        message: `Simulation ${targetId} terminated`,
        simulation: result,
      };
    }

    const terminated = this.threatSimulator.stopAllSimulations(reason);
    return {
      message: terminated.length
        ? `Terminated ${terminated.length} simulations`
        : "No active simulations to terminate",
      simulations: terminated,
    };
  }

  private async handleReplayTelemetry(args: any, context: ExecutionContext): Promise<unknown> {
    const simulationId: string = args.simulation_id;
    const scenarioId: string | undefined = args.scenario_id;
    const simulation = this.threatSimulator.getSimulation(simulationId);
    if (!simulation) {
      throw new Error(`No active simulation found for id ${simulationId}`);
    }

    const scenario = scenarioId ? this.scenarioManager.getScenario(scenarioId) : undefined;
    const telemetry = this.normaliseTelemetry(args);
    const result = replayTelemetry({
      simulation,
      scenario,
      telemetry,
    });

    const recommendations = this.createRecommendationsFromTelemetry(simulation, result.detectionGaps, context);
    await this.controlFeed.capture(recommendations);
    await this.metricsTracker.record("replay_telemetry", {
      simulationId,
      totalEvents: result.totalEvents,
      matchedTechniques: result.matchedTechniques.length,
      detectionGaps: result.detectionGaps.length,
    }, context.provenance);

    return result;
  }

  private async handleListMetrics(_context: ExecutionContext): Promise<unknown> {
    return await this.metricsTracker.summarize();
  }

  private async handleExportControls(_context: ExecutionContext): Promise<unknown> {
    return await this.controlFeed.export();
  }

  private async handleSyncRiskRegister(args: any, _context: ExecutionContext): Promise<unknown> {
    const system = args.system as RiskSystem;
    const incidentId = args.incident_id as string;
    const investigations = this.incidentManager.listInvestigations();
    const investigation = investigations.find((item) => item.incidentId === incidentId);
    const incidentSummary = this.buildIncidentSummary(incidentId, investigation);

    const payload = buildRiskPayload({
      system,
      incident: incidentSummary,
      investigation,
      priority: args.priority,
      owner: args.owner,
      dueDate: args.due_date,
    });

    return payload;
  }

  private async handleValidationReport(_context: ExecutionContext): Promise<unknown> {
    const logPath = this.auditLogger.getLogFilePath();
    return await generateValidationDigest(logPath);
  }

  private normaliseTelemetry(args: any): TelemetryEvent[] {
    if (Array.isArray(args.telemetry)) {
      return args.telemetry as TelemetryEvent[];
    }

    if (typeof args.telemetry_base64 === "string") {
      try {
        const decoded = Buffer.from(args.telemetry_base64, "base64").toString("utf8");
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

  private async captureControlsFromNetwork(result: NetworkAnalysisResult, context: ExecutionContext): Promise<void> {
    const recommendations: ControlRecommendation[] = [];

    result.detectionArtifacts.sigma?.forEach((rule) => {
      recommendations.push({
        id: rule.id,
        title: rule.title,
        category: "detection",
        description: rule.description,
        source: "sigma",
        priority: "high",
        payload: {
          segmentId: result.segmentId,
          query: rule.query,
          tags: rule.tags,
        },
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
        payload: {
          query: rule.query,
          tags: rule.tags,
        },
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
        payload: {
          query: rule.query,
          tags: rule.tags,
        },
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
        payload: {
          recommendations: gap.recommendations,
        },
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
        payload: {
          configuration: hook.configuration,
          samplePayload: hook.samplePayload,
        },
        executedBy: context.actorId,
        provenance: context.provenance,
      });
    });

    await this.controlFeed.capture(recommendations);
  }

  private createRecommendationsFromTelemetry(
    simulation: AttackSimulationResult,
    detectionGaps: string[],
    context: ExecutionContext
  ): ControlRecommendation[] {
    return detectionGaps.map((gap, index) => ({
      id: `telemetry-gap-${simulation.simulationId}-${index}`,
      title: `Create detection for ${gap}`,
      category: "telemetry-gap",
      description: `Simulation ${simulation.simulationId} identified missing telemetry coverage for ${gap}.` ,
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

  private buildIncidentSummary(
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

  private extractMetadata(tool: string, data: unknown): Record<string, unknown> | undefined {
    if (!data || typeof data !== "object") {
      return undefined;
    }

    switch (tool) {
      case "create_scenario":
        return {
          scenarioId: (data as { id?: string }).id,
          difficulty: (data as { difficulty?: string }).difficulty,
          type: (data as { type?: string }).type,
        };
      case "simulate_attack":
        return {
          simulationId: (data as { simulationId?: string }).simulationId,
          target: (data as { target?: string }).target,
          intensity: (data as { intensity?: string }).intensity,
          status: (data as { status?: string }).status,
        };
      case "stop_simulation":
        if (Array.isArray((data as { simulations?: unknown[] }).simulations)) {
          const list = (data as { simulations?: { simulationId?: string }[] }).simulations || [];
          return {
            terminatedCount: list.length,
            simulationIds: list.map((item) => item?.simulationId).filter(Boolean),
          };
        }
        if ((data as { simulation?: { simulationId?: string; stopReason?: string } }).simulation) {
          const sim = (data as { simulation: { simulationId?: string; stopReason?: string } }).simulation;
          return {
            terminatedCount: 1,
            simulationId: sim.simulationId,
            stopReason: sim.stopReason,
          };
        }
        return undefined;
      case "replay_telemetry":
        return {
          matchedTechniques: (data as { matchedTechniques?: unknown[] }).matchedTechniques
            ? (data as { matchedTechniques: unknown[] }).matchedTechniques.length
            : 0,
          detectionGaps: (data as { detectionGaps?: unknown[] }).detectionGaps
            ? (data as { detectionGaps: unknown[] }).detectionGaps.length
            : 0,
        };
      case "list_metrics":
        return {
          totalExercises: (data as { totalExercises?: number }).totalExercises,
          reportsGenerated: (data as { reportsGenerated?: number }).reportsGenerated,
        };
      case "export_controls":
        return {
          controlCount: Array.isArray(data) ? data.length : 0,
        };
      case "sync_risk_register":
        return {
          system: (data as { targetSystem?: string }).targetSystem,
          endpoint: (data as { endpoint?: string }).endpoint,
        };
      case "generate_validation_report":
        return {
          totalEntries: (data as { totalEntries?: number }).totalEntries,
          hash: (data as { hash?: string }).hash,
        };
      case "generate_report":
        return {
          reportType: (data as { reportType?: string }).reportType,
          detectionLatency: (data as { metrics?: { mttd?: number } }).metrics?.mttd,
          containmentTime: (data as { metrics?: { mttr?: number } }).metrics?.mttr,
        };
      default:
        return undefined;
    }
  }

  async run(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error("CyberSim Pro MCP server running on stdio");
  }
}

// Start the server
const server = new CyberSimProServer();
server.run().catch(console.error);
