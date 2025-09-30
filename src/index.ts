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
import { NetworkSimulator } from "./simulators/networkSimulator.js";
import { ThreatSimulator } from "./simulators/threatSimulator.js";
import { IncidentResponseManager } from "./managers/incidentResponseManager.js";
import { ForensicsAnalyzer } from "./analyzers/forensicsAnalyzer.js";

class CyberSimProServer {
  private server: Server;
  private scenarioManager: SecurityScenarioManager;
  private networkSimulator: NetworkSimulator;
  private threatSimulator: ThreatSimulator;
  private incidentManager: IncidentResponseManager;
  private forensicsAnalyzer: ForensicsAnalyzer;

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

      try {
        switch (name) {
          case "create_scenario":
            return await this.handleCreateScenario(args);
          case "simulate_attack":
            return await this.handleSimulateAttack(args);
          case "analyze_network":
            return await this.handleAnalyzeNetwork(args);
          case "investigate_incident":
            return await this.handleInvestigateIncident(args);
          case "forensics_analysis":
            return await this.handleForensicsAnalysis(args);
          case "generate_report":
            return await this.handleGenerateReport(args);
          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
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
          },
          required: ["report_type"],
        },
      },
    ];
  }

  private async handleCreateScenario(args: any): Promise<CallToolResult> {
    const scenario = await this.scenarioManager.createScenario(
      args.type,
      args.difficulty,
      args.environment
    );
    
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(scenario, null, 2),
        } as TextContent,
      ],
    };
  }

  private async handleSimulateAttack(args: any): Promise<CallToolResult> {
    const result = await this.threatSimulator.simulateAttack(
      args.attack_type,
      args.target,
      args.intensity || "medium"
    );
    
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        } as TextContent,
      ],
    };
  }

  private async handleAnalyzeNetwork(args: any): Promise<CallToolResult> {
    const analysis = await this.networkSimulator.analyzeNetwork(
      args.network_segment,
      args.duration || 10,
      args.focus || ["anomalies"]
    );
    
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(analysis, null, 2),
        } as TextContent,
      ],
    };
  }

  private async handleInvestigateIncident(args: any): Promise<CallToolResult> {
    const investigation = await this.incidentManager.investigateIncident(
      args.incident_id,
      args.scope || "initial"
    );
    
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(investigation, null, 2),
        } as TextContent,
      ],
    };
  }

  private async handleForensicsAnalysis(args: any): Promise<CallToolResult> {
    const forensics = await this.forensicsAnalyzer.analyzeArtifact(
      args.artifact_type,
      args.system_id,
      args.analysis_depth || "standard"
    );
    
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(forensics, null, 2),
        } as TextContent,
      ],
    };
  }

  private async handleGenerateReport(args: any): Promise<CallToolResult> {
    const report = await this.incidentManager.generateReport(
      args.report_type,
      args.incident_ids || [],
      args.include_recommendations !== false
    );
    
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(report, null, 2),
        } as TextContent,
      ],
    };
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