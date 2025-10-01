import { AttackSimulationResult } from "../simulators/threatSimulator.js";
import { SecurityScenario } from "../scenarios/scenarioManager.js";

export interface TelemetryEvent {
  timestamp: string;
  source?: string;
  destination?: string;
  indicator?: string;
  techniqueId?: string;
  description?: string;
  metadata?: Record<string, unknown>;
}

export interface TelemetryReplayRequest {
  simulation?: AttackSimulationResult;
  scenario?: SecurityScenario;
  telemetry: TelemetryEvent[];
}

export interface TelemetryReplayResult {
  totalEvents: number;
  matchedTechniques: Array<{
    techniqueId: string;
    techniqueName: string;
    matchingEvents: TelemetryEvent[];
  }>;
  unmatchedPhases: string[];
  detectionGaps: string[];
  observations: string[];
}

function normalise(value?: string): string {
  return value ? value.toLowerCase() : "";
}

export function replayTelemetry(request: TelemetryReplayRequest): TelemetryReplayResult {
  const { simulation, scenario, telemetry } = request;
  if (!simulation) {
    throw new Error("Telemetry replay requires a simulation context");
  }

  const events = telemetry || [];
  const matchedTechniques: TelemetryReplayResult["matchedTechniques"] = [];
  const unmatchedPhases: string[] = [];
  const detectionGaps: string[] = [];
  const observations: string[] = [];

  simulation.phases.forEach((phase) => {
    const phaseMatches: TelemetryEvent[] = [];
    phase.techniques.forEach((technique) => {
      const identifier = technique.mitreId;
      const techniqueName = technique.name;
      const matches = events.filter((event) => {
        const indicator = normalise(event.indicator);
        const description = normalise(event.description);
        const techniqueId = normalise(event.techniqueId);
        return (
          techniqueId.includes(normalise(identifier)) ||
          description.includes(normalise(identifier)) ||
          description.includes(normalise(techniqueName)) ||
          indicator.includes(normalise(techniqueName))
        );
      });
      if (matches.length) {
        phaseMatches.push(...matches);
        matchedTechniques.push({
          techniqueId: identifier,
          techniqueName,
          matchingEvents: matches,
        });
      } else {
        detectionGaps.push(`${phase.phase} :: ${technique.name}`);
      }
    });
    if (!phaseMatches.length) {
      unmatchedPhases.push(phase.phase);
    }
  });

  if (scenario) {
    observations.push(`Scenario ${scenario.id} (${scenario.type}) matched ${matchedTechniques.length} techniques across telemetry.`);
  } else {
    observations.push(`Simulation ${simulation.simulationId} matched ${matchedTechniques.length} techniques across telemetry.`);
  }

  if (detectionGaps.length) {
    observations.push("Consider creating detections for unmatched techniques listed in detectionGaps.");
  }

  return {
    totalEvents: events.length,
    matchedTechniques,
    unmatchedPhases,
    detectionGaps,
    observations,
  };
}
