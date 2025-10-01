import fs from "fs";
import path from "path";

export interface MetricRecord {
  timestamp: string;
  tool: string;
  data: Record<string, unknown>;
}

export interface MetricsSummary {
  totalExercises: number;
  averageDetectionLatency?: number;
  averageContainmentTime?: number;
  reportsGenerated: number;
  trend: MetricRecord[];
}

export class MetricsTracker {
  private metricsDir: string;
  private metricsFile: string;

  constructor(metricsDirectory = path.join(process.cwd(), "metrics"), metricsFileName = "metrics.jsonl") {
    this.metricsDir = metricsDirectory;
    this.metricsFile = path.join(metricsDirectory, metricsFileName);
  }

  async record(tool: string, data: Record<string, unknown>): Promise<void> {
    await fs.promises.mkdir(this.metricsDir, { recursive: true });
    const entry: MetricRecord = {
      timestamp: new Date().toISOString(),
      tool,
      data,
    };
    await fs.promises.appendFile(this.metricsFile, JSON.stringify(entry) + "\n", { encoding: "utf8" });
  }

  async summarize(): Promise<MetricsSummary> {
    const records = await this.readAll();
    let totalExercises = 0;
    let totalDetectionLatency = 0;
    let detectionCount = 0;
    let totalContainment = 0;
    let containmentCount = 0;
    let reportsGenerated = 0;

    records.forEach((record) => {
      if (record.tool === "simulate_attack") {
        totalExercises += 1;
      }
      if (record.tool === "generate_report") {
        reportsGenerated += 1;
        if (typeof record.data?.detectionLatencyHours === "number") {
          totalDetectionLatency += record.data.detectionLatencyHours;
          detectionCount += 1;
        }
        if (typeof record.data?.containmentTimeHours === "number") {
          totalContainment += record.data.containmentTimeHours;
          containmentCount += 1;
        }
      }
    });

    const summary: MetricsSummary = {
      totalExercises,
      reportsGenerated,
      trend: records.slice(-25),
    };

    if (detectionCount > 0) {
      summary.averageDetectionLatency = +(totalDetectionLatency / detectionCount).toFixed(2);
    }

    if (containmentCount > 0) {
      summary.averageContainmentTime = +(totalContainment / containmentCount).toFixed(2);
    }

    return summary;
  }

  private async readAll(): Promise<MetricRecord[]> {
    try {
      const raw = await fs.promises.readFile(this.metricsFile, "utf8");
      return raw
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line) as MetricRecord);
    } catch (error: any) {
      if (error.code === "ENOENT") {
        return [];
      }
      throw error;
    }
  }
}
