import fs from "fs";
import path from "path";

import type { ExecutionProvenance } from "./executionContext.js";

export interface ControlRecommendation {
  id: string;
  title: string;
  category: string;
  description: string;
  source: string;
  priority: "low" | "medium" | "high" | "critical";
  payload: Record<string, unknown>;
  executedBy?: string;
  provenance?: ExecutionProvenance;
}

export class ControlFeed {
  private controlDir: string;
  private controlFile: string;

  constructor(controlDirectory = path.join(process.cwd(), "controls"), controlFileName = "control-feed.jsonl") {
    this.controlDir = controlDirectory;
    this.controlFile = path.join(controlDirectory, controlFileName);
  }

  async capture(recommendations: ControlRecommendation[]): Promise<void> {
    if (!recommendations.length) {
      return;
    }
    await fs.promises.mkdir(this.controlDir, { recursive: true });
    const capturedAt = new Date().toISOString();
    const lines = recommendations.map((rec) => JSON.stringify({ ...rec, capturedAt }));
    await fs.promises.appendFile(this.controlFile, lines.join("\n") + "\n", { encoding: "utf8" });
  }

  async export(): Promise<ControlRecommendation[]> {
    try {
      const raw = await fs.promises.readFile(this.controlFile, "utf8");
      return raw
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line) as ControlRecommendation);
    } catch (error: any) {
      if (error.code === "ENOENT") {
        return [];
      }
      throw error;
    }
  }
}
