#!/usr/bin/env node

import fs from "fs";
import path from "path";

import type { ExecutionProvenance } from "../utils/executionContext.js";

interface BackfillOptions {
  metricsPath: string | null;
  controlsPath: string | null;
  dryRun: boolean;
}

interface BackfillResult {
  label: string;
  filePath: string;
  processed: number;
  updated: number;
  skipped: number;
  exists: boolean;
}

const DEFAULT_METRICS_PATH = path.resolve("metrics/metrics.jsonl");
const DEFAULT_CONTROLS_PATH = path.resolve("controls/control-feed.jsonl");

function parseArgs(argv: string[]): BackfillOptions {
  const options: BackfillOptions = {
    metricsPath: DEFAULT_METRICS_PATH,
    controlsPath: DEFAULT_CONTROLS_PATH,
    dryRun: false,
  };

  for (let index = 2; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg) continue;
    switch (arg) {
      case "--metrics": {
        const next = argv[index + 1];
        if (!next) {
          throw new Error("--metrics requires a path argument");
        }
        options.metricsPath = path.resolve(next);
        index += 1;
        break;
      }
      case "--controls": {
        const next = argv[index + 1];
        if (!next) {
          throw new Error("--controls requires a path argument");
        }
        options.controlsPath = path.resolve(next);
        index += 1;
        break;
      }
      case "--skip-metrics":
        options.metricsPath = null;
        break;
      case "--skip-controls":
        options.controlsPath = null;
        break;
      case "--dry-run":
        options.dryRun = true;
        break;
      case "--help":
      case "-h":
        printUsage();
        process.exit(0);
      default:
        throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return options;
}

function printUsage(): void {
  console.log(`CyberSim Pro – Backfill provenance metadata\n\n` +
    `Usage: node build/cli/backfillProvenance.js [options]\n\n` +
    `Options:\n` +
    `  --metrics <path>       Override metrics JSONL path (default metrics/metrics.jsonl)\n` +
    `  --controls <path>      Override control-feed JSONL path (default controls/control-feed.jsonl)\n` +
    `  --skip-metrics         Skip metrics backfill\n` +
    `  --skip-controls        Skip control feed backfill\n` +
    `  --dry-run              Report changes without rewriting files\n` +
    `  -h, --help             Show this help message\n`);
}

function createFallbackProvenance(recordedAt: string | undefined, executedBy: unknown): ExecutionProvenance {
  const timestamp = typeof recordedAt === "string" && recordedAt.trim() ? recordedAt.trim() : new Date().toISOString();
  const actorId = typeof executedBy === "string" && executedBy.trim() ? executedBy.trim() : undefined;

  const provenance: ExecutionProvenance = {
    recordedAt: timestamp,
    source: actorId ? "operator" : "anonymous",
  };

  if (actorId) {
    provenance.actorId = actorId;
    provenance.operator = { id: actorId };
  }

  return provenance;
}

function backfillJsonl(
  label: string,
  filePath: string,
  updater: (record: Record<string, any>) => boolean,
  dryRun: boolean
): BackfillResult {
  if (!fs.existsSync(filePath)) {
    return {
      label,
      filePath,
      processed: 0,
      updated: 0,
      skipped: 0,
      exists: false,
    };
  }

  const text = fs.readFileSync(filePath, "utf8");
  const lines = text.split("\n");
  const nextLines: string[] = [];
  let processed = 0;
  let updated = 0;
  let skipped = 0;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }
    processed += 1;
    try {
      const record = JSON.parse(line) as Record<string, any>;
      const changed = updater(record);
      if (changed) {
        updated += 1;
      } else {
        skipped += 1;
      }
      nextLines.push(JSON.stringify(record));
    } catch (error) {
      skipped += 1;
      nextLines.push(line);
      console.warn(`[${label}] Failed to parse line ${processed}:`, error);
    }
  }

  if (!dryRun && updated > 0) {
    fs.writeFileSync(filePath, nextLines.join("\n") + "\n", "utf8");
  }

  return {
    label,
    filePath,
    processed,
    updated,
    skipped,
    exists: true,
  };
}

function backfillMetrics(filePath: string, dryRun: boolean): BackfillResult {
  return backfillJsonl(
    "metrics",
    filePath,
    (record) => {
      if (record.provenance) {
        return false;
      }
      const executedBy = record?.data?.executedBy;
      record.provenance = createFallbackProvenance(record.timestamp, executedBy);
      return true;
    },
    dryRun
  );
}

function backfillControls(filePath: string, dryRun: boolean): BackfillResult {
  return backfillJsonl(
    "controls",
    filePath,
    (record) => {
      if (record.provenance) {
        return false;
      }
      record.provenance = createFallbackProvenance(record.capturedAt, record.executedBy);
      return true;
    },
    dryRun
  );
}

function reportResult(result: BackfillResult, dryRun: boolean): void {
  if (!result.exists) {
    console.log(`[${result.label}] No file found at ${result.filePath}, skipping.`);
    return;
  }

  const mode = dryRun ? "(dry-run) " : "";
  console.log(
    `[${result.label}] ${mode}${result.updated} updated / ${result.skipped} already compliant (processed ${result.processed}) at ${result.filePath}`
  );
}

function main(): void {
  const options = parseArgs(process.argv);

  try {
    if (options.metricsPath) {
      const metricsResult = backfillMetrics(options.metricsPath, options.dryRun);
      reportResult(metricsResult, options.dryRun);
    } else {
      console.log("[metrics] Skipped by flag.");
    }

    if (options.controlsPath) {
      const controlsResult = backfillControls(options.controlsPath, options.dryRun);
      reportResult(controlsResult, options.dryRun);
    } else {
      console.log("[controls] Skipped by flag.");
    }

    if (options.dryRun) {
      console.log("\nDry-run complete. Re-run without --dry-run to apply changes.");
    }
  } catch (error) {
    console.error("Migration failed:", error instanceof Error ? error.message : error);
    process.exit(1);
  }
}

main();

