#!/usr/bin/env node

import path from "path";

import { exportValidationBundle } from "../utils/validationReport.js";

interface CliOptions {
  logFile?: string;
  outputDir?: string;
  bundleFormat?: "json" | "json.gz";
  includeSamples: boolean;
}

const USAGE = `Create a tamper-evident audit seal and regulator bundle.

Usage: node build/cli/exportAuditSeal.js --log <path> [options]

Options:
  --log, -l <path>       Path to the audit log (defaults to logs/audit.log)
  --output, -o <dir>     Output directory for seals/bundles (default: <logDir>/seals)
  --format, -f <type>    Bundle format: json | json.gz (default: json)
  --no-samples           Omit sample entries from the bundle payload
  --help, -h             Show this help message
`;

function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = { includeSamples: true };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case "--log":
      case "-l": {
        const value = argv[++i];
        if (!value) {
          throw new Error("Missing value for --log");
        }
        options.logFile = value;
        break;
      }
      case "--output":
      case "-o": {
        const value = argv[++i];
        if (!value) {
          throw new Error("Missing value for --output");
        }
        options.outputDir = value;
        break;
      }
      case "--format":
      case "-f": {
        const value = argv[++i];
        if (!value) {
          throw new Error("Missing value for --format");
        }
        if (value !== "json" && value !== "json.gz") {
          throw new Error(`Unsupported bundle format: ${value}`);
        }
        options.bundleFormat = value;
        break;
      }
      case "--no-samples":
        options.includeSamples = false;
        break;
      case "--help":
      case "-h":
        console.log(USAGE);
        process.exit(0);
        break;
      default:
        if (arg.startsWith("-")) {
          throw new Error(`Unknown option: ${arg}`);
        }
        if (!options.logFile) {
          options.logFile = arg;
        } else if (!options.outputDir) {
          options.outputDir = arg;
        } else {
          throw new Error(`Unexpected positional argument: ${arg}`);
        }
    }
  }
  return options;
}

async function main(): Promise<void> {
  try {
    const argv = process.argv.slice(2);
    const options = parseArgs(argv);
    const logFile = options.logFile || path.resolve("logs/audit.log");

    const result = await exportValidationBundle(logFile, {
      outputDir: options.outputDir,
      bundleFormat: options.bundleFormat,
      includeSamples: options.includeSamples,
    });

    console.log(`[CyberSim] Audit seal created: ${result.sealPath}`);
    console.log(`[CyberSim] Regulator bundle created: ${result.bundlePath}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[CyberSim] Failed to create audit seal: ${message}`);
    process.exitCode = 1;
  }
}

void main();
