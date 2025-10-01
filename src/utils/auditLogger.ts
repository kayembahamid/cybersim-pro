import { promises as fs } from "fs";
import path from "path";

export type AuditStatus = "success" | "error";

export interface AuditEntry {
  timestamp: string;
  tool: string;
  status: AuditStatus;
  durationMs: number;
  arguments?: unknown;
  metadata?: Record<string, unknown>;
  errorMessage?: string;
}

export class AuditLogger {
  private readonly logDir: string;
  private readonly logFile: string;
  private ensureDirPromise: Promise<void> | null = null;

  constructor(
    logDirectory = process.env.CYBERSIM_AUDIT_LOG_DIR || path.join(process.cwd(), "logs"),
    logFileName = "audit.log"
  ) {
    this.logDir = logDirectory;
    this.logFile = path.join(this.logDir, logFileName);
  }

  async log(entry: AuditEntry): Promise<void> {
    await this.ensureDirectory();
    const sanitized = this.sanitizeEntry(entry);
    const line = JSON.stringify(sanitized);
    await fs.appendFile(this.logFile, line + "\n", { encoding: "utf8" });
  }

  getLogFilePath(): string {
    return this.logFile;
  }

  private async ensureDirectory(): Promise<void> {
    if (!this.ensureDirPromise) {
      this.ensureDirPromise = fs
        .mkdir(this.logDir, { recursive: true })
        .then(() => undefined);
    }
    await this.ensureDirPromise;
  }

  private sanitizeEntry(entry: AuditEntry): AuditEntry {
    const clone: AuditEntry = {
      timestamp: entry.timestamp,
      tool: entry.tool,
      status: entry.status,
      durationMs: entry.durationMs,
    };

    if (entry.arguments !== undefined) {
      clone.arguments = this.truncateValue(entry.arguments);
    }

    if (entry.metadata) {
      clone.metadata = this.truncateValue(entry.metadata) as Record<string, unknown>;
    }

    if (entry.errorMessage) {
      clone.errorMessage = entry.errorMessage.slice(0, 500);
    }

    return clone;
  }

  private truncateValue(value: unknown, depth = 0): unknown {
    if (depth > 3) {
      return "[Truncated]";
    }

    if (value === null || value === undefined) {
      return value;
    }

    if (typeof value === "string") {
      return value.length > 500 ? `${value.slice(0, 500)}…[truncated]` : value;
    }

    if (typeof value === "number" || typeof value === "boolean") {
      return value;
    }

    if (Array.isArray(value)) {
      return value.slice(0, 20).map((item) => this.truncateValue(item, depth + 1));
    }

    if (typeof value === "object") {
      const result: Record<string, unknown> = {};
      const entries = Object.entries(value as Record<string, unknown>).slice(0, 50);
      for (const [key, val] of entries) {
        result[key] = this.truncateValue(val, depth + 1);
      }
      return result;
    }

    return String(value);
  }
}
