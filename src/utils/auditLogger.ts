import { createHash, createHmac } from "crypto";
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

export interface AuditEnvelope {
  schemaVersion: number;
  sequence: number;
  chainId: string;
  prevChainHash: string;
  eventHash: string;
  chainHash: string;
  signature?: string;
  signatureType?: string;
  signatureKeyId?: string;
  entry: AuditEntry;
}

const ZERO_HASH = "0".repeat(64);

export const AUDIT_CHAIN_ZERO_HASH = ZERO_HASH;

interface ChainReplayContext {
  sequence: number;
  lastChainHash: string;
  integrityAnomalies: string[];
  legacyDetected?: boolean;
}

export class AuditLogger {
  private static readonly ZERO_HASH = ZERO_HASH;

  private readonly logDir: string;
  private readonly logFile: string;
  private readonly chainId: string;
  private readonly signingKey?: Buffer;
  private readonly signingKeyId?: string;

  private ensureDirPromise: Promise<void> | null = null;
  private initPromise: Promise<void> | null = null;
  private sequence = 0;
  private lastChainHash = AuditLogger.ZERO_HASH;
  private integrityWarnings: string[] = [];

  constructor(
    logDirectory = process.env.CYBERSIM_AUDIT_LOG_DIR || path.join(process.cwd(), "logs"),
    logFileName = "audit.log"
  ) {
    this.logDir = logDirectory;
    this.logFile = path.join(this.logDir, logFileName);
    this.chainId = process.env.CYBERSIM_AUDIT_CHAIN_ID || "default";

    const signingKey = process.env.CYBERSIM_AUDIT_HMAC_KEY;
    const keyEncoding = (process.env.CYBERSIM_AUDIT_HMAC_KEY_ENCODING || "utf8") as BufferEncoding | "base64";
    if (signingKey) {
      this.signingKey = this.decodeKey(signingKey, keyEncoding);
      this.signingKeyId = process.env.CYBERSIM_AUDIT_HMAC_KEY_ID || "primary";
    }
  }

  async log(entry: AuditEntry): Promise<void> {
    await this.ensureInitialized();
    const sanitized = this.sanitizeEntry(entry);
    const eventHash = computeAuditEventHash(sanitized);
    const prevChainHash = this.lastChainHash;
    const chainHash = computeAuditChainHash(prevChainHash, eventHash);
    const sequence = this.sequence + 1;

    const envelope: AuditEnvelope = {
      schemaVersion: 2,
      sequence,
      chainId: this.chainId,
      prevChainHash,
      eventHash,
      chainHash,
      entry: sanitized,
    };

    if (this.signingKey) {
      envelope.signatureType = "hmac-sha256";
      envelope.signatureKeyId = this.signingKeyId;
      envelope.signature = createHmac("sha256", this.signingKey).update(chainHash, "utf8").digest("hex");
    }

    const line = JSON.stringify(envelope);
    await fs.appendFile(this.logFile, line + "\n", { encoding: "utf8" });

    this.sequence = sequence;
    this.lastChainHash = chainHash;
  }

  getLogFilePath(): string {
    return this.logFile;
  }

  getLastChainHash(): string {
    return this.lastChainHash;
  }

  getIntegrityWarnings(): string[] {
    return [...this.integrityWarnings];
  }

  private async ensureInitialized(): Promise<void> {
    if (!this.initPromise) {
      this.initPromise = this.initializeChainState();
    }
    await this.initPromise;
  }

  private async initializeChainState(): Promise<void> {
    await this.ensureDirectory();
    const context: ChainReplayContext = {
      sequence: 0,
      lastChainHash: AuditLogger.ZERO_HASH,
      integrityAnomalies: [],
      legacyDetected: false,
    };

    const exists = await this.fileExists(this.logFile);
    if (!exists) {
      this.sequence = 0;
      this.lastChainHash = AuditLogger.ZERO_HASH;
      this.integrityWarnings = [];
      return;
    }

    const content = await fs.readFile(this.logFile, "utf8");
    const lines = content.split(/\r?\n/).filter((line) => line.trim().length > 0);
    for (const line of lines) {
      context.sequence += 1;
      this.replayLine(line, context);
    }

    this.sequence = context.sequence;
    this.lastChainHash = context.lastChainHash;
    this.integrityWarnings = context.integrityAnomalies;

    if (this.integrityWarnings.length > 0) {
      console.warn("[CyberSim] Audit log integrity warnings detected:", this.integrityWarnings);
    }
  }

  private replayLine(line: string, context: ChainReplayContext): void {
    try {
      const parsed = JSON.parse(line) as AuditEnvelope | AuditEntry;
      if (this.isEnvelope(parsed)) {
        const entry = parsed.entry;
        const eventHash = computeAuditEventHash(entry);
        if (parsed.sequence !== context.sequence) {
          context.integrityAnomalies.push(
            `Sequence mismatch (expected ${context.sequence}, found ${parsed.sequence})`
          );
        }
        if (parsed.eventHash !== eventHash) {
          context.integrityAnomalies.push(`Event hash mismatch at sequence ${context.sequence}`);
        }
        if (parsed.prevChainHash !== context.lastChainHash) {
          context.integrityAnomalies.push(`Prev chain hash mismatch at sequence ${context.sequence}`);
        }
        const computedChainHash = computeAuditChainHash(context.lastChainHash, eventHash);
        if (parsed.chainHash !== computedChainHash) {
          context.integrityAnomalies.push(`Chain hash mismatch at sequence ${context.sequence}`);
        }
        context.lastChainHash = computedChainHash;
      } else {
        const entry = parsed;
        const eventHash = computeAuditEventHash(entry);
        context.lastChainHash = computeAuditChainHash(context.lastChainHash, eventHash);
        if (!context.legacyDetected) {
          context.integrityAnomalies.push(
            `Legacy audit entries detected starting at sequence ${context.sequence}; consider regenerating hashes`
          );
          context.legacyDetected = true;
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      context.integrityAnomalies.push(`Failed to replay audit line ${context.sequence}: ${message}`);
    }
  }

  private async ensureDirectory(): Promise<void> {
    if (!this.ensureDirPromise) {
      this.ensureDirPromise = fs
        .mkdir(this.logDir, { recursive: true })
        .then(() => undefined);
    }
    await this.ensureDirPromise;
  }

  private async fileExists(target: string): Promise<boolean> {
    try {
      await fs.access(target);
      return true;
    } catch {
      return false;
    }
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

  private isEnvelope(value: AuditEnvelope | AuditEntry): value is AuditEnvelope {
    return (
      typeof value === "object" &&
      value !== null &&
      "entry" in value &&
      "chainHash" in value &&
      "eventHash" in value &&
      "sequence" in value
    );
  }

  private decodeKey(key: string, encoding: BufferEncoding | "base64"): Buffer {
    if (encoding === "base64") {
      return Buffer.from(key, "base64");
    }
    return Buffer.from(key, encoding);
  }
}

export function computeAuditEventHash(entry: AuditEntry): string {
  return createHash("sha256").update(JSON.stringify(entry), "utf8").digest("hex");
}

export function computeAuditChainHash(prevChainHash: string, eventHash: string): string {
  return createHash("sha256").update(prevChainHash, "utf8").update(eventHash, "utf8").digest("hex");
}
