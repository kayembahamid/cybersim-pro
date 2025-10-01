import { createHash, createHmac, timingSafeEqual } from "crypto";
import fs from "fs";
import path from "path";
import { promisify } from "util";
import { gzip as gzipCallback } from "zlib";

import {
  AUDIT_CHAIN_ZERO_HASH,
  AuditEntry,
  AuditEnvelope,
  AuditStatus,
  computeAuditChainHash,
  computeAuditEventHash,
} from "./auditLogger.js";

const gzip = promisify(gzipCallback);

export interface ValidationSample {
  sequence: number;
  timestamp: string;
  tool: string;
  status: AuditStatus;
  chainHash: string;
  signature?: string;
  signatureType?: string;
  signatureVerified?: boolean;
}

export interface ValidationResult {
  totalEntries: number;
  hash: string;
  sampleEntries: ValidationSample[];
  generatedAt: string;
  chainVerified: boolean;
  lastChainHash: string;
  anomalies: string[];
  legacyEntries: number;
  sequenceRange?: { start: number; end: number };
  chainId?: string;
  lastSignature?: {
    sequence: number;
    signature: string;
    signatureType?: string;
    signatureKeyId?: string;
    verified?: boolean;
  };
}

export interface ValidationExportOptions {
  outputDir?: string;
  bundleFormat?: "json" | "json.gz";
  includeSamples?: boolean;
}

export interface ValidationExportResult {
  digest: ValidationResult;
  sealPath: string;
  bundlePath: string;
}

export async function generateValidationDigest(logFile: string): Promise<ValidationResult> {
  let content: string;
  try {
    content = await fs.promises.readFile(logFile, "utf8");
  } catch (error) {
    const err = error as NodeJS.ErrnoException;
    if (err.code === "ENOENT") {
      return buildEmptyResult();
    }
    throw error;
  }

  const lines = content.split(/\r?\n/).filter((line) => line.trim().length > 0);
  const hash = createHash("sha256").update(content, "utf8").digest("hex");

  if (lines.length === 0) {
    return {
      ...buildEmptyResult(),
      hash,
    };
  }

  const anomalies: string[] = [];
  const samples: ValidationSample[] = [];
  let chainVerified = true;
  let legacyEntries = 0;
  let previousChainHash = AUDIT_CHAIN_ZERO_HASH;
  let totalEntries = 0;
  let sequenceStart: number | undefined;
  let sequenceEnd: number | undefined;
  let chainId: string | undefined;
  let lastSignature: ValidationResult["lastSignature"];

  const hmacKeyRaw =
    process.env.CYBERSIM_AUDIT_VALIDATION_HMAC_KEY || process.env.CYBERSIM_AUDIT_HMAC_KEY;
  const hmacKeyEncoding = (process.env.CYBERSIM_AUDIT_VALIDATION_HMAC_KEY_ENCODING ||
    process.env.CYBERSIM_AUDIT_HMAC_KEY_ENCODING ||
    "utf8") as BufferEncoding | "base64";
  const hmacVerificationKey = hmacKeyRaw ? decodeKey(hmacKeyRaw, hmacKeyEncoding) : undefined;

  for (const line of lines) {
    totalEntries += 1;
    let envelope: AuditEnvelope | undefined;
    let entry: AuditEntry;

    try {
      const parsed = JSON.parse(line) as AuditEnvelope | AuditEntry;
      if (isEnvelope(parsed)) {
        envelope = parsed;
        entry = parsed.entry;
      } else {
        entry = parsed;
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      anomalies.push(`Unable to parse audit line ${totalEntries}: ${message}`);
      chainVerified = false;
      continue;
    }

    const eventHash = computeAuditEventHash(entry);
    const derivedChainHash = computeAuditChainHash(previousChainHash, eventHash);

    if (envelope) {
      const { sequence } = envelope;
      sequenceStart ??= sequence;
      sequenceEnd = sequence;

      if (!chainId) {
        chainId = envelope.chainId;
      } else if (chainId !== envelope.chainId) {
        anomalies.push(
          `Mixed chain IDs detected at sequence ${sequence} (${chainId} vs ${envelope.chainId})`
        );
        chainVerified = false;
      }

      if (envelope.sequence !== totalEntries) {
        anomalies.push(
          `Sequence gap detected: envelope ${envelope.sequence}, replay index ${totalEntries}`
        );
      }

      if (envelope.eventHash !== eventHash) {
        anomalies.push(`Event hash mismatch at sequence ${sequence}`);
        chainVerified = false;
      }

      if (envelope.prevChainHash !== previousChainHash) {
        anomalies.push(`Prev chain hash mismatch at sequence ${sequence}`);
        chainVerified = false;
      }

      if (envelope.chainHash !== derivedChainHash) {
        anomalies.push(`Chain hash mismatch at sequence ${sequence}`);
        chainVerified = false;
      }

      let signatureVerified: boolean | undefined;
      if (envelope.signature) {
        if (envelope.signatureType === "hmac-sha256" && hmacVerificationKey) {
          const expected = createHmac("sha256", hmacVerificationKey)
            .update(envelope.chainHash, "utf8")
            .digest("hex");
          signatureVerified = secureCompareHex(expected, envelope.signature);
          if (signatureVerified === false) {
            anomalies.push(`Signature mismatch at sequence ${sequence}`);
            chainVerified = false;
          }
        }

        lastSignature = {
          sequence,
          signature: envelope.signature,
          signatureType: envelope.signatureType,
          signatureKeyId: envelope.signatureKeyId,
          verified: signatureVerified,
        };
      }

      previousChainHash = derivedChainHash;

      const sample: ValidationSample = {
        sequence,
        timestamp: entry.timestamp,
        tool: entry.tool,
        status: entry.status,
        chainHash: envelope.chainHash,
      };

      if (envelope.signature) {
        sample.signature = envelope.signature;
        sample.signatureType = envelope.signatureType;
        if (lastSignature?.sequence === sequence) {
          sample.signatureVerified = lastSignature.verified;
        } else {
          sample.signatureVerified = signatureVerified;
        }
      }

      pushSample(samples, sample);
    } else {
      legacyEntries += 1;
      anomalies.push(`Legacy audit entry encountered at line ${totalEntries}`);
      chainVerified = false;
      previousChainHash = derivedChainHash;

      pushSample(samples, {
        sequence: totalEntries,
        timestamp: entry.timestamp,
        tool: entry.tool,
        status: entry.status,
        chainHash: derivedChainHash,
      });
    }
  }

  return {
    totalEntries,
    hash,
    sampleEntries: samples,
    generatedAt: new Date().toISOString(),
    chainVerified: chainVerified && legacyEntries === 0,
    lastChainHash: previousChainHash,
    anomalies,
    legacyEntries,
    sequenceRange:
      sequenceStart !== undefined && sequenceEnd !== undefined
        ? { start: sequenceStart, end: sequenceEnd }
        : undefined,
    chainId,
    lastSignature,
  };
}

export async function exportValidationBundle(
  logFile: string,
  options: ValidationExportOptions = {}
): Promise<ValidationExportResult> {
  const digest = await generateValidationDigest(logFile);
  const outputDir = options.outputDir || path.join(path.dirname(logFile), "seals");
  await fs.promises.mkdir(outputDir, { recursive: true });

  const exportedAt = new Date();
  const exportedAtIso = exportedAt.toISOString();
  const timestampSegment = makeFileSafeTimestamp(exportedAtIso);

  const sealEnvelope = createSealEnvelope(logFile, digest, exportedAtIso);
  const sealPath = path.join(outputDir, `audit-seal-${timestampSegment}.json`);
  await fs.promises.writeFile(sealPath, JSON.stringify(sealEnvelope, null, 2), "utf8");

  const bundlePayload = buildBundlePayload(logFile, digest, exportedAtIso, options.includeSamples);
  const bundleFormat = options.bundleFormat || "json";
  let bundlePath: string;

  if (bundleFormat === "json.gz") {
    const buffer = Buffer.from(JSON.stringify(bundlePayload, null, 2), "utf8");
    const compressed = await gzip(buffer);
    bundlePath = path.join(outputDir, `audit-bundle-${timestampSegment}.json.gz`);
    await fs.promises.writeFile(bundlePath, compressed);
  } else if (bundleFormat === "json") {
    bundlePath = path.join(outputDir, `audit-bundle-${timestampSegment}.json`);
    await fs.promises.writeFile(bundlePath, JSON.stringify(bundlePayload, null, 2), "utf8");
  } else {
    throw new Error(`Unsupported bundle format: ${bundleFormat}`);
  }

  return { digest, sealPath, bundlePath };
}

function buildEmptyResult(): ValidationResult {
  const emptyHash = createHash("sha256").update("", "utf8").digest("hex");
  return {
    totalEntries: 0,
    hash: emptyHash,
    sampleEntries: [],
    generatedAt: new Date().toISOString(),
    chainVerified: true,
    lastChainHash: AUDIT_CHAIN_ZERO_HASH,
    anomalies: [],
    legacyEntries: 0,
  };
}

function pushSample(collection: ValidationSample[], sample: ValidationSample): void {
  collection.push(sample);
  if (collection.length > 5) {
    collection.shift();
  }
}

function decodeKey(key: string, encoding: BufferEncoding | "base64"): Buffer {
  return encoding === "base64" ? Buffer.from(key, "base64") : Buffer.from(key, encoding);
}

function isEnvelope(value: AuditEnvelope | AuditEntry): value is AuditEnvelope {
  return (
    typeof value === "object" &&
    value !== null &&
    "entry" in value &&
    "chainHash" in value &&
    "eventHash" in value &&
    "sequence" in value
  );
}

function secureCompareHex(expected: string, actual: string): boolean {
  if (expected.length !== actual.length || expected.length % 2 !== 0) {
    return expected === actual;
  }

  try {
    const expectedBuffer = Buffer.from(expected, "hex");
    const actualBuffer = Buffer.from(actual, "hex");
    if (expectedBuffer.length !== actualBuffer.length) {
      return false;
    }
    return timingSafeEqual(expectedBuffer, actualBuffer);
  } catch {
    return expected === actual;
  }
}

interface SealEnvelope {
  version: number;
  generatedAt: string;
  logFile: string;
  chainId?: string;
  digest: {
    totalEntries: number;
    hash: string;
    lastChainHash: string;
    chainVerified: boolean;
    sequenceRange?: { start: number; end: number };
    lastSignature?: ValidationResult["lastSignature"];
  };
  signature?: {
    type: string;
    value: string;
    keyId?: string;
  };
}

function createSealEnvelope(
  logFile: string,
  digest: ValidationResult,
  generatedAtIso: string
): SealEnvelope {
  const envelope: SealEnvelope = {
    version: 1,
    generatedAt: generatedAtIso,
    logFile: path.resolve(logFile),
    chainId: digest.chainId,
    digest: {
      totalEntries: digest.totalEntries,
      hash: digest.hash,
      lastChainHash: digest.lastChainHash,
      chainVerified: digest.chainVerified,
      sequenceRange: digest.sequenceRange,
      lastSignature: digest.lastSignature,
    },
  };

  const sealKeyRaw = process.env.CYBERSIM_AUDIT_SEAL_KEY || process.env.CYBERSIM_AUDIT_HMAC_KEY;
  const sealKeyEncoding = (process.env.CYBERSIM_AUDIT_SEAL_KEY_ENCODING ||
    process.env.CYBERSIM_AUDIT_HMAC_KEY_ENCODING ||
    "utf8") as BufferEncoding | "base64";

  if (sealKeyRaw) {
    const key = decodeKey(sealKeyRaw, sealKeyEncoding);
    const signatureValue = createHmac("sha256", key)
      .update(JSON.stringify(envelope.digest), "utf8")
      .update(envelope.generatedAt, "utf8")
      .digest("hex");
    envelope.signature = {
      type: "hmac-sha256",
      value: signatureValue,
      keyId: process.env.CYBERSIM_AUDIT_SEAL_KEY_ID || process.env.CYBERSIM_AUDIT_HMAC_KEY_ID || "primary",
    };
  }

  return envelope;
}

function buildBundlePayload(
  logFile: string,
  digest: ValidationResult,
  exportedAtIso: string,
  includeSamples = true
): Record<string, unknown> {
  const sampleEntries = includeSamples
    ? digest.sampleEntries.map((sample) => ({ ...sample }))
    : [];

  return {
    version: 1,
    exportedAt: exportedAtIso,
    logFile: path.resolve(logFile),
    chainId: digest.chainId,
    digest: {
      ...digest,
      sampleEntries,
      anomalies: [...digest.anomalies],
      lastSignature: digest.lastSignature ? { ...digest.lastSignature } : undefined,
    },
  };
}

function makeFileSafeTimestamp(isoTimestamp: string): string {
  return isoTimestamp.replace(/[:.]/g, "-");
}
