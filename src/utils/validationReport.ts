import crypto from "crypto";
import fs from "fs";

export interface ValidationResult {
  totalEntries: number;
  hash: string;
  sampleEntries: unknown[];
  generatedAt: string;
}

export async function generateValidationDigest(logFile: string): Promise<ValidationResult> {
  const content = await fs.promises.readFile(logFile, "utf8");
  const lines = content.split("\n").filter(Boolean);
  const hash = crypto.createHash("sha256").update(content, "utf8").digest("hex");
  const sampleEntries = lines.slice(-5).map((line) => {
    try {
      const parsed = JSON.parse(line);
      delete (parsed as Record<string, unknown>).arguments;
      return parsed;
    } catch {
      return { raw: line };
    }
  });
  return {
    totalEntries: lines.length,
    hash,
    sampleEntries,
    generatedAt: new Date().toISOString(),
  };
}
