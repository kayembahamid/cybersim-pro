#!/usr/bin/env node

import fs from "fs";
import path from "path";

import { controlCatalog } from "../data/controlCatalog.js";

interface SummaryCounts {
  domain: string;
  total: number;
  operational: number;
  inProgress: number;
  planned: number;
}

function summariseControls(): SummaryCounts[] {
  const byDomain = new Map<string, SummaryCounts>();
  for (const control of controlCatalog) {
    const existing = byDomain.get(control.domain) || {
      domain: control.domain,
      total: 0,
      operational: 0,
      inProgress: 0,
      planned: 0,
    };
    existing.total += 1;
    if (control.status === "operational") {
      existing.operational += 1;
    } else if (control.status === "in-progress") {
      existing.inProgress += 1;
    } else {
      existing.planned += 1;
    }
    byDomain.set(control.domain, existing);
  }
  return Array.from(byDomain.values()).sort((a, b) => a.domain.localeCompare(b.domain));
}

function printControlSummary(): void {
  console.log("=== CyberSim Pro Control Landscape ===\n");
  const totals = summariseControls();
  for (const summary of totals) {
    console.log(
      `${summary.domain}: ${summary.operational} operational / ${summary.inProgress} in-progress / ${summary.planned} planned (total ${summary.total})`
    );
  }

  const operational = controlCatalog.filter((c) => c.status === "operational").length;
  console.log("\nOverall maturity: ");
  console.log(`- Operational controls: ${operational}`);
  console.log(
    `- In-progress controls: ${controlCatalog.filter((c) => c.status === "in-progress").length}`
  );
  console.log(`- Planned controls: ${controlCatalog.filter((c) => c.status === "planned").length}`);
}

function extractRoadmapUpdatedAt(filePath: string): string | null {
  try {
    const content = fs.readFileSync(filePath, "utf8");
    const match = content.match(/_Last updated:\s*(.+?)_/i);
    return match ? match[1] : null;
  } catch {
    return null;
  }
}

function printRoadmapLocation(): void {
  const roadmapPath = path.resolve("docs/COMPLIANCE_ROADMAP.md");
  console.log("\nRoadmap document:");
  console.log(`- ${roadmapPath}`);

  const updated = extractRoadmapUpdatedAt(roadmapPath);
  if (updated) {
    console.log(`- Last updated: ${updated}`);
  }

  const mappingPath = path.resolve("docs/control-mapping.json");
  if (fs.existsSync(mappingPath)) {
    console.log(`- Framework mapping: ${mappingPath}`);
  }
}

function printUpcomingMilestones(): void {
  const milestones = controlCatalog
    .filter((c) => c.status !== "operational")
    .flatMap((control) =>
      control.frameworks.map((framework) => ({
        controlId: control.id,
        domain: control.domain,
        program: framework.program,
        reference: framework.reference,
        status: control.status,
      }))
    )
    .slice(0, 10);

  if (milestones.length === 0) {
    console.log("\nAll controls are operational. Great job!\n");
    return;
  }

  console.log("\nUpcoming compliance focus (first 10 mappings):");
  for (const milestone of milestones) {
    console.log(
      `- [${milestone.status}] ${milestone.controlId} (${milestone.domain}) → ${milestone.program} ${milestone.reference}`
    );
  }
}

function main(): void {
  printControlSummary();
  printUpcomingMilestones();
  printRoadmapLocation();
  console.log("\nTip: share the roadmap doc with Legal and Risk, and include this summary in monthly compliance updates.\n");
}

main();
