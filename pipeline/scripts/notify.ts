/**
 * notify.ts — posts AppSec Sentinel scan summaries to a Slack webhook.
 * Demonstrates the automation/notification layer of the pipeline in TypeScript.
 *
 * Usage:
 *   npx ts-node scripts/notify.ts scan-results.json
 *
 * In CI, this is wired into the GitHub Actions workflow after the scan step
 * to alert the on-call AppSec engineer when critical/high findings appear.
 */

import * as fs from "fs";

interface Finding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  scan_type: string;
  location: string;
  line_number?: number;
}

const SEVERITY_EMOJI: Record<string, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🟢",
};

function loadFindings(path: string): Finding[] {
  const raw = fs.readFileSync(path, "utf-8");
  return JSON.parse(raw) as Finding[];
}

function summarize(findings: Finding[]): string {
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  }

  const lines = [
    `*AppSec Sentinel — Scan Summary*`,
    `Total findings: ${findings.length}`,
    ...Object.entries(counts).map(
      ([sev, count]) => `${SEVERITY_EMOJI[sev] ?? "⚪"} ${sev.toUpperCase()}: ${count}`
    ),
  ];

  const criticalFindings = findings.filter((f) => f.severity === "critical");
  if (criticalFindings.length > 0) {
    lines.push("", "*Critical findings requiring immediate triage:*");
    for (const f of criticalFindings.slice(0, 5)) {
      lines.push(`• ${f.title} — \`${f.location}\``);
    }
  }

  return lines.join("\n");
}

async function postToSlack(webhookUrl: string, text: string): Promise<void> {
  const res = await fetch(webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
  });
  if (!res.ok) {
    throw new Error(`Slack webhook failed: ${res.status} ${res.statusText}`);
  }
}

async function main() {
  const filePath = process.argv[2] ?? "scan-results.json";
  const webhookUrl = process.env.SLACK_WEBHOOK_URL;

  if (!fs.existsSync(filePath)) {
    console.error(`Scan results file not found: ${filePath}`);
    process.exit(1);
  }

  const findings = loadFindings(filePath);
  const summary = summarize(findings);

  console.log(summary);

  if (webhookUrl) {
    await postToSlack(webhookUrl, summary);
    console.log("\n✓ Posted summary to Slack");
  } else {
    console.log("\n(SLACK_WEBHOOK_URL not set — printed summary only)");
  }
}

main().catch((err) => {
  console.error("notify.ts failed:", err);
  process.exit(1);
});
