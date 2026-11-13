"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { atomicWrite, outputDirectory } = require("./common");

function summaryText(report) {
  const lines = [
    `${report.platform.toUpperCase()} PUBLIC OSINT REPORT`, "=".repeat(68),
    `Collected: ${report.collected_at}`, `Type: ${report.query.type}`, `Target: ${report.query.target}`,
    `Keywords: ${report.query.keywords.join(", ") || "N/A"}`, `Repositories: ${report.repositories.length}`,
    `Users: ${report.users.length}`, `Emails: ${report.emails.length}`, `Indicators: ${report.indicators.length}`,
    `Partial: ${report.partial}`, "", "Repository relevance is evidence, not proof of ownership or malicious intent.", "",
    "REPOSITORIES", "=".repeat(68)
  ];
  for (const repo of report.repositories) lines.push(
    `Repository: ${repo.full_name || repo.name || "N/A"}`, `URL: ${repo.url || "N/A"}`,
    `Relevance: ${repo.relevance ? `${repo.relevance.score}/100 (${repo.relevance.level}, ${repo.relevance.scope})` : "N/A"}`,
    `Description: ${repo.description || "N/A"}`, `Visibility: ${repo.visibility || "N/A"}`,
    `Updated: ${repo.updated_at || "N/A"}`, `Evidence: ${(repo.evidence || []).join("; ") || "N/A"}`, ""
  );
  lines.push("USERS", "=".repeat(68));
  for (const user of report.users) lines.push(`${user.username || "N/A"} | ${user.url || "N/A"} | ${user.evidence || "N/A"}`);
  lines.push("", "INDICATORS", "=".repeat(68));
  for (const item of report.indicators) lines.push(`${item.severity} | ${item.type} | ${item.repository || "N/A"} | ${item.source_url}`, `  ${item.reason}`);
  lines.push("", "ERRORS", "=".repeat(68), ...report.errors);
  return `${lines.join("\n")}\n`;
}

function emailText(report) {
  const lines = ["UNIQUE PUBLIC EMAILS", "=".repeat(68), "Commit identities are user-configured and do not prove account ownership.", ""];
  for (const item of report.emails) lines.push(item.email, `  Repositories: ${(item.repositories || []).join(", ") || "N/A"}`, `  Evidence: ${(item.evidence || []).length}`, "");
  return `${lines.join("\n")}\n`;
}

function buildPrimaryResults(report, { includeAll = false, includeBots = false } = {}) {
  const repositories = new Map();
  for (const repository of report.repositories || []) {
    if (!repository.full_name || !repository.relevance) continue;
    const exact = repository.relevance.scope === "exact_domain";
    if (!includeAll && !exact) continue;
    repositories.set(repository.full_name, repository);
  }

  const pairs = new Map();
  for (const entry of report.emails || []) {
    const email = String(entry.email || "").trim().toLowerCase();
    if (!email || (!includeBots && email.includes("noreply"))) continue;
    for (const evidence of entry.evidence || []) {
      if (evidence.evidence_type !== "public_commit_metadata") continue;
      const repository = repositories.get(evidence.repository);
      if (!repository) continue;
      const key = `${repository.full_name}\0${email}`;
      if (!pairs.has(key)) {
        pairs.set(key, {
          repository: repository.full_name,
          repository_url: repository.url,
          relevance_score: Number.isInteger(repository.relevance.score) ? repository.relevance.score : 0,
          relevance_level: repository.relevance.level === "strong" ? "strong" : "weak",
          scope: repository.relevance.scope === "exact_domain" ? "exact_domain" : "keyword_only",
          email,
          amount: 0
        });
      }
      pairs.get(key).amount += 1;
    }
  }

  const results = [...pairs.values()].sort((a, b) =>
    b.relevance_score - a.relevance_score ||
    b.amount - a.amount ||
    a.repository.localeCompare(b.repository) ||
    a.email.localeCompare(b.email)
  );

  return {
    search_domain: report.query.target,
    search_keyword: report.query.keywords[0] || "",
    generated_at: report.collected_at,
    totals: {
      repositories: new Set(results.map(row => row.repository)).size,
      emails: new Set(results.map(row => row.email)).size,
      pairs: results.length
    },
    results
  };
}

function writeReport(report, root, now = new Date(), options = {}) {
  const directory = outputDirectory(root, report.platform, report.query.type, report.query.target, now);
  const json = `${JSON.stringify(report, null, 2)}\n`;
  const type = report.query.type;
  const files = new Map();
  if (report.platform === "github") {
    if (type === "domain") {
      files.set("domain-intel.json", json);
      files.set("repositories-intel.json", `${JSON.stringify(report.repositories, null, 2)}\n`);
      files.set("search.txt", summaryText(report));
      files.set("results.json", `${JSON.stringify(buildPrimaryResults(report, options), null, 2)}\n`);
    } else if (type === "user") {
      files.set("user-intel.json", json);
      files.set("user-intel.txt", summaryText(report));
      files.set("unique-emails.txt", emailText(report));
    } else files.set("repository-intel.json", json);
  } else {
    if (type === "domain") {
      files.set("gitlab-intel.json", json);
      files.set("gitlab-search.txt", summaryText(report));
      files.set("gitlab-emails.txt", emailText(report));
    } else if (type === "user") {
      files.set("user-intel.json", json);
      files.set("unique-emails.txt", emailText(report));
    } else files.set("repository-intel.json", json);
  }
  if (report.platform === "github" && type === "domain") {
    fs.rmSync(path.join(directory, "runs"), { recursive: true, force: true });
    for (const legacy of ["repositories.json", "unique-emails.txt"]) fs.rmSync(path.join(directory, legacy), { force: true });
  }
  for (const [name, content] of files) {
    atomicWrite(path.join(directory, name), content);
  }
  return directory;
}

module.exports = { summaryText, emailText, buildPrimaryResults, writeReport };
