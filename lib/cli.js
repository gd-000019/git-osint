"use strict";

const { parseCli, usage } = require("./common");
const { createGitHubClient, runGitHubInvestigation } = require("./github");
const { createGitLabClient, runGitLabInvestigation } = require("./gitlab");
const { writeReport } = require("./report");
const { loadEnvFile } = require("./env");

async function runCli(platform, argv = process.argv.slice(2), dependencies = {}) {
  loadEnvFile();
  let config;
  try { config = parseCli(argv, platform); }
  catch (error) {
    console.error(`Error: ${error.message}\n\n${usage(platform)}`);
    return 2;
  }
  if (config.help) { console.log(usage(platform)); return 0; }
  try {
    const client = dependencies.client || (platform === "github" ? createGitHubClient(dependencies) : createGitLabClient(dependencies));
    const runner = platform === "github" ? runGitHubInvestigation : runGitLabInvestigation;
    if (!client.authenticated) console.error(`[!] ${platform === "github" ? "GITHUB_TOKEN" : "GITLAB_TOKEN"} is not set. Running with public unauthenticated limits; code search is unavailable. Add the token to the project .env file for configured access.`);
    if (!config.json) console.error(`[+] Investigating ${platform} ${config.type}: ${config.target}`);
    const report = await runner({ ...config, client, collectedAt: dependencies.collectedAt });
    const directory = writeReport(report, config.folder, dependencies.now, { includeAll: config.includeAll, includeBots: config.includeBots });
    if (config.json) process.stdout.write(`${JSON.stringify(report)}\n`);
    else console.error(`[+] Saved ${report.repositories.length} repositories, ${report.emails.length} emails to ${directory}`);
    return report.partial ? 3 : 0;
  } catch (error) {
    console.error(`Error: ${error.message}`);
    return 1;
  }
}

module.exports = { runCli };
