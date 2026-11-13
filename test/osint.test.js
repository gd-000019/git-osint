"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { parseCli, outputDirectory, dedupeEmails, dedupeRepositories, extractObservables, inspectContent } = require("../lib/common");
const { createRequester, ApiError } = require("../lib/http");
const { runGitHubInvestigation } = require("../lib/github");
const { runGitLabInvestigation } = require("../lib/gitlab");
const { buildPrimaryResults, writeReport } = require("../lib/report");

const collectedAt = "2026-11-12T12:00:00.000Z";
const githubRepo = {
  id: 1, name: "repo", full_name: "owner/repo", html_url: "https://github.com/owner/repo",
  owner: { login: "owner" }, private: false, visibility: "public", description: null,
  homepage: null, created_at: collectedAt, updated_at: collectedAt, pushed_at: collectedAt,
  archived: false, fork: false, default_branch: "main"
};
const gitlabProject = {
  id: 2, name: "repo", path_with_namespace: "owner/repo", web_url: "https://gitlab.com/owner/repo",
  namespace: { full_path: "owner" }, visibility: "public", description: null, website_url: null,
  created_at: collectedAt, last_activity_at: collectedAt, archived: false, default_branch: "main"
};

function githubClient({ failSearch = false, includeRepo = true } = {}) {
  return {
    authenticated: true,
    async list(endpoint, params) {
      if (failSearch && endpoint.startsWith("/search/")) throw new Error("rate limited");
      if (endpoint === "/search/repositories") return includeRepo ? [githubRepo, githubRepo] : [];
      if (endpoint === "/search/users") return [];
      if (endpoint === "/search/code") return [];
      if (endpoint.includes("/repos") && !endpoint.includes("/commits")) return includeRepo ? [githubRepo] : [];
      return [];
    },
    async api(endpoint) {
      if (endpoint === "/users/alice") return { id: 7, login: "alice", html_url: "https://github.com/alice", email: "Alice@Example.com", created_at: collectedAt, updated_at: collectedAt };
      if (endpoint.includes("/git/trees/")) return { tree: [] };
      if (endpoint.startsWith("/repos/")) return githubRepo;
      return [];
    }
  };
}

function gitlabClient({ failSearch = false, includeProject = true } = {}) {
  return {
    authenticated: true,
    async list(endpoint) {
      if (failSearch && ["/projects", "/users", "/search"].includes(endpoint)) throw new Error("forbidden");
      if (endpoint === "/projects") return includeProject ? [gitlabProject, gitlabProject] : [];
      if (endpoint === "/users") return [];
      if (endpoint === "/search") return [];
      if (endpoint.includes("/projects") && endpoint.includes("/repository/")) return [];
      return [];
    },
    async api(endpoint) {
      if (endpoint === "/users") return [{ id: 8, username: "alice", web_url: "https://gitlab.com/alice" }];
      if (endpoint === "/users/8") return { id: 8, username: "alice", web_url: "https://gitlab.com/alice", public_email: "alice@example.com" };
      if (endpoint.startsWith("/projects/")) return gitlabProject;
      return [];
    }
  };
}

test("CLI parses domain investigations with and without keywords", () => {
  const parsed = parseCli(["domain", "Example.COM", "example", "--limit", "5", "--include-all", "--include-bots"], "github");
  assert.deepEqual(parsed.keywords, ["example"]);
  assert.equal(parsed.includeAll, true);
  assert.equal(parsed.includeBots, true);
  assert.deepEqual(parseCli(["domain", "example.com"], "gitlab").keywords, []);
});

test("CLI rejects malformed and traversal-like inputs", () => {
  assert.throws(() => parseCli(["domain", "../example.com"], "github"), /Invalid domain/);
  assert.throws(() => parseCli(["repository", "../secret"], "github"), /Invalid repository/);
  assert.throws(() => parseCli(["user", "a", "extra"], "github"), /does not accept keywords/);
  assert.throws(() => parseCli(["domain", "example.com", "--limit", "0"], "github"), /1 to 100/);
});

test("domain investigations distinguish keywords and deduplicate repositories", async () => {
  const report = await runGitHubInvestigation({ type: "domain", target: "example.com", keywords: ["brand"], limit: 5, client: githubClient(), collectedAt });
  assert.equal(report.repositories.length, 1);
  assert.deepEqual(report.query.keywords, ["brand"]);
  assert.ok(report.repositories[0].evidence.includes("exact_domain_repository_search"));
  assert.ok(report.repositories[0].evidence.includes("keyword_repository_search"));
});

test("weak keyword-only GitHub matches inspect matched files without recursive trees", async () => {
  let treeRequested = false;
  const client = {
    authenticated: true,
    async list(endpoint, params) {
      if (endpoint === "/search/code" && params.q.startsWith("brand")) return [{ path: "matched.html", html_url: `${githubRepo.html_url}/blob/main/matched.html`, repository: githubRepo }];
      return [];
    },
    async api(endpoint) {
      if (endpoint.includes("/git/trees/")) { treeRequested = true; throw new Error("tree should not be requested"); }
      if (endpoint.includes("/contents/matched.html")) return { encoding: "base64", content: Buffer.from("brand reference").toString("base64"), html_url: `${githubRepo.html_url}/blob/main/matched.html` };
      if (endpoint.startsWith("/repos/")) return githubRepo;
      return [];
    }
  };
  const report = await runGitHubInvestigation({ type: "domain", target: "example.com", keywords: ["brand"], limit: 5, client, collectedAt });
  assert.equal(treeRequested, false);
  assert.equal(report.repositories[0].relevance.scope, "keyword_only");
  assert.equal(report.partial, false);
});

test("user intelligence collects public profile email", async () => {
  const report = await runGitHubInvestigation({ type: "user", target: "alice", limit: 5, client: githubClient({ includeRepo: false }), collectedAt });
  assert.equal(report.users[0].username, "alice");
  assert.equal(report.emails[0].email, "alice@example.com");
});

test("GitLab user intelligence collects the exact public profile", async () => {
  const report = await runGitLabInvestigation({ type: "user", target: "alice", limit: 5, client: gitlabClient({ includeProject: false }), collectedAt });
  assert.equal(report.users[0].username, "alice");
  assert.equal(report.emails[0].email, "alice@example.com");
});

test("repository intelligence returns exact public repository", async () => {
  const report = await runGitHubInvestigation({ type: "repository", target: "owner/repo", limit: 5, client: githubClient(), collectedAt });
  assert.equal(report.repositories[0].full_name, "owner/repo");
  assert.deepEqual(report.repositories[0].evidence, ["exact_repository_lookup"]);
});

test("GitHub domain writer creates exactly the four primary files", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "osint-test-"));
  try {
    const config = parseCli(["domain", "example.com"], "github");
    assert.equal(config.folder, "OUTPUT");
    const report = { platform: "github", query: { type: "domain", target: "example.com", keywords: [] }, collected_at: collectedAt, users: [], repositories: [], emails: [], domains: [], indicators: [], errors: [], partial: false };
    const directory = writeReport(report, path.join(temp, "custom"), new Date("2026-11-12T12:00:00Z"));
    assert.match(directory, /custom\/12-11-2026\/github\/domains\/example\.com$/);
    assert.deepEqual(fs.readdirSync(directory).sort(), ["domain-intel.json", "repositories-intel.json", "results.json", "search.txt"]);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(directory, "repositories-intel.json"), "utf8")), report.repositories);
    assert.ok(outputDirectory(path.join(temp, config.folder), "github", "user", "alice").startsWith(temp));
  } finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("results.json defaults to exact non-bot pairs and counts commit evidence", () => {
  const report = {
    query: { target: "example.com", keywords: ["brand"] }, collected_at: collectedAt,
    repositories: [
      { full_name: "owner/exact", url: "https://github.com/owner/exact", relevance: { score: 100, level: "strong", scope: "exact_domain" } },
      { full_name: "owner/weak", url: "https://github.com/owner/weak", relevance: { score: 20, level: "weak", scope: "keyword_only" } }
    ],
    emails: [
      { email: "Person@Example.com", evidence: [
        { repository: "owner/exact", evidence_type: "public_commit_metadata" },
        { repository: "owner/exact", evidence_type: "public_commit_metadata" },
        { repository: "owner/exact", evidence_type: "public_file_content" },
        { repository: "owner/weak", evidence_type: "public_commit_metadata" }
      ] },
      { email: "noreply@github.com", evidence: [{ repository: "owner/exact", evidence_type: "public_commit_metadata" }] },
      { email: "1+renovate[bot]@users.noreply.github.com", evidence: [{ repository: "owner/exact", evidence_type: "public_commit_metadata" }] }
    ]
  };
  const primary = buildPrimaryResults(report);
  assert.deepEqual(primary.totals, { repositories: 1, emails: 1, pairs: 1 });
  assert.equal(primary.results[0].email, "person@example.com");
  assert.equal(primary.results[0].amount, 2);
  assert.equal(buildPrimaryResults(report, { includeAll: true }).results.length, 2);
  assert.equal(buildPrimaryResults(report, { includeBots: true }).results.length, 3);
});

test("email and canonical repository deduplication is deterministic", () => {
  assert.deepEqual(dedupeEmails(["A@Example.com", "a@example.com"]), ["a@example.com"]);
  assert.equal(dedupeRepositories([{ url: "https://x.test/A/" }, { url: "https://x.test/a" }]).length, 1);
});

test("observable extraction excludes common filenames and JavaScript properties", () => {
  const result = extractObservables("1.jpg array.from auth-v2-login.html example.com https://safe.example/path");
  assert.deepEqual(result.domains, ["example.com", "safe.example"]);
});

test("requester retries rate limits and surfaces 404 without retry", async () => {
  let calls = 0;
  const request = createRequester({
    fetchImpl: async () => {
      calls += 1;
      return calls === 1
        ? new Response("limited", { status: 429, headers: { "retry-after": "1" } })
        : new Response('{"ok":true}', { status: 200, headers: { "content-type": "application/json" } });
    }, sleepImpl: async () => {}, retries: 2
  });
  assert.deepEqual(await request("https://api.github.com/test"), { ok: true });
  assert.equal(calls, 2);
  const missing = createRequester({ fetchImpl: async () => new Response("missing", { status: 404 }), retries: 2 });
  await assert.rejects(() => missing("https://api.github.com/missing"), error => error instanceof ApiError && error.status === 404);
});

test("empty results and search failures are represented without fabricated data", async () => {
  const empty = await runGitHubInvestigation({ type: "domain", target: "example.com", limit: 2, client: githubClient({ includeRepo: false }), collectedAt });
  assert.deepEqual(empty.repositories, []);
  const partial = await runGitHubInvestigation({ type: "domain", target: "example.com", limit: 2, client: githubClient({ failSearch: true }), collectedAt });
  assert.equal(partial.partial, true);
  assert.ok(partial.errors.length > 0);
});

test("GitHub and GitLab reports share the intelligence envelope", async () => {
  const github = await runGitHubInvestigation({ type: "domain", target: "example.com", limit: 2, client: githubClient({ includeRepo: false }), collectedAt });
  const gitlab = await runGitLabInvestigation({ type: "domain", target: "example.com", limit: 2, client: gitlabClient({ includeProject: false }), collectedAt });
  const keys = ["platform", "query", "collected_at", "capabilities", "users", "repositories", "emails", "domains", "indicators", "errors", "partial"];
  assert.deepEqual(Object.keys(github), keys);
  assert.deepEqual(Object.keys(gitlab), keys);
});

test("static inspection classifies evidence conservatively", () => {
  const indicators = inspectContent('<form action="https://forms.example/collect"><input type="password"></form>', { sourceUrl: "https://github.com/o/r/blob/main/index.html", repository: "o/r", path: "index.html" }, collectedAt);
  assert.equal(indicators[0].severity, "medium");
  assert.match(indicators[0].reason, /manual review/);
  assert.equal(indicators[0].source_url, "https://github.com/o/r/blob/main/index.html");
});
