"use strict";

const { createRequester } = require("./http");
const { baseReport, dedupeEmails, dedupeRepositories, extractObservables, inspectContent, addRelationshipIndicators } = require("./common");

function normalizeGitLabUrl(value) {
  const url = new URL(value || "https://gitlab.com");
  if (!/^https?:$/.test(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error("GITLAB_URL must be an HTTP(S) origin");
  return `${url.origin}${url.pathname.replace(/\/+$/, "")}/api/v4`;
}

function createGitLabClient({ token = process.env.GITLAB_TOKEN, baseUrl = process.env.GITLAB_URL, fetchImpl, sleepImpl } = {}) {
  const headers = { Accept: "application/json", "User-Agent": "public-osint-cli" };
  if (token) headers["PRIVATE-TOKEN"] = token;
  const request = createRequester({ headers, fetchImpl, sleepImpl });
  const base = normalizeGitLabUrl(baseUrl);
  const api = async (endpoint, params = {}) => {
    const url = new URL(`${base}${endpoint}`);
    for (const [key, value] of Object.entries(params)) if (value !== undefined) url.searchParams.set(key, String(value));
    return request(url.toString());
  };
  const list = async (endpoint, params = {}, limit = 20) => {
    const result = [];
    for (let page = 1; page <= Math.min(10, Math.ceil(limit / 100) || 1) && result.length < limit; page += 1) {
      const data = await api(endpoint, { ...params, per_page: Math.min(100, limit), page });
      if (!Array.isArray(data)) break;
      result.push(...data);
      if (data.length < Math.min(100, limit)) break;
    }
    return result.slice(0, limit);
  };
  return { api, list, authenticated: Boolean(token), base };
}

function projectRecord(project, evidence) {
  return {
    id: project.id ?? null, owner: project.namespace?.full_path || project.path_with_namespace?.split("/")[0] || null,
    name: project.name || null, full_name: project.path_with_namespace || null, url: project.web_url || null,
    description: project.description ?? null, visibility: project.visibility || null, homepage: project.web_url || null,
    website_url: project.website_url || null, created_at: project.created_at || null,
    updated_at: project.last_activity_at || null, pushed_at: project.last_activity_at || null,
    archived: project.archived ?? null, default_branch: project.default_branch || null,
    evidence: evidence ? [evidence] : [], matches: [], commits: [], observables: { domains: [], urls: [], ips: [] }
  };
}

function createState(type, target, keywords, collectedAt) {
  const report = baseReport("gitlab", { type, target, keywords }, collectedAt);
  const projects = new Map(); const emails = []; const domains = new Set();
  const addProject = (project, evidence) => {
    if (!project?.web_url) return null;
    const key = project.web_url.toLowerCase().replace(/\/$/, "");
    if (!projects.has(key)) projects.set(key, projectRecord(project, evidence));
    else projects.get(key).evidence.push(evidence);
    return projects.get(key);
  };
  const fail = (label, error) => { report.errors.push(`${label}: ${error.message}`); report.partial = true; };
  const safe = async (label, fn, fallback = []) => { try { return await fn(); } catch (error) { fail(label, error); return fallback; } };
  return { report, projects, emails, domains, addProject, safe, fail, collectedAt };
}

function projectRelevance(record) {
  const evidence = new Set(record.evidence);
  let score = 0;
  if (evidence.has("exact_domain_homepage")) score += 100;
  if (evidence.has("exact_domain_code_match")) score += 80;
  if (evidence.has("exact_domain_project_search")) score += 40;
  if (evidence.has("keyword_code_match")) score += 20;
  if (evidence.has("keyword_project_search")) score += 10;
  if (evidence.has("exact_repository_lookup") || evidence.has("public_user_repository")) score = 100;
  score = Math.min(100, score);
  return { score, level: score >= 80 ? "strong" : score >= 40 ? "moderate" : "weak", scope: evidence.has("exact_domain_homepage") || evidence.has("exact_domain_code_match") ? "exact_domain" : evidence.has("exact_domain_project_search") ? "domain_search" : "keyword_only", note: "Relevance measures collected evidence, not ownership or maliciousness." };
}

function addCommit(commit, record, state) {
  const item = { sha: commit.id || null, url: commit.web_url || null, message: commit.title || null, author: { name: commit.author_name || null, email: commit.author_email || null, date: commit.authored_date || null }, committer: { name: commit.committer_name || null, email: commit.committer_email || null, date: commit.committed_date || null } };
  record.commits.push(item);
  for (const [role, identity] of [["author", item.author], ["committer", item.committer]]) if (identity.email) state.emails.push({ email: identity.email, names: identity.name ? [identity.name] : [], repositories: [record.full_name], evidence: [{ role, sha: item.sha, source_url: item.url, repository: record.full_name, evidence_type: "public_commit_metadata", collected_at: state.collectedAt }] });
}

function relevantPath(value, terms) {
  const path = value.toLowerCase();
  return /(^|\/)(readme|index|login|signin|auth|config|package|vercel|netlify|firebase|\.env)[^/]*$/i.test(value) || terms.some(term => path.includes(term.toLowerCase()));
}

async function inspectProject(client, project, record, state, terms, limit) {
  const id = encodeURIComponent(project.id);
  const commits = await state.safe(`commits ${record.full_name}`, () => client.list(`/projects/${id}/repository/commits`, {}, Math.min(30, limit * 2)));
  for (const commit of commits) addCommit(commit, record, state);
  const matchedPaths = new Set(record.matches.map(x => x.path));
  const broadInspection = state.report.query.type !== "domain" || record.evidence.some(x => x.startsWith("exact_domain_"));
  const files = broadInspection
    ? (await state.safe(`tree ${record.full_name}`, () => client.list(`/projects/${id}/repository/tree`, { recursive: true }, Math.min(100, limit * 10)))).filter(x => x.type === "blob" && relevantPath(x.path, terms)).slice(0, limit)
    : [...matchedPaths].slice(0, limit).map(path => ({ path }));
  for (const file of files) {
    const encodedPath = encodeURIComponent(file.path);
    const data = await state.safe(`file ${record.full_name}/${file.path}`, () => client.api(`/projects/${id}/repository/files/${encodedPath}`, { ref: project.default_branch || "HEAD" }), null);
    if (!data?.content || data.encoding !== "base64") continue;
    const text = Buffer.from(data.content, "base64").toString("utf8");
    const sourceUrl = `${project.web_url}/-/blob/${encodeURIComponent(project.default_branch || "HEAD")}/${file.path.split("/").map(encodeURIComponent).join("/")}`;
    const index = terms[0] ? text.toLowerCase().indexOf(terms[0].toLowerCase()) : -1;
    record.matches.push({ path: file.path, source_url: sourceUrl, match_type: index >= 0 ? "exact_domain" : "inspected_relevant_file", snippet: index >= 0 ? text.slice(Math.max(0, index - 120), index + terms[0].length + 180) : null });
    const observables = extractObservables(text);
    for (const email of observables.emails) state.emails.push({ email, repositories: [record.full_name], evidence: [{ source_url: sourceUrl, repository: record.full_name, path: file.path, evidence_type: "public_file_content", collected_at: state.collectedAt }] });
    for (const domain of observables.domains) state.domains.add(domain);
    const evidence = value => ({ value, source_url: sourceUrl, path: file.path, collected_at: state.collectedAt });
    record.observables.domains.push(...observables.domains.map(evidence));
    record.observables.urls.push(...observables.urls.map(evidence));
    record.observables.ips.push(...observables.ips.map(evidence));
    state.report.indicators.push(...inspectContent(text, { sourceUrl, repository: record.full_name, path: file.path, keywords: state.report.query.keywords }, state.collectedAt));
  }
}

async function investigateDomain(client, target, keywords, limit, state) {
  for (const term of [target, ...keywords]) {
    const projects = await state.safe(`project search ${term}`, () => client.list("/projects", { search: term, visibility: "public", simple: true }, limit));
    for (const project of projects) {
      const record = state.addProject(project, term === target ? "exact_domain_project_search" : "keyword_project_search");
      if (record && project.website_url) {
        try {
          const host = new URL(project.website_url.includes("://") ? project.website_url : `https://${project.website_url}`).hostname.toLowerCase();
          if (host === target || host.endsWith(`.${target}`)) record.evidence.push("exact_domain_homepage");
        } catch {}
      }
    }
    const users = await state.safe(`user search ${term}`, () => client.list("/users", { search: term }, limit));
    for (const user of users) state.report.users.push({ id: user.id ?? null, username: user.username, name: user.name ?? null, url: user.web_url, evidence: term === target ? "exact_domain_profile_search" : "keyword_profile_search" });
    if (!client.authenticated) { state.report.errors.push(`Global code search '${term}' skipped: GITLAB_TOKEN or instance authorization may be required`); state.report.partial = true; continue; }
    const matches = await state.safe(`global code search ${term}`, () => client.list("/search", { scope: "blobs", search: term }, limit));
    for (const match of matches) {
      let record = [...state.projects.values()].find(x => x.id === match.project_id);
      if (!record) {
        const project = await state.safe(`resolve project ${match.project_id}`, () => client.api(`/projects/${encodeURIComponent(match.project_id)}`), null);
        if (project) record = state.addProject(project, term === target ? "exact_domain_code_match" : "keyword_code_match");
      }
      if (record) record.matches.push({ path: match.path, source_url: `${record.url}/-/blob/${encodeURIComponent(match.ref || "HEAD")}/${match.path.split("/").map(encodeURIComponent).join("/")}`, match_type: term === target ? "exact_domain" : "keyword_only", snippet: match.data?.slice(0, 1000) || null });
    }
  }
  for (const record of [...state.projects.values()].slice(0, limit)) {
    const project = await state.safe(`project ${record.full_name}`, () => client.api(`/projects/${encodeURIComponent(record.id)}`), null);
    if (project) {
      Object.assign(record, { description: project.description ?? null, visibility: project.visibility || null, website_url: project.website_url || null, created_at: project.created_at || null, updated_at: project.last_activity_at || null, archived: project.archived ?? null, default_branch: project.default_branch || null });
      await inspectProject(client, project, record, state, [target, ...keywords], Math.min(15, limit));
    }
  }
}

async function investigateUser(client, username, limit, state) {
  const found = await client.api("/users", { username });
  if (!Array.isArray(found) || !found.length) throw new Error(`GitLab user not found: ${username}`);
  const user = await state.safe("public user profile", () => client.api(`/users/${encodeURIComponent(found[0].id)}`), found[0]);
  state.report.users.push({ id: user.id ?? null, username: user.username, name: user.name ?? null, url: user.web_url, bio: user.bio ?? null, location: user.location ?? null, organization: user.organization ?? null, public_email: user.public_email || null, website_url: user.website_url || null, created_at: user.created_at || null, evidence: "exact_public_profile" });
  if (user.public_email) state.emails.push({ email: user.public_email, repositories: [], evidence: [{ source_url: user.web_url, repository: null, evidence_type: "public_profile", collected_at: state.collectedAt }] });
  const memberships = await state.safe("public group memberships", () => client.list(`/users/${encodeURIComponent(user.id)}/memberships`, {}, limit));
  state.report.users[0].organizations = memberships.map(x => ({ id: x.source_id || null, name: x.source_name || null, type: x.source_type || null }));
  const projects = await state.safe("public user projects", () => client.list(`/users/${encodeURIComponent(user.id)}/projects`, { visibility: "public" }, limit));
  for (const project of projects) {
    const record = state.addProject(project, "public_user_repository");
    await inspectProject(client, project, record, state, [username], Math.min(10, limit));
  }
}

async function investigateRepository(client, target, limit, state) {
  const project = await client.api(`/projects/${encodeURIComponent(target)}`);
  if (project.visibility !== "public") throw new Error("Repository is not public");
  const record = state.addProject(project, "exact_repository_lookup");
  await inspectProject(client, project, record, state, target.split(/[\/_-]/), Math.min(30, limit));
}

function mergeEmails(items) {
  const map = new Map();
  for (const item of items) {
    const key = String(item.email || "").toLowerCase();
    if (!key) continue;
    if (!map.has(key)) map.set(key, { email: key, names: [], repositories: [], evidence: [] });
    const current = map.get(key); current.names.push(...(item.names || [])); current.repositories.push(...(item.repositories || [])); current.evidence.push(...(item.evidence || []));
  }
  return dedupeEmails([...map.values()].map(x => ({ ...x, names: [...new Set(x.names)].sort(), repositories: [...new Set(x.repositories)].filter(Boolean).sort(), evidence: x.evidence.sort((a, b) => String(a.source_url).localeCompare(String(b.source_url))) })));
}

async function runGitLabInvestigation({ type, target, keywords = [], limit = 20, client = createGitLabClient(), collectedAt = new Date().toISOString() }) {
  const state = createState(type, target, keywords, collectedAt);
  state.report.capabilities = { authenticated: client.authenticated, repository_search: true, code_search: client.authenticated };
  if (type === "domain") await investigateDomain(client, target, keywords, limit, state);
  else if (type === "user") await investigateUser(client, target, limit, state);
  else await investigateRepository(client, target, limit, state);
  state.report.repositories = dedupeRepositories([...state.projects.values()].map(x => ({ ...x, relevance: projectRelevance(x), evidence: [...new Set(x.evidence)].sort(), matches: x.matches.sort((a, b) => String(a.source_url).localeCompare(String(b.source_url))), commits: x.commits.sort((a, b) => String(a.sha).localeCompare(String(b.sha))), observables: Object.fromEntries(Object.entries(x.observables).map(([key, values]) => [key, [...new Map(values.map(item => [`${item.value}|${item.source_url}|${item.path}`, item])).values()].sort((a, b) => a.value.localeCompare(b.value))])) }))).sort((a, b) => b.relevance.score - a.relevance.score || a.url.localeCompare(b.url));
  state.report.users.sort((a, b) => String(a.username).localeCompare(String(b.username)));
  state.report.emails = mergeEmails(state.emails); state.report.domains = [...state.domains].sort();
  addRelationshipIndicators(state.report);
  state.report.indicators.sort((a, b) => `${a.repository}/${a.path}/${a.type}`.localeCompare(`${b.repository}/${b.path}/${b.type}`));
  return state.report;
}

module.exports = { normalizeGitLabUrl, createGitLabClient, runGitLabInvestigation, projectRecord };
