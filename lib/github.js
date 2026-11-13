"use strict";

const { createRequester } = require("./http");
const { baseReport, dedupeEmails, dedupeRepositories, extractObservables, inspectContent, addRelationshipIndicators } = require("./common");

function createGitHubClient({ token = process.env.GITHUB_TOKEN, fetchImpl, sleepImpl } = {}) {
  const headers = { Accept: "application/vnd.github+json, application/vnd.github.text-match+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "public-osint-cli" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const request = createRequester({ headers, fetchImpl, sleepImpl });
  const api = async (endpoint, params = {}) => {
    const url = new URL(endpoint, "https://api.github.com");
    for (const [key, value] of Object.entries(params)) if (value !== undefined) url.searchParams.set(key, String(value));
    return request(url.toString());
  };
  const list = async (endpoint, params = {}, limit = 20) => {
    const result = [];
    const pages = Math.min(10, Math.ceil(limit / 100) || 1);
    for (let page = 1; page <= pages && result.length < limit; page += 1) {
      const data = await api(endpoint, { ...params, per_page: Math.min(100, limit), page });
      const items = Array.isArray(data) ? data : data?.items;
      if (!Array.isArray(items)) break;
      result.push(...items);
      if (items.length < Math.min(100, limit)) break;
    }
    return result.slice(0, limit);
  };
  return { api, list, authenticated: Boolean(token) };
}

function repositoryRecord(repo, evidence = []) {
  return {
    id: repo.id ?? null, owner: repo.owner?.login || repo.full_name?.split("/")[0] || null,
    name: repo.name || repo.path || null, full_name: repo.full_name || null,
    url: repo.html_url || null, description: repo.description ?? null,
    visibility: repo.visibility || (repo.private === false ? "public" : null), homepage: repo.homepage || null,
    created_at: repo.created_at || null, updated_at: repo.updated_at || null, pushed_at: repo.pushed_at || null,
    archived: repo.archived ?? null, fork: repo.fork ?? null, default_branch: repo.default_branch || null,
    evidence: [...new Set(evidence)].sort(), matches: [], commits: [], observables: { domains: [], urls: [], ips: [] }
  };
}

function createState(type, target, keywords, collectedAt) {
  const report = baseReport("github", { type, target, keywords }, collectedAt);
  const repositories = new Map();
  const emails = [];
  const domains = new Set();
  const addRepo = (repo, evidence) => {
    if (!repo?.html_url) return null;
    const key = repo.html_url.toLowerCase().replace(/\/$/, "");
    if (!repositories.has(key)) repositories.set(key, repositoryRecord(repo, [evidence]));
    else if (evidence) repositories.get(key).evidence.push(evidence);
    return repositories.get(key);
  };
  const fail = (label, error) => { report.errors.push(`${label}: ${error.message}`); report.partial = true; };
  const safe = async (label, action, fallback = []) => { try { return await action(); } catch (error) { fail(label, error); return fallback; } };
  return { report, repositories, emails, domains, addRepo, safe, fail, collectedAt };
}

function repositoryRelevance(record) {
  const evidence = new Set(record.evidence);
  let score = 0;
  if (evidence.has("exact_domain_homepage")) score += 100;
  if (evidence.has("exact_domain_code_match")) score += 80;
  if (evidence.has("exact_domain_repository_search")) score += 40;
  if (evidence.has("keyword_code_match")) score += 20;
  if (evidence.has("keyword_repository_search")) score += 10;
  if (evidence.has("exact_repository_lookup") || evidence.has("public_user_repository")) score = 100;
  score = Math.min(100, score);
  return { score, level: score >= 80 ? "strong" : score >= 40 ? "moderate" : "weak", scope: evidence.has("exact_domain_homepage") || evidence.has("exact_domain_code_match") ? "exact_domain" : evidence.has("exact_domain_repository_search") ? "domain_search" : "keyword_only", note: "Relevance measures collected evidence, not ownership or maliciousness." };
}

function addCommit(commit, record, state) {
  const raw = commit.commit || commit;
  const entry = {
    sha: commit.sha || commit.id || null, url: commit.html_url || null,
    message: raw.message?.split("\n")[0] || null,
    author: { name: raw.author?.name || null, email: raw.author?.email || null, date: raw.author?.date || null, username: commit.author?.login || null },
    committer: { name: raw.committer?.name || null, email: raw.committer?.email || null, date: raw.committer?.date || null, username: commit.committer?.login || null }
  };
  record.commits.push(entry);
  for (const [role, identity] of [["author", entry.author], ["committer", entry.committer]]) {
    if (identity.email) state.emails.push({ email: identity.email, names: identity.name ? [identity.name] : [], repositories: [record.full_name], evidence: [{ role, sha: entry.sha, source_url: entry.url, repository: record.full_name, evidence_type: "public_commit_metadata", collected_at: state.collectedAt }] });
  }
}

function mergeObservables(observables, record, source, state) {
  for (const email of observables.emails) state.emails.push({ email, repositories: [record.full_name], evidence: [{ source_url: source.url, repository: record.full_name, path: source.path, evidence_type: "public_file_content", collected_at: state.collectedAt }] });
  for (const domain of observables.domains) state.domains.add(domain);
  const evidence = value => ({ value, source_url: source.url, path: source.path, collected_at: state.collectedAt });
  record.observables.domains.push(...observables.domains.map(evidence));
  record.observables.urls.push(...observables.urls.map(evidence));
  record.observables.ips.push(...observables.ips.map(evidence));
  for (const url of observables.urls) {
    try { state.domains.add(new URL(url).hostname.toLowerCase()); } catch {}
  }
}

function relevantPath(path, terms) {
  const lower = path.toLowerCase();
  return /(^|\/)(readme|index|login|signin|auth|config|package|vercel|netlify|firebase|\.env)[^/]*$/i.test(path) || terms.some(term => lower.includes(term.toLowerCase()));
}

async function inspectRepository(client, repo, record, state, terms, fileLimit = 15) {
  const encoded = repo.full_name.split("/").map(encodeURIComponent).join("/");
  const commits = await state.safe(`commits ${repo.full_name}`, () => client.list(`/repos/${encoded}/commits`, {}, Math.min(30, fileLimit * 2)));
  for (const commit of commits) addCommit(commit, record, state);
  const branch = repo.default_branch || "HEAD";
  const matchedPaths = new Set(record.matches.map(x => x.path));
  const broadInspection = state.report.query.type !== "domain" || record.evidence.some(x => x.startsWith("exact_domain_"));
  let files;
  if (broadInspection) {
    const tree = await state.safe(`tree ${repo.full_name}`, () => client.api(`/repos/${encoded}/git/trees/${encodeURIComponent(branch)}`, { recursive: 1 }), null);
    if (!tree?.tree) return;
    if (tree.truncated) state.fail(`tree ${repo.full_name}`, new Error("Git tree was truncated by GitHub"));
    files = tree.tree.filter(x => x.type === "blob" && x.size <= 500_000 && relevantPath(x.path, terms)).slice(0, fileLimit);
  } else {
    files = [...matchedPaths].slice(0, fileLimit).map(path => ({ path }));
  }
  for (const file of files) {
    const content = await state.safe(`file ${repo.full_name}/${file.path}`, () => client.api(`/repos/${encoded}/contents/${file.path.split("/").map(encodeURIComponent).join("/")}`, { ref: branch }), null);
    if (!content?.content || content.encoding !== "base64") continue;
    const text = Buffer.from(content.content.replace(/\n/g, ""), "base64").toString("utf8");
    const sourceUrl = content.html_url || `${repo.html_url}/blob/${branch}/${file.path}`;
    const exact = terms[0] && text.toLowerCase().includes(terms[0].toLowerCase());
    record.matches.push({ path: file.path, source_url: sourceUrl, match_type: exact ? "exact_domain" : "inspected_relevant_file", snippet: exact ? text.slice(Math.max(0, text.toLowerCase().indexOf(terms[0].toLowerCase()) - 120), text.toLowerCase().indexOf(terms[0].toLowerCase()) + terms[0].length + 180) : null });
    mergeObservables(extractObservables(text), record, { url: sourceUrl, path: file.path }, state);
    state.report.indicators.push(...inspectContent(text, { sourceUrl, repository: record.full_name, path: file.path, keywords: state.report.query.keywords }, state.collectedAt));
  }
}

async function investigateDomain(client, target, keywords, limit, state) {
  const searches = [{ q: `"${target}"`, evidence: "exact_domain_repository_search" }, ...keywords.map(q => ({ q, evidence: "keyword_repository_search" }))];
  for (const search of searches) {
    const items = await state.safe(`repository search ${search.q}`, () => client.list("/search/repositories", { q: search.q }, limit));
    for (const repo of items) {
      const record = state.addRepo(repo, search.evidence);
      if (record && repo.homepage) {
        try {
          const host = new URL(repo.homepage.includes("://") ? repo.homepage : `https://${repo.homepage}`).hostname.toLowerCase();
          if (host === target || host.endsWith(`.${target}`)) record.evidence.push("exact_domain_homepage");
        } catch {}
      }
    }
  }
  const codeQueries = [{ q: `"${target}" in:file`, type: "exact_domain" }, ...keywords.map(q => ({ q: `${q} in:file`, type: "keyword_only" }))];
  for (const search of codeQueries) {
    if (!client.authenticated) { state.report.errors.push(`Code search '${search.q}' skipped: GITHUB_TOKEN is required by GitHub`); state.report.partial = true; continue; }
    const items = await state.safe(`code search ${search.q}`, () => client.list("/search/code", { q: search.q }, limit));
    for (const item of items) {
      const record = state.addRepo(item.repository, search.type === "exact_domain" ? "exact_domain_code_match" : "keyword_code_match");
      if (record) record.matches.push({ path: item.path, source_url: item.html_url, match_type: search.type, snippet: item.text_matches?.[0]?.fragment?.slice(0, 1000) || null });
    }
  }
  for (const term of [target, ...keywords].slice(0, 3)) {
    const found = await state.safe(`user search ${term}`, () => client.list("/search/users", { q: term }, limit));
    for (const user of found) state.report.users.push({ username: user.login, url: user.html_url, type: user.type || null, evidence: term === target ? "exact_domain_profile_search" : "keyword_profile_search" });
  }
  const candidates = [...state.repositories.values()].slice(0, limit);
  for (const record of candidates) {
    const repo = await state.safe(`repository ${record.full_name}`, () => client.api(`/repos/${record.full_name.split("/").map(encodeURIComponent).join("/")}`), null);
    if (repo) {
      Object.assign(record, { description: repo.description ?? null, visibility: repo.visibility || "public", homepage: repo.homepage || null, created_at: repo.created_at || null, updated_at: repo.updated_at || null, pushed_at: repo.pushed_at || null, archived: repo.archived ?? null, default_branch: repo.default_branch || null });
      await inspectRepository(client, repo, record, state, [target, ...keywords], Math.min(15, limit));
    }
  }
}

async function investigateUser(client, username, limit, state) {
  const user = await client.api(`/users/${encodeURIComponent(username)}`);
  state.report.users.push({ id: user.id ?? null, username: user.login, name: user.name ?? null, url: user.html_url, bio: user.bio ?? null, company: user.company ?? null, location: user.location ?? null, blog: user.blog || null, public_email: user.email || null, created_at: user.created_at || null, updated_at: user.updated_at || null, evidence: "exact_public_profile" });
  if (user.email) state.emails.push({ email: user.email, repositories: [], evidence: [{ source_url: user.html_url, repository: null, evidence_type: "public_profile", collected_at: state.collectedAt }] });
  const repos = await state.safe("public repositories", () => client.list(`/users/${encodeURIComponent(user.login)}/repos`, { type: "owner", sort: "updated" }, limit));
  const orgs = await state.safe("public organizations", () => client.list(`/users/${encodeURIComponent(user.login)}/orgs`, {}, limit));
  state.report.users[0].organizations = orgs.map(x => ({ login: x.login, url: `https://github.com/${x.login}` }));
  for (const repo of repos) {
    const record = state.addRepo(repo, "public_user_repository");
    await inspectRepository(client, repo, record, state, [username], Math.min(10, limit));
  }
}

async function investigateRepository(client, target, limit, state) {
  const encoded = target.split("/").map(encodeURIComponent).join("/");
  const repo = await client.api(`/repos/${encoded}`);
  if (repo.private) throw new Error("Repository is not public");
  const record = state.addRepo(repo, "exact_repository_lookup");
  await inspectRepository(client, repo, record, state, target.split(/[\/_-]/), Math.min(30, limit));
}

function mergeEmailEvidence(items) {
  const map = new Map();
  for (const item of items) {
    const key = String(item.email || "").toLowerCase();
    if (!key) continue;
    if (!map.has(key)) map.set(key, { email: key, names: [], repositories: [], evidence: [] });
    const current = map.get(key);
    current.names.push(...(item.names || [])); current.repositories.push(...(item.repositories || [])); current.evidence.push(...(item.evidence || []));
  }
  return dedupeEmails([...map.values()].map(x => ({ ...x, names: [...new Set(x.names)].sort(), repositories: [...new Set(x.repositories)].filter(Boolean).sort(), evidence: x.evidence.sort((a, b) => String(a.source_url).localeCompare(String(b.source_url))) })));
}

async function runGitHubInvestigation({ type, target, keywords = [], limit = 20, client = createGitHubClient(), collectedAt = new Date().toISOString() }) {
  const state = createState(type, target, keywords, collectedAt);
  state.report.capabilities = { authenticated: client.authenticated, repository_search: true, code_search: client.authenticated };
  if (type === "domain") await investigateDomain(client, target, keywords, limit, state);
  else if (type === "user") await investigateUser(client, target, limit, state);
  else await investigateRepository(client, target, limit, state);
  state.report.repositories = dedupeRepositories([...state.repositories.values()].map(record => ({ ...record, relevance: repositoryRelevance(record), evidence: [...new Set(record.evidence)].sort(), matches: record.matches.sort((a, b) => String(a.source_url).localeCompare(String(b.source_url))), commits: record.commits.sort((a, b) => String(a.sha).localeCompare(String(b.sha))), observables: Object.fromEntries(Object.entries(record.observables).map(([key, values]) => [key, [...new Map(values.map(item => [`${item.value}|${item.source_url}|${item.path}`, item])).values()].sort((a, b) => a.value.localeCompare(b.value))])) }))).sort((a, b) => b.relevance.score - a.relevance.score || a.url.localeCompare(b.url));
  state.report.users.sort((a, b) => String(a.username).localeCompare(String(b.username)));
  state.report.emails = mergeEmailEvidence(state.emails);
  state.report.domains = [...state.domains].sort();
  addRelationshipIndicators(state.report);
  state.report.indicators.sort((a, b) => `${a.repository}/${a.path}/${a.type}`.localeCompare(`${b.repository}/${b.path}/${b.type}`));
  return state.report;
}

module.exports = { createGitHubClient, runGitHubInvestigation, repositoryRecord };
