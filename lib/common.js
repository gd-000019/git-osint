"use strict";

const fs = require("node:fs");
const path = require("node:path");
const net = require("node:net");

const EMAIL_RE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b/gi;
const URL_RE = /https?:\/\/[^\s<>"'`{}|\\^\[\]]+/gi;
const HOST_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi;
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

function usage(platform) {
  const repository = platform === "github" || platform === "gitlab"
    ? `\n  node ${platform}-osint.js repository owner/repository [--folder <path>] [--limit <number>] [--json]`
    : "";
  const resultFlags = platform === "github" ? " [--include-all] [--include-bots]" : "";
  const resultOptions = platform === "github" ? "\n  --include-all    Include weak/keyword-only repositories in results.json\n  --include-bots   Include bot and noreply addresses in results.json" : "";
  return `Usage:\n  node ${platform}-osint.js domain <domain> [keywords...] [--folder <path>] [--limit <number>] [--json]${resultFlags}\n  node ${platform}-osint.js user <username> [--folder <path>] [--limit <number>] [--json]${repository}\n\nOptions:\n  --folder <path>  Output root (default: OUTPUT)\n  --limit <number> Maximum results per category (1-100, default: 20)\n  --json           Print the JSON intelligence summary to stdout${resultOptions}\n  --help           Display this help`;
}

function normalizeDomain(value) {
  if (typeof value !== "string" || value.length > 253 || /[\\/\0]/.test(value)) {
    throw new Error("Invalid domain: provide a hostname such as example.com");
  }
  let host;
  try {
    host = new URL(value.includes("://") ? value : `https://${value}`).hostname;
  } catch {
    throw new Error("Invalid domain: provide a hostname such as example.com");
  }
  host = host.toLowerCase().replace(/\.$/, "");
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host)) {
    throw new Error("Invalid domain: provide a hostname such as example.com");
  }
  return host;
}

function validateUsername(value, platform = "github") {
  const valid = platform === "github"
    ? typeof value === "string" && /^[a-z\d](?:[a-z\d-]{0,37}[a-z\d])?$/i.test(value)
    : typeof value === "string" && value.length <= 255 && /^[a-z\d_](?:[a-z\d._-]*[a-z\d_-])?$/i.test(value) && !/\.(?:git|atom)$/i.test(value);
  if (!valid) throw new Error(`Invalid ${platform} username`);
  return value;
}

function validateRepository(value) {
  if (typeof value !== "string" || value.includes("..") || !/^[a-z\d_.-]+\/[a-z\d_.-]+$/i.test(value)) {
    throw new Error("Invalid repository: use owner/repository");
  }
  return value;
}

function parseCli(argv, platform) {
  if (argv.includes("--help") || argv.includes("-h")) return { help: true };
  const positional = [];
  const options = { folder: "output", limit: 20, json: false, includeAll: false, includeBots: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--json") options.json = true;
    else if (arg === "--include-all") options.includeAll = true;
    else if (arg === "--include-bots") options.includeBots = true;
    else if (arg === "--folder") {
      const value = argv[++i];
      if (!value || value.startsWith("--") || value.includes("\0")) throw new Error("--folder requires a valid path");
      options.folder = value;
    } else if (arg === "--limit") {
      const value = argv[++i];
      if (!/^\d+$/.test(value || "") || Number(value) < 1 || Number(value) > 100) {
        throw new Error("--limit must be an integer from 1 to 100");
      }
      options.limit = Number(value);
    } else if (arg.startsWith("--")) throw new Error(`Unknown option: ${arg}`);
    else positional.push(arg);
  }
  const [type, rawTarget, ...rawKeywords] = positional;
  if (!["domain", "user", "repository"].includes(type) || !rawTarget) {
    throw new Error("A command and target are required. Use --help for usage.");
  }
  if ((options.includeAll || options.includeBots) && (platform !== "github" || type !== "domain")) {
    throw new Error("--include-all and --include-bots are supported only for GitHub domain investigations");
  }
  if (type !== "domain" && rawKeywords.length) throw new Error(`${type} does not accept keywords`);
  const target = type === "domain" ? normalizeDomain(rawTarget)
    : type === "repository" ? validateRepository(rawTarget)
      : validateUsername(rawTarget, platform);
  const keywords = [...new Set(rawKeywords.map(x => x.trim()).filter(Boolean))];
  if (keywords.some(x => x.length > 100 || /[\0\r\n]/.test(x))) throw new Error("Keywords must be 1-100 characters without line breaks");
  return { help: false, type, target, keywords, ...options };
}

function sanitizeSegment(value) {
  const clean = String(value).normalize("NFKC").replace(/[^a-zA-Z0-9._-]+/g, "_").replace(/^\.+|\.+$/g, "").slice(0, 120);
  if (!clean || clean === "." || clean === "..") throw new Error("Target cannot be converted to a safe output directory");
  return clean;
}

function dateFolder(now = new Date()) {
  const pad = value => String(value).padStart(2, "0");
  return `${pad(now.getDate())}-${pad(now.getMonth() + 1)}-${now.getFullYear()}`;
}

function outputDirectory(root, platform, type, target, now = new Date()) {
  const rootPath = path.resolve(root);
  const plural = type === "repository" ? "repositories" : `${type}s`;
  const segment = type === "repository" ? target.replace("/", "__") : target;
  const result = path.resolve(rootPath, dateFolder(now), platform, plural, sanitizeSegment(segment));
  const relative = path.relative(rootPath, result);
  if (relative.startsWith("..") || path.isAbsolute(relative)) throw new Error("Unsafe output path rejected");
  return result;
}

function atomicWrite(file, content, mode = 0o600) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temporary = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.${Date.now()}.tmp`);
  try {
    fs.writeFileSync(temporary, content, { encoding: "utf8", mode });
    fs.renameSync(temporary, file);
  } finally {
    if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
  }
}

function canonicalUrl(value) {
  try {
    const url = new URL(value);
    url.hash = "";
    url.search = "";
    return url.toString().replace(/\/$/, "").toLowerCase();
  } catch { return String(value || "").toLowerCase(); }
}

function dedupeRepositories(items) {
  const map = new Map();
  for (const item of items) {
    const key = canonicalUrl(item.url || item.web_url || item.html_url);
    if (key && !map.has(key)) map.set(key, item);
  }
  return [...map.values()].sort((a, b) => canonicalUrl(a.url).localeCompare(canonicalUrl(b.url)));
}

function dedupeEmails(items) {
  const map = new Map();
  for (const item of items) {
    const value = typeof item === "string" ? item : item.email;
    const key = String(value || "").trim().toLowerCase();
    if (key && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(key) && !map.has(key)) map.set(key, typeof item === "string" ? key : { ...item, email: key });
  }
  return [...map.values()].sort((a, b) => String(a.email || a).localeCompare(String(b.email || b)));
}

function extractObservables(text) {
  const value = typeof text === "string" ? text : "";
  const emails = dedupeEmails(value.match(EMAIL_RE) || []);
  const urls = [...new Set((value.match(URL_RE) || []).map(x => x.replace(/[),.;]+$/, "")))].sort();
  const fileExtensions = new Set(["avif", "bmp", "css", "csv", "gif", "htm", "html", "ico", "jpeg", "jpg", "js", "json", "map", "md", "pdf", "php", "png", "svg", "txt", "webp", "woff", "woff2", "xml"]);
  const codeProperties = new Set(["assign", "entries", "forEach", "from", "includes", "keys", "map", "prototype", "querySelector", "replace", "values"]);
  const domains = new Set((value.match(HOST_RE) || []).map(x => x.toLowerCase()).filter(host => {
    const labels = host.split(".");
    const tld = labels.at(-1);
    return !fileExtensions.has(tld) && !(labels.length === 2 && codeProperties.has(tld));
  }));
  for (const url of urls) { try { domains.add(new URL(url).hostname.toLowerCase()); } catch {} }
  const ips = [...new Set((value.match(IP_RE) || []).filter(ip => net.isIP(ip) === 4))].sort();
  return { emails, urls, domains: [...domains].sort(), ips };
}

function inspectContent(text, context, collectedAt) {
  const indicators = [];
  const add = (severity, type, reason, evidence) => indicators.push({
    severity, type, reason, evidence: String(evidence).slice(0, 500), evidence_type: context.evidenceType || "file_content",
    source_url: context.sourceUrl, repository: context.repository, path: context.path || null, collected_at: collectedAt
  });
  const value = String(text || "");
  const forms = /<form\b[\s\S]{0,4000}?<\/form>/gi;
  for (const match of value.match(forms) || []) {
    const hasPassword = /type\s*=\s*["']?password/i.test(match);
    const action = match.match(/action\s*=\s*["']([^"']+)/i)?.[1] || null;
    if (hasPassword && action && /^https?:\/\//i.test(action)) add("medium", "external_credential_form", "A password form submits to an absolute external URL; manual review is required.", match.slice(0, 500));
    else if (hasPassword) add("low", "login_form", "A password input is present. This alone does not establish malicious intent.", match.slice(0, 500));
  }
  if (/\b(?:window\.)?location(?:\.href)?\s*=\s*["']https?:\/\//i.test(value)) add("low", "external_redirect", "Client-side code redirects to an absolute external URL.", value.match(/.{0,100}(?:window\.)?location.{0,250}/i)?.[0] || "redirect assignment");
  if (/(?:eval\s*\(|atob\s*\(|String\.fromCharCode\s*\().{0,300}(?:location|document|fetch|XMLHttpRequest)/is.test(value)) add("medium", "obfuscated_javascript", "Obfuscation-like JavaScript appears near browser or network operations.", value.match(/.{0,150}(?:eval|atob|fromCharCode).{0,300}/is)?.[0] || "obfuscated JavaScript");
  if (/<form\b[\s\S]{0,2500}?(?:login|sign[ -]?in|password|credential)/i.test(value) && /(?:fetch\s*\(|XMLHttpRequest|action\s*=)/i.test(value)) add("informational", "login_workflow", "Login-related form and submission logic are both present; context and authorization are unknown.", "login-related form with submission logic");
  const keyword = (context.keywords || []).find(term => term && value.toLowerCase().includes(term.toLowerCase()));
  if (keyword && /(?:login|sign[ -]?in|password|credential)/i.test(value)) add("informational", "keyword_login_reference", `Investigation keyword '${keyword}' appears with login-related content. This is not proof of impersonation or malicious intent.`, `keyword=${keyword}; login-related content present`);
  return indicators;
}

function addRelationshipIndicators(report) {
  const references = new Map();
  for (const repository of report.repositories) {
    for (const item of repository.observables?.urls || []) {
      if (!references.has(item.value)) references.set(item.value, []);
      references.get(item.value).push({ repository: repository.full_name, source_url: item.source_url, path: item.path });
    }
  }
  for (const [url, evidence] of references) {
    const repositories = [...new Set(evidence.map(x => x.repository))];
    if (repositories.length < 2) continue;
    report.indicators.push({ severity: "informational", type: "shared_url_reference", reason: "The same URL is referenced by multiple repositories. Shared references can be benign and do not establish common ownership.", evidence: JSON.stringify({ referenced_url: url, repositories, sources: evidence }).slice(0, 2000), evidence_type: "cross_repository_correlation", source_url: evidence[0].source_url, repository: repositories.join(", "), path: evidence[0].path || null, collected_at: report.collected_at });
  }
}

function baseReport(platform, query, collectedAt = new Date().toISOString()) {
  return { platform, query, collected_at: collectedAt, capabilities: null, users: [], repositories: [], emails: [], domains: [], indicators: [], errors: [], partial: false };
}

module.exports = { usage, normalizeDomain, validateUsername, validateRepository, parseCli, sanitizeSegment, dateFolder, outputDirectory, atomicWrite, canonicalUrl, dedupeRepositories, dedupeEmails, extractObservables, inspectContent, addRelationshipIndicators, baseReport };
