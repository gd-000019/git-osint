# GitHub/GitLab Public OSINT CLI

Static, API-based collection of public repository, user, commit-email, domain, URL, IP, and phishing-related evidence. Requires Node.js 20.6 or newer. No third-party packages are required.

## Installation

Copy the project files and verify Node.js with `node --version`. There are no runtime packages to install; `npm test` uses Node's built-in test runner.

## Configuration

Create `.env` as needed:

```dotenv
GITHUB_TOKEN=optional_public_api_token
GITLAB_TOKEN=optional_public_api_token
GITLAB_URL=https://gitlab.com
```

Tokens increase rate limits and enable search capabilities permitted by the platform. They are never written to reports. Unauthenticated public queries are supported where the API permits them.
The CLI automatically loads the project `.env`; existing shell environment variables take precedence.

## Commands

```bash
node github-osint.js domain example.com example
node gitlab-osint.js domain example.com example
node github-osint.js user username
node gitlab-osint.js user username
node github-osint.js repository owner/repository
node gitlab-osint.js repository owner/repository

# Options
node github-osint.js domain example.com --folder ./results --limit 10 --json
node github-osint.js domain example.com example --include-all
node github-osint.js domain example.com example --include-bots
node github-osint.js --help
```

## Parameters

### Commands

- `domain <domain> [keyword]`: searches for a domain and an optional related word.
  - Example: `domain example.com example`
- `user <username>`: investigates a public user account.
- `repository <owner/name>`: investigates one public repository.

### Options

- `--folder <path>`: changes the output root. Default: `OUTPUT`.
- `--limit <number>`: limits results per search category. Allowed: `1` to `100`. Default: `20`.
- `--json`: prints the full intelligence report as JSON to stdout.
- `--include-all`: includes weak and keyword-only repositories in `results.json`.
- `--include-bots`: includes bot and `noreply` email addresses in `results.json`.
- `--help`: displays command help.

`--include-all` and `--include-bots` apply only to GitHub domain investigations.

`github-user-osint.js USERNAME` and `github-repository-osint.js DOMAIN [KEYWORD]` remain compatibility entry points.

## Output

The default root is `OUTPUT/DD-MM-YYYY/`; `--folder` replaces `OUTPUT`. Targets are isolated and sanitized.

```text
OUTPUT/DD-MM-YYYY/
├── github/
│   ├── domains/example.com/{domain-intel.json,repositories-intel.json,search.txt,results.json}
│   ├── users/username/{user-intel.json,user-intel.txt,unique-emails.txt}
│   └── repositories/owner__repository/repository-intel.json
└── gitlab/
    ├── domains/example.com/{gitlab-search.txt,gitlab-emails.txt,gitlab-intel.json}
    ├── users/username/{user-intel.json,unique-emails.txt}
    └── repositories/owner__repository/repository-intel.json
```

GitHub domain investigations produce exactly four files:

- `domain-intel.json`: unchanged full intelligence report.
- `repositories-intel.json`: repository intelligence array.
- `search.txt`: human-readable report.
- `results.json`: primary parse-friendly repository/email pairs.

By default, `results.json` includes only exact-domain repositories and excludes bot/noreply addresses. Use `--include-all` for weak keyword-only repositories and `--include-bots` for bot/noreply addresses. Files are written atomically and rows are deterministically sorted.

## Intelligence schema

Every primary JSON report includes `platform`, `query`, `collected_at`, `users`, `repositories`, `emails`, `domains`, `indicators`, `errors`, and `partial`. Repository records retain matches, commits, and source-linked observables. Indicators include severity, reason, evidence type, source URL, repository, path, and collection time.

Indicator levels are `informational`, `low`, `medium`, and `high`. Static signals are review leads only; a brand name, login form, keyword, or domain never establishes maliciousness or ownership by itself.

## Limitations and permissions

- Only public data exposed by official GitHub/GitLab APIs is queried.
- GitHub code search generally requires `GITHUB_TOKEN`; GitLab global blob search depends on token permissions and instance configuration.
- If `.env` is absent and no token exists in the shell environment, the CLI prints an unauthenticated-mode warning and code-search results may be incomplete.
- Results are bounded by `--limit`, API pagination, indexing, rate limits, and repository-tree limits. Gaps are recorded in `errors` with `partial: true`.
- Commit names and emails are user-configured metadata, not verified identities. Matching usernames across platforms are not identity proof.
- Repository files are read as text for static inspection only. Repository code is never executed, and extracted URLs are never requested.

## Tests

```bash
npm test
```

Tests use mocked API clients and do not make external requests.
