# Skillforge Naming Conventions

This document defines the naming standards for all components in this plugin. Follow these conventions when creating new skills, commands, agents, or hooks.

The goal of this scheme is:
- Predictable discovery (you can guess names before searching)
- Honest classification (no forcing everything into a “platform” bucket)
- Long-term scalability as Skillforge grows beyond infra-only tooling


## Skills

**Pattern:**  
`{domain}-{category}-{topic}[-{qualifier}]`

**Format Rules:**
- All lowercase
- Hyphen-separated (kebab-case)
- Prefer singular nouns
- Optional qualifier only when it adds clarity (vendor, language, scope)

---

### Domains

| Prefix  | Description                                                                   |
| ------- | ----------------------------------------------------------------------------- |
| `win`   | Windows / PowerShell                                                          |
| `linux` | Linux / Bash                                                                  |
| `aws`   | Amazon Web Services                                                           |
| `azure` | Microsoft Azure                                                               |
| `m365`  | Microsoft 365                                                                 |
| `git`   | Git *tooling itself* (rebase, hooks, config, bisect)                          |
| `dev`   | Software development workflows (commits, PRs, releases, standards)            |
| `ci`    | CI/CD pipelines, runners, build/test workflows                                |
| `repo`  | Repository hygiene and structure (templates, policies, ownership)             |
| `pkg`   | Dependency and package management (npm, pip, nuget, renovate-style workflows) |

**Rule of thumb:**  
If it’s about how developers work, it’s probably `dev-`, not `git-`.

---

### Categories

#### Infrastructure / Platform Categories

| Category     | Description                                  |
| ------------ | -------------------------------------------- |
| `monitoring` | Health checks, logs, performance, alerts     |
| `admin`      | Management tasks, configuration, maintenance |
| `security`   | Auditing, permissions, hardening             |
| `network`    | Connectivity, firewall, DNS                  |
| `automation` | Scripts, scheduled tasks, workflows          |

#### Development / Workflow Categories

| Category    | Description                                    |
| ----------- | ---------------------------------------------- |
| `standards` | Conventions, linting rules, naming, formatting |
| `quality`   | Tests, coverage, static analysis               |
| `review`    | PR analysis, summaries, risk flags             |
| `release`   | Versioning, changelogs, tagging                |
| `deps`      | Dependency updates and remediation             |
| `docs`      | Documentation generation and maintenance       |
| `scaffold`  | Project or repository bootstrapping            |

---

### Topic & Qualifier Rules

- **Topic** should be concise and specific (for example: `eventlogs`, `ec2`, `conventionalcommits`)
- Avoid filler words such as `tool`, `helper`, `manager`
- **Qualifier** is optional and used only when necessary:
  - Vendor: `ado`, `gh`, `gl`
  - Language/ecosystem: `dotnet`, `python`, `node`, `powershell`
  - Scope: `repo`, `org`, `project`

---

### Skill Examples

#### Platform-Oriented Skills

| Description                  | Skill Name                      |
| ---------------------------- | ------------------------------- |
| Windows Event Logs           | `win-monitoring-eventlogs`      |
| Windows Performance Counters | `win-monitoring-performance`    |
| Windows Services             | `win-admin-services`            |
| Windows Disk Management      | `win-admin-disks`               |
| Windows Scheduled Tasks      | `win-automation-scheduledtasks` |
| Windows Firewall             | `win-network-firewall`          |
| Linux Log Analysis           | `linux-monitoring-logs`         |
| Azure VM Management          | `azure-admin-vms`               |
| AWS EC2 Instances            | `aws-admin-ec2`                 |

#### Development & Workflow Skills

| Description                         | Skill Name                              |
| ----------------------------------- | --------------------------------------- |
| Conventional Commits validation     | `dev-standards-conventionalcommits`     |
| Conventional Commits (Azure DevOps) | `dev-standards-conventionalcommits-ado` |
| Semantic versioning from commits    | `dev-release-semver`                    |
| Changelog generation                | `dev-release-changelog`                 |
| PR summary generation               | `dev-review-prsummary`                  |
| Repo bootstrap templates            | `repo-scaffold-bootstrap`               |
| Dependency upgrade assistant        | `pkg-deps-upgrades`                     |
| Git hook installer                  | `git-automation-hooks`                  |

---

## Commands

Commands represent **direct user actions**.

**Pattern:**  
`{domain}-{action}-{target}`

**Format Rules:**
- All lowercase
- Hyphen-separated
- Verb-first action where possible
- This is the canonical form (short aliases may exist but are optional)

---

### Command Examples

| Description                     | Command                            |
| ------------------------------- | ---------------------------------- |
| Windows health check            | `win-check-health`                 |
| AWS IAM audit                   | `aws-audit-iam`                    |
| Disk usage report               | `win-report-disk`                  |
| Service status                  | `win-check-service`                |
| Conventional commits validation | `dev-validate-conventionalcommits` |
| Pipeline lint                   | `ci-check-pipeline`                |
| Repo template initialization    | `repo-init-templates`              |

---

## Agents

Agents represent **roles or personas** with ongoing responsibility.

**Pattern:**  
`{role}[-{domain-or-specialization}]`

**Format Rules:**
- All lowercase
- Hyphen-separated

---

### Agent Examples

| Description            | Agent                  |
| ---------------------- | ---------------------- |
| General troubleshooter | `troubleshooter`       |
| Windows troubleshooter | `troubleshooter-win`   |
| Capacity planner       | `capacity-planner`     |
| Security auditor (AWS) | `security-auditor-aws` |
| Release manager        | `release-manager-dev`  |
| CI pipeline specialist | `pipeline-sheriff-ci`  |

---

## Hooks

Hooks represent **lifecycle-driven automation**.

**Pattern:**  
`{lifecycle}-{scope}-{action}`

**Lifecycle Prefixes:** `pre`, `post`, `on`

**Format Rules:**
- All lowercase
- Hyphen-separated

---

### Hook Examples

| Description              | Hook                  |
| ------------------------ | --------------------- |
| Pre-commit validation    | `pre-commit-validate` |
| Pre-push linting         | `pre-push-lint`       |
| On pull request labeling | `on-pr-label`         |
| Post-tool logging        | `post-tool-log`       |

---

## Directory Structure (Option A)

Components are organized directly by name:

```
skills/
├── win-monitoring-eventlogs/
│   └── SKILL.md
├── dev-standards-conventionalcommits/
│   └── SKILL.md
├── aws-security-iam/
│   └── SKILL.md

commands/
├── win-check-health.md
├── dev-validate-conventionalcommits.md
└── repo-init-templates.md

agents/
├── troubleshooter.md
├── release-manager-dev.md
└── pipeline-sheriff-ci.md
```
