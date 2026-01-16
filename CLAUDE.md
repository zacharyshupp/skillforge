# Skillforge - Claude Code Plugin

This repository contains Claude Code skills, commands, agents, and hooks for Windows system administration and related tasks.

## Naming Conventions

**IMPORTANT:** Before creating any new component, read and follow the naming conventions in [docs/CONVENTIONS.md](docs/CONVENTIONS.md).

Quick reference:

- **Skills:** `{platform}-{category}-{topic}` (e.g., `win-monitoring-eventlogs`)
- **Commands:** `{action}-{target}` (e.g., `health-check`)
- **Agents:** `{role}` (e.g., `troubleshooter`)
- **Hooks:** `{event}-{action}` (e.g., `precommit-validate`)

## Project Structure

```text
skillforge/
├── .claude-plugin/plugin.json   # Plugin manifest
├── skills/                      # Knowledge modules (auto-invoked)
├── commands/                    # Slash commands (user-invoked)
├── agents/                      # Specialized sub-agents
├── hooks/                       # Event hooks
├── docs/                        # Documentation
│   └── CONVENTIONS.md           # Naming standards (read first!)
├── CHANGELOG.md                 # Version history
└── README.md                    # User documentation
```

## Creating Components

### Skills

1. Create folder: `skills/{platform}-{category}-{topic}/`
2. Add `SKILL.md` with YAML frontmatter containing `name` and `description`
3. Include practical examples and reference material

### Commands

1. Create file: `commands/{action}-{target}.md`
2. Add YAML frontmatter with `description`
3. Use `$ARGUMENTS` for user input

### Agents

1. Create file: `agents/{role}.md`
2. Add YAML frontmatter with `description` and `capabilities`
3. Define clear scope and when the agent should be used
