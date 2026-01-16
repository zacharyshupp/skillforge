# Skillforge

A curated collection of Claude Code skills, built to extend Claude with reusable, composable, and production-minded capabilities.

## Installation

Install this plugin via the Claude Code marketplace:

```bash
/install skillforge@zacharyshupp
```

Or install directly from GitHub:

```bash
/install https://github.com/zacharyshupp/skillforge
```

## Components

### Skills

Skills are specialized knowledge modules that Claude can invoke autonomously based on task context.

| Skill | Description |
|-------|-------------|
| *Coming soon* | |

### Commands

Slash commands for quick actions.

| Command | Description |
|---------|-------------|
| *Coming soon* | |

### Agents

Specialized agents for complex tasks.

| Agent | Description |
|-------|-------------|
| *Coming soon* | |

## Development

### Project Structure

```text
skillforge/
├── .claude-plugin/
│   └── plugin.json      # Plugin manifest
├── commands/            # Slash commands
├── agents/              # Specialized agents
├── skills/              # Knowledge modules
├── hooks/               # Event hooks
├── docs/                # Documentation
│   └── CONVENTIONS.md   # Naming standards
├── marketplace.json     # Marketplace distribution config
├── LICENSE
├── CHANGELOG.md
└── README.md
```

### Adding New Components

**Skills**: Create a new directory under `skills/` with a `SKILL.md` file.

**Commands**: Add a markdown file to `commands/` with YAML frontmatter.

**Agents**: Add a markdown file to `agents/` with YAML frontmatter.

**Hooks**: Configure in `hooks/hooks.json`.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

[Zachary Shupp](https://github.com/zacharyshupp)
