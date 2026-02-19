# Contributing to VulnInventory

Thank you for your interest! Here's how to get started.

## Quick Start

1. Fork the repo
2. Clone: `git clone https://github.com/CrisorHacker/vulninventory.git`
3. Create branch: `git checkout -b feature/my-feature`
4. Make changes
5. Test: `cd api && pytest`
6. Push and open a Pull Request

## Commit Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add PDF export
fix: correct CVSS calculation
docs: update API reference
style: format with black
refactor: extract auth module
test: add finding creation tests
chore: update dependencies
```

## Code Style

**Backend:** `black` formatter, `ruff` linter, type hints encouraged
**Frontend:** `prettier` formatter, `eslint` linter, functional React components

## Areas We Need Help With

- 🌐 i18n / English UI translation
- 📊 PDF report generation
- 🔌 Scan tool adapters (Nmap, OpenVAS, Trivy)
- 🧪 Test coverage
- 📱 Mobile responsive
- ♿ Accessibility (a11y)

## Code of Conduct

Be respectful. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
