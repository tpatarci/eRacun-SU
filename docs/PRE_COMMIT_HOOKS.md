# Pre-Commit Hooks

Automated code quality checks that run before every commit.

## Overview

Pre-commit hooks prevent common mistakes and ensure code quality standards:

- ✅ Prevent committing secrets (.env files, certificates, private keys)
- ✅ Enforce TypeScript/ESLint standards
- ✅ Validate YAML, JSON, and Markdown files
- ✅ Check service size limits (2,500 LOC max)
- ✅ Verify architecture compliance
- ✅ Detect merge conflicts and large files
- ✅ Lint shell scripts and Dockerfiles

## Installation

### Quick Setup
```bash
./scripts/setup-pre-commit-hooks.sh
```

### Manual Setup
```bash
# Install pre-commit
pip3 install pre-commit

# Install hooks
pre-commit install

# Initialize secrets baseline
detect-secrets scan > .secrets.baseline
```

## Usage

### Automatic (Default)
Hooks run automatically on `git commit`:
```bash
git add .
git commit -m "feat: add new feature"
# ↑ Hooks run here automatically
```

### Manual Execution
```bash
# Run all hooks on all files
pre-commit run --all-files

# Run all hooks on staged files
pre-commit run

# Run specific hook
pre-commit run trailing-whitespace
pre-commit run eslint
pre-commit run check-secrets-not-committed
```

### Bypass Hooks (Use Sparingly)
```bash
# Skip hooks for emergency commits only
git commit --no-verify -m "hotfix: critical bug"
```

## Hooks Included

### File Quality Checks
- **trailing-whitespace** - Remove trailing whitespace
- **end-of-file-fixer** - Ensure files end with newline
- **check-yaml** - Validate YAML syntax
- **check-json** - Validate JSON syntax
- **check-merge-conflict** - Detect merge conflict markers
- **mixed-line-ending** - Enforce LF line endings

### Security Checks
- **detect-secrets** - Prevent committing secrets
- **detect-private-key** - Detect private keys
- **check-secrets-not-committed** - Block .env, .p12, .key, .pem files
- **check-added-large-files** - Block files >1MB

### Code Quality
- **eslint** - TypeScript/JavaScript linting (auto-fix enabled)
- **typescript-check** - TypeScript type checking
- **shellcheck** - Shell script linting
- **hadolint-docker** - Dockerfile linting
- **yamllint** - YAML formatting
- **markdownlint** - Markdown formatting

### eRacun-Specific Checks
- **check-env-example** - Ensure .env.example exists in all services
- **check-architecture-compliance** - Verify no direct HTTP calls between services
- **check-service-size** - Enforce 2,500 LOC limit per service
- **no-commit-to-branch** - Prevent direct commits to main/master

## Common Issues

### Hook Fails with "command not found"
```bash
# Install missing dependency
pip3 install <package-name>

# Or reinstall all hooks
pre-commit clean
pre-commit install
pre-commit run --all-files
```

### ESLint Errors
```bash
# Auto-fix most issues
npm run lint:fix

# Or let pre-commit auto-fix
git commit  # ESLint will auto-fix and re-stage
```

### Secrets Detection False Positive
```bash
# Add to .secrets.baseline
detect-secrets scan --baseline .secrets.baseline

# Then commit the updated baseline
git add .secrets.baseline
git commit -m "chore: update secrets baseline"
```

### Service Size Limit Exceeded
```bash
# Check service size
find services/my-service/src -name "*.ts" | xargs wc -l

# If >2,500 LOC, split service into smaller bounded contexts
# See docs/ARCHITECTURE.md for guidance
```

## Updating Hooks

```bash
# Update to latest versions
pre-commit autoupdate

# Test updated hooks
pre-commit run --all-files
```

## Disabling Specific Hooks

Edit `.pre-commit-config.yaml` and comment out unwanted hooks:

```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      # - id: check-yaml  # Disabled
      - id: check-json    # Active
```

## CI/CD Integration

Pre-commit hooks also run in CI/CD:

```yaml
# .github/workflows/pre-commit.yml
- name: Run pre-commit
  run: pre-commit run --all-files
```

## Best Practices

1. **Commit Early, Commit Often** - Hooks prevent bad commits
2. **Fix Auto-Fixable Issues** - ESLint, Prettier auto-fix most problems
3. **Don't Bypass Hooks** - Use `--no-verify` only for emergencies
4. **Update Regularly** - Run `pre-commit autoupdate` monthly
5. **Add New Hooks** - Suggest improvements to `.pre-commit-config.yaml`

## Troubleshooting

### Hooks Running Slowly
```bash
# Skip expensive hooks during development
SKIP=typescript-check,eslint git commit -m "WIP"

# Re-enable for final commit
git commit --amend --no-edit
```

### Clean Reinstall
```bash
# Remove all hooks
pre-commit uninstall

# Clean cache
pre-commit clean

# Reinstall
pre-commit install
pre-commit run --all-files
```

## Related Documentation

- **Code Standards:** @docs/DEVELOPMENT_STANDARDS.md
- **Architecture Compliance:** @docs/ARCHITECTURE.md
- **Security Standards:** @docs/SECURITY.md
- **Git Workflow:** @docs/WORKFLOW.md

---

**Last Updated:** 2025-11-14
**Maintainer:** DevOps Team
