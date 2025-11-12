# Development Workflow

## Git Branching Strategy

**Trunk-Based Development:**
- `main` branch always deployable
- Feature branches max 2 days lifespan
- CI/CD on every commit to `main`

**Branch Naming:**
```
feature/<service-name>/<short-description>
fix/<service-name>/<issue-number>
refactor/<service-name>/<improvement>
```

---

## Commit Standards

**Conventional Commits:**
```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:** `feat`, `fix`, `refactor`, `perf`, `test`, `docs`, `chore`
**Scope:** Service name (e.g., `email-worker`, `schema-validator`)

---

## CI/CD Pipeline

**On Every Commit:**
1. Lint (ESLint, Prettier)
2. Type check (TypeScript strict mode)
3. Unit tests (Jest)
4. Security scan (Snyk, Trivy)
5. Build Docker images
6. Push to registry (only on `main`)

**On Merge to Main:**
7. Integration tests (Testcontainers)
8. Deploy to staging
9. E2E smoke tests
10. Deploy to production (manual approval gate)

---

## PENDING Tracking (MANDATORY)

**⚠️ CONSTITUTIONAL MANDATE:** All identified critical gaps MUST be tracked in `PENDING.md`

**Purpose:** Prevent critical work from being forgotten when deferred for higher priorities.

### When to Create PENDING Item
- ✅ Critical architectural gap identified (blocks or risks significant work)
- ✅ Scope is clear (known what needs deciding/building)
- ✅ Can't address immediately due to higher priority work
- ❌ Simple bugs (use GitHub issues or fix immediately)
- ❌ Vague concerns without clear scope (discuss first)

### Workflow (NON-NEGOTIABLE)

1. **Identify Gap**
   - During architecture review, development, or design
   - Recognize it blocks or creates risk for other work

2. **Create Detailed Specification**
   - File: `docs/pending/{number}-{slug}.md`
   - Number sequentially (001, 002, 003...)
   - Must include:
     - Problem statement (what's missing/wrong)
     - Scope (what needs deciding/building)
     - Open questions requiring decisions
     - Deliverables required to close
     - What it blocks
     - Why deferred (what was higher priority)
     - Estimated effort

3. **Track in PENDING.md**
   - Add to appropriate priority section
   - Link to detailed file
   - Note blockers and dependencies

4. **Resolve When Priority Allows**
   - Complete deliverables (ADRs, implementation, docs)
   - Update related documents (CLAUDE.md, TBD.md)
   - Move from "Active Items" to "Completed Items"

### Priority Levels (P0-P3)
- **🔴 P0 (Critical):** Blocks all work, resolve immediately
- **🟡 P1 (High):** Blocks significant work, resolve this sprint
- **🟢 P2 (Medium):** Important but not blocking, resolve soon
- **⚪ P3 (Low):** Nice to have, address when convenient

### PENDING.md vs TBD.md
- **TBD.md** = Questions without answers (architectural exploration)
- **PENDING.md** = Work with known scope (implementation deferred)

### Review Cadence
Weekly triage required:
- Re-prioritize as work evolves
- Promote P1→P0 if blocking increases
- Close P2/P3 if no longer relevant

---

## Completion Reports (MANDATORY)

**Purpose:** Traceability, forensic analysis, audit trail, knowledge transfer

**Location:** `docs/reports/`

### When to Write Completion Reports
- ✅ After completing TODO items (especially Priority 1 items)
- ✅ After completing PENDING items
- ✅ After implementing bounded contexts or services
- ✅ After deploying to staging or production
- ✅ After investigating major incidents or bugs
- ❌ For trivial changes (typo fixes, minor refactors)

### File Naming Convention
```
YYYY-MM-DD-{task-id}-{short-description}.md
```

**Examples:**
- `2025-11-10-TODO-006-completion.md`
- `2025-12-05-xsd-validator-implementation.md`
- `2026-01-01-production-launch.md`

### Required Sections
1. **Executive Summary** - Brief overview (2-3 sentences)
2. **What Was Delivered** - Detailed breakdown with code examples
3. **Git Status** - Commit hash, branch, files changed
4. **Traceability** - Previous work, task duration, quality metrics
5. **Next Steps** - Suggested follow-up work (if applicable)

### Integration with Other Documentation
- **ADRs** (`/docs/adr/`) - Architectural **decisions** (why we chose X over Y)
- **PENDING** (`/docs/pending/`) - **Deferred work** (what needs doing later)
- **TODO.md** - **Active work** (what we're doing now)
- **CHANGELOG.md** - **User-facing changes** (releases)
- **Reports** (`/docs/reports/`) - **Completed work** (what we did and how)

---

**Last Updated:** 2025-11-12
**Document Owner:** Engineering Lead
**Review Cadence:** Monthly
