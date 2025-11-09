# PENDING - Critical Issues Requiring Resolution

**Purpose:** Track identified problems that MUST be addressed before related work can proceed.

**Difference from TBD.md:**
- **TBD.md** = Open architectural questions without clear answers yet
- **PENDING.md** = Identified work with known scope, just deferred for prioritization

---

## Priority Levels

- **🔴 P0 (Critical):** Blocks all work, must resolve immediately
- **🟡 P1 (High):** Blocks significant work, resolve this sprint
- **🟢 P2 (Medium):** Important but not blocking, resolve soon
- **⚪ P3 (Low):** Nice to have, address when convenient

---

## Active Items

### 🔴 P0 - CRITICAL (Blocking)

#### [PENDING-001](docs/pending/001-configuration-security-strategy.md) - Configuration & Secrets Management Strategy
**Status:** 🔴 Open
**Created:** 2025-11-09
**Blocks:** All service implementation
**Summary:** No defined strategy for config placement (global vs local), secrets protection (FINA certs, passwords), environment separation (dev/staging/prod).

**Key Decisions Required:**
- Secrets management tool (HashiCorp Vault recommended)
- Configuration hierarchy (platform/service/environment levels)
- Directory structure for configs
- FINA certificate storage approach
- .gitignore protection against committed secrets

**Estimated Effort:** 2-4 days (ADRs + implementation + Vault setup)

**Why Deferred Now:** Establishing SSOT foundation was more pressing (no point configuring services before we know how to specify them properly).

---

## Completed Items

_None yet_

---

## Process Guidelines

### When to Create a PENDING Item

**Create when:**
- ✅ Critical architectural gap identified
- ✅ Scope is clear (you know what needs deciding/building)
- ✅ Blocks or significantly impacts other work
- ✅ Can't/shouldn't address immediately due to higher priority

**Don't create when:**
- ❌ Simple bug (create GitHub issue or fix immediately)
- ❌ Vague concern without clear scope (discuss first, then create if needed)
- ❌ Already covered in TBD.md (use existing structure)

### Workflow

1. **Identify Issue**
   - During architecture review, code review, or development
   - Recognize it blocks or risks other work

2. **Capture Details**
   - Create `docs/pending/{number}-{slug}.md`
   - Number sequentially (001, 002, etc.)
   - Include: problem statement, scope, decisions required, blockers, deliverables

3. **Add to PENDING.md**
   - List in appropriate priority section
   - Link to detailed file
   - Note what it blocks

4. **Resolve**
   - Complete deliverables (ADRs, code, docs)
   - Move from "Active Items" to "Completed Items"
   - Update related documents (CLAUDE.md, TBD.md)

5. **Reference**
   - Git commit messages: `fix(pending-001): implement Vault configuration strategy`
   - ADRs: `See PENDING-001 for background`

### Priority Triage

**Review PENDING.md weekly:**
- Are P0s still blocking? (Should be resolved ASAP)
- Can P1s be promoted to P0? (If blocking work increases)
- Can P2/P3 be closed? (If no longer relevant)

### Integration with TBD.md

**TBD.md** = Questions without answers
**PENDING.md** = Work with known scope

**Example:**
- TBD.md: "Should we use GraphQL or REST for query API?"
- PENDING.md: "Implement API gateway with chosen protocol (REST decided)"

**Flow:**
```
TBD Question → Decision Made → PENDING Implementation → Completed → Closed
```

---

## References

- **TBD.md** - Open architectural decisions
- **docs/adr/** - Architectural Decision Records (outcomes)
- **docs/pending/** - Detailed pending item specifications

---

**Maintainer:** Technical Lead
**Last Updated:** 2025-11-09
**Review Cadence:** Weekly (during planning)
