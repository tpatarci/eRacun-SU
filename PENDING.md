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

### 🟢 [PENDING-002](docs/pending/002-test-execution-verification.md) - Test Execution Verification (xsd-validator)

**Priority:** 🟢 P2 (Medium)
**Created:** 2025-11-11
**Estimated Effort:** 30 minutes

**Problem:** Test suite written (65+ tests) but not executed to verify all pass and 85% coverage threshold met.

**Blocks:**
- Staging deployment (xsd-validator)
- Production deployment (xsd-validator)

**Does NOT Block:**
- Implementing other services (can proceed in parallel)

**Next Action:** Run `npm install && npm run test:coverage` in `services/xsd-validator/` before staging deployment

**Deferred Because:** User prioritized "Continue building" over immediate verification

---

### ⚪ [PENDING-003] - Service Documentation Gap (pdf-parser, file-classifier)

**Priority:** ⚪ P3 (Low)
**Created:** 2025-11-12
**Estimated Effort:** 2 hours

**Problem:** pdf-parser and file-classifier services lack README.md files documenting purpose, API contracts, dependencies, and operational characteristics.

**Blocks:**
- Onboarding new developers to these services
- Operational runbooks (understanding failure modes)

**Does NOT Block:**
- Production deployment (services are functional)
- Other service development

**Deliverables Required:**
- [ ] `services/pdf-parser/README.md` with standard service documentation
- [ ] `services/file-classifier/README.md` with standard service documentation
- [ ] Document API contracts (HTTP endpoints, message formats)
- [ ] Document failure modes and recovery procedures

**Next Action:** Create README.md files following template in CLAUDE.md section 2.2

**Deferred Because:** P1 service implementations prioritized (attachment-handler, ubl-transformer)

**Note:** Identified in Team B verification report (2025-11-12-team-b-verification.md)

---

## Completed Items

### ✅ [PENDING-001](docs/pending/001-configuration-security-strategy.md) - Configuration & Secrets Management Strategy

**Status:** ✅ Completed
**Created:** 2025-11-09
**Resolved:** 2025-11-09
**Implementation Time:** ~8 hours (1 day)

**Problem:** No defined strategy for configuration management and secrets protection on DigitalOcean droplets.

**Solution Implemented:**
- **Secrets Management:** SOPS + age encryption (Mozilla open source, €0 cost)
- **Configuration Strategy:** Filesystem-based `/etc/eracun/` hierarchy (ADR-001)
- **Deployment:** systemd service orchestration with Unix conventions

**Deliverables Completed:**
- ✅ ADR-001: Configuration Management Strategy (filesystem-based)
- ✅ ADR-002: Secrets Management with SOPS + age
- ✅ Directory structure: `config/`, `secrets/`, `deployment/systemd/`
- ✅ systemd service template + decrypt-secrets.sh script
- ✅ Configuration templates (.conf.example files)
- ✅ .gitignore with comprehensive secret protection
- ✅ Operational documentation (deployment/systemd/README.md)
- ✅ Updated CLAUDE.md sections 2.1, 3.4, 6.1, 6.2

**Git Commits:**
- `86fa9ad` - feat(config): implement Unix/systemd configuration and secrets management
- `85c70bc` - chore(gitignore): add comprehensive secret protection rules
- `89b9424` - docs(claude): update deployment architecture to Unix/systemd

**Outcome:** Service development can now proceed with secure configuration and secrets management infrastructure.

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
**Last Updated:** 2025-11-12 (PENDING-003 added: service documentation gap)
**Review Cadence:** Weekly (during planning)
