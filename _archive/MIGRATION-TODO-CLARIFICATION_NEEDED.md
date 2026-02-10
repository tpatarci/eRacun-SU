# MIGRATION-TODO.md - Clarifications Needed Before Execution

**Date:** 2025-11-16
**Status:** ⚠️ AWAITING CLARIFICATION
**Reviewed By:** Claude Code
**Source Task List:** `MIGRATION-TODO.md`

---

## ✅ **Task List Reviewed - Need Clarifications Before Starting**

I've carefully reviewed the **MIGRATION-TODO.md** file. It's a comprehensive, well-structured sequential task list covering all remaining migration work. However, I need to clarify several important points before I begin executing:

---

## 🤔 **Critical Questions:**

### 1. **Repository Structure**
The task list references domain-specific repositories:
- `~/repos/eracun-validation`
- `~/repos/eracun-ingestion`
- `~/repos/eracun-integration`
- `~/repos/eracun-transformation`
- etc.

**But we've been using:** `/tmp/eracun-infrastructure-pilot` (single pilot repository)

**Question:** Should I:
- A) **Create separate domain repositories** as outlined in the tasks?
- B) **Continue using the pilot repository** (`eracun-infrastructure-pilot`)?
- C) **Transition from pilot to domain-specific repos** now?

**Decision:** ___________

---

### 2. **Mock Repository**
Tasks reference: `git clone git@github.com:eracun/eracun-mocks.git`

**Status:** This repository doesn't exist yet. We only have mock strategy documents.

**Question:** Should I:
- A) **Create the mock repository first** with working implementations?
- B) **Skip mock setup** and proceed with service extraction?
- C) **Use mock strategy documents** as reference only?

**Decision:** ___________

---

### 3. **Execution Approach**
The task list has detailed checkboxes for manual tracking.

**Question:** Should I:
- A) **Execute tasks sequentially** (one by one, checking them off)?
- B) **Work autonomously** through multiple tasks at once?
- C) **Wait for specific direction** on which task to start?
- D) **Ask permission** before each phase?

**Decision:** ___________

---

### 4. **Service Count Discrepancy**
- **MIGRATION-TODO.md** says: "12/31 services complete (39%)"
- **MIGRATION-STATUS.md** (just created) says: "12/29 services (42%)"

**Question:** Which count is correct? Are there 29 or 31 total services?

**Actual Count:** ___________

---

### 5. **Target Directories**
Tasks use: `~/repos/eracun-*/SERVICE_NAME`

**Current working location:** `/home/tomislav/PycharmProjects/eRačun` (monorepo)

**Question:** Should I:
- A) **Create ~/repos/** directory structure?
- B) **Use existing pilot location** (`/tmp/eracun-infrastructure-pilot`)?
- C) **Use a different location** you specify?

**Decision:** ___________

---

### 6. **Immediate Start Point**
The file indicates: **"Next Service: data-extractor"**

**Question:** Should I:
- A) **Start with Prerequisites & Setup** (Phase 1 - mock repository)?
- B) **Skip to data-extractor extraction** (assuming prerequisites done)?
- C) **Wait for your direction** on where to begin?

**Decision:** ___________

---

## 📋 **What I Understand:**

✅ **Clear aspects:**
- Sequential extraction approach (good!)
- Time estimates per service
- Copy-first strategy for shared packages
- Mock usage for external dependencies
- "Good enough" > perfection philosophy
- Daily progress tracking expected

❌ **Need clarification on:**
- Repository structure (single vs multi-repo)
- Mock repository setup requirements
- Execution autonomy level
- Service count accuracy
- Directory locations

---

## 🎯 **My Recommendation:**

If you want me to proceed immediately, I suggest:

1. **Clarify repository structure** (most critical)
2. **Start with data-extractor** (quick win, no dependencies)
3. **Use pilot repository** until multi-repo structure is confirmed
4. **Skip mock setup** initially (use strategy documents as reference)

**Would you like me to proceed with these assumptions, or should we clarify the points above first?**

---

## 📝 **Decision Template**

Please fill in your decisions below and I'll proceed accordingly:

```markdown
### DECISIONS:

1. Repository Structure: [A/B/C] _______
   Notes: _______

2. Mock Repository: [A/B/C] _______
   Notes: _______

3. Execution Approach: [A/B/C/D] _______
   Notes: _______

4. Service Count: [29/31/Other] _______
   Notes: _______

5. Target Directories: [A/B/C] _______
   Path: _______

6. Start Point: [A/B/C] _______
   Notes: _______

### ADDITIONAL INSTRUCTIONS:
_______
```

---

**Status:** Awaiting decisions before execution
**Ready to proceed:** Once clarifications provided
**Estimated time to first extraction:** 15-30 minutes after decisions
