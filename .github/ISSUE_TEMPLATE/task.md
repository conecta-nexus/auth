---
name: Engineering Task
about: Granular engineering task decomposing a parent User Story (models, logic, endpoints, database, security)
title: '[<SERVICE>-TASK] <Short Description in English>'
labels: ['task']
assignees: ''
---

### 1. Task Metadata & Traceability
- **Module / Microservice:** `<service-name>` (e.g. `auth` | `profile` | `challenge` | `application` | `moderation` | `notification`)
- **Parent User Story:** Closes part of conecta-nexus/<repo>#<issue-number>
- **Assigned Developer:** @<username>
- **Sprint:** Sprint 1 | Sprint 2 | Sprint 3

---

### 2. Objective & Description
<!-- Provide a clear, actionable summary of what needs to be implemented and why -->

---

### 3. Technical Specifications & Constraints
- **Database / Schema:** Table name, PostgreSQL column types, primary/foreign keys, CHECK constraints, migrations.
- **APIs & Contracts:** HTTP Method, endpoint route (`/api/v1/...`), request schemas, response codes.
- **Business Rules & Standards:** Mention specific rules (e.g. ADR-002 RS256, RB-08 immutability, RF06 semester 6-10, Ley 1581, RF08 contact masking).
- **Target Files:**
  - `path/to/file1.py`
  - `path/to/file2.py`

---

### 4. Acceptance Criteria & Deliverables
- [ ] Core model / repository / service / schema implemented.
- [ ] Endpoint / router exposed and validated with Pydantic / DRF serializers.
- [ ] Unit & integration tests implemented with Pytest (coverage >= 80%).
- [ ] Code formatted with team linters (`ruff`).

---

### 5. Verification Command
<!-- Command to verify the task locally -->
```bash
uv run pytest tests/test_<module>.py
```
