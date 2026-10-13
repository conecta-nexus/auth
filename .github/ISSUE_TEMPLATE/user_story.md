---
name: User Story
about: Functional user story template for backlog items
title: '[<SERVICE>] HU-<ID>: <Short English Title>'
labels: ['user-story']
assignees: ''
---

### 1. User Story Statement
**As a** [user role: Student / Company / Administrator]  
**I want to** [action, capability, or functional requirement]  
**So that** [business value, benefit, or rationale]  

---

### 2. Traceability & Scope
- **Module / Microservice:** `auth` | `profile` | `challenge` | `application` | `moderation` | `notification` | `frontend` | `gateway` | `infra`
- **Functional Requirements:** RF<XX>, RF<YY>
- **Business Rules:** RB<XX> (e.g., RB-03 non-duplicity, RB-04 atomic in-process lock, RB-08 semester immutability)
- **Use Case:** CU<XX>
- **Sprint:** Sprint 1 | Sprint 2 | Sprint 3
- **Story Points (Fibonacci):** 1 | 2 | 3 | 5 | 8 | 13

---

### 3. Acceptance Criteria (Gherkin Scenarios)
#### Scenario 1: Successful Execution
- **Given** [initial context or precondition]
- **When** [action executed by the actor]
- **Then** [observable expected result / status code / state change]

#### Scenario 2: Validation Failure / Business Rule Enforcement
- **Given** [invalid input, unauthorized actor, or boundary condition]
- **When** [action attempted]
- **Then** [rejection response, error message, or access blocked]

---

### 4. Technical Checklist
- [ ] Database schema model and migration created (`db_<service>`)
- [ ] Domain logic, entities, and services implemented
- [ ] REST API endpoints exposed and validated with Pydantic / DRF serializers
- [ ] Unit tests implemented with Pytest (test coverage >= 80%)
- [ ] OpenAPI / Swagger documentation verified at `/docs`
- [ ] Integration with API Gateway tested
