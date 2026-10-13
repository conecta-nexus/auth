# Conecta Nexus - Engineering & Git Workflow Guidelines

Welcome to the **Conecta Nexus** development workflow. This document defines the mandatory engineering practices, branching rules, commit standards, and GitHub Projects synchronization policies.

---

## 1. Golden Language Rule
All branch names, commit messages, pull request titles, and pull request descriptions **MUST BE WRITTEN IN ENGLISH**.
- Consistent English naming complies with enterprise standards and prevents character encoding mismatches.
- It guarantees professional auditable traceability for academic evaluation.

---

## 2. Branching Strategy

Our ecosystem uses a streamlined GitFlow architecture with two protected long-lived branches:
- `main`: Production-ready, fully tested, and deployable code.
- `develop`: Central integration branch for ongoing sprint work.

**Direct pushes to `main` or `develop` are strictly prohibited.**

### Allowed Branch Types:
| Type | Format | Description & Example |
| :--- | :--- | :--- |
| **Feature** | `feature/HU-[ID]-[short-name]` | New user story from the product backlog.<br>`feature/HU-01-auth-jwt`<br>`feature/HU-06-create-challenge` |
| **Chore** | `chore/[short-name]` | Tooling, dependencies, linters, or workspace setup.<br>`chore/setup-podman-compose`<br>`chore/configure-ruff-linter` |
| **Bugfix** | `bugfix/issue-[ID]-[short-name]` | Functional bug correction found during testing.<br>`bugfix/issue-14-token-expiration` |
| **Refactor**| `refactor/[short-name]` | Internal code improvement without behavior changes.<br>`refactor/db-connection-pool` |
| **Hotfix**  | `hotfix/[short-name]` | Critical emergency patch branched from `main`.<br>`hotfix/fix-db-connection-string` |

```bash
# Workflow example:
git checkout develop
git pull origin develop
git checkout -b feature/HU-01-auth-jwt
```

---

## 3. Commit Message Standards (Conventional Commits)

Format: `<type>(<scope>): <imperative mood description in English> [#issue-id]`

### Commit Types:
- `feat`: New feature or user story increment.
- `fix`: Defect or bug resolution.
- `chore`: Tooling, dependency, or configuration adjustment.
- `docs`: Documentation updates.
- `refactor`: Code refactoring without behavioral alterations.
- `test`: Unit or integration test addition/modification.
- `ci`: GitHub Actions workflow or deployment pipeline changes.

### Examples:
```bash
git commit -m "feat(auth): implement user registration and password hashing #5"
git commit -m "test(auth): add unit test for invalid jwt signature #5"
git commit -m "fix(challenge): validate allowed mime types for pdf attachments #18"
git commit -m "chore(infra): add multi-db postgresql initialization script"
```

---

## 4. STRICT MERGE POLICY: NO SQUASH MERGE

**Squash Merge is strictly forbidden.**
- All pull requests must be merged using **"Create a merge commit"** (`--no-ff`).
- **Rationale:** Preserves atomic commits, individual author attributions across pairing partners (Code Owners), and full chronological audit trails for academic reviews.

---

## 5. GitHub Projects v2 Workflow Integration

1. **Pick a Task:** Locate your assigned User Story in the **To Do** column of the organizational project `Conecta Nexus - Core Management`.
2. **Move to In Progress:** Drag the card to **In Progress** or self-assign when beginning local implementation.
3. **Open Pull Request:** Target base `develop` from your feature branch.
   - Include the closing keyword in the PR description: `Closes conecta-nexus/<repo>#<issue-number>`.
   - Card automatically transitions to **In Review**.
4. **Peer Review:** Your assigned Code Owner partner reviews the PR, comments, and marks **Approve**.
5. **Merge & Done:** Once CI checks pass and 1 approval is granted, execute **Create a merge commit**. The issue and project card automatically move to **Done**.
