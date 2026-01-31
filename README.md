# Kintsugi 🏺

**Autonomous self-healing for Playwright & Cypress tests, powered by Gemini 3.**

*Built for the Google Gemini API Developer Competition — Agent Track*

---

## 🚀 Quick Start

### Step 1: Install the GitHub App

[**→ Install Kintsugi**](https://github.com/apps/kintsugi-bot)

Grant access to the repositories where you want automatic test healing.

### Step 2: Add Configuration

Create `.github/kintsugi.yml` in your repository:

```yaml
version: 1
demo_password: "<provided-by-kintsugi-team>"

ai:
  mode: "smart"  # "smart" = Gemini Pro, "fast" = Gemini Flash
```

### Step 3: Authentication

During the hackathon demo period, you'll need a `demo_password` to activate Kintsugi. This will be provided directly by the Kintsugi team to authorized evaluators.

### Step 4: Watch the Magic

1. **Your E2E test fails** in GitHub Actions
2. **Kintsugi analyzes** the failure (logs, screenshots, videos, traces)
3. **A fix is committed** to a `kintsugi-fix-*` branch
4. **CI re-runs automatically** — if it passes, a PR opens for your review
5. **If it fails again**, Kintsugi iterates with new context (up to max_attempts)

You don't need to do anything. Just merge when you're happy.

---

## 🧠 Technical Innovation

### Multimodal Temporal Reasoning

Kintsugi leverages **Gemini 3's native video understanding** to analyze `.webm` test recordings frame-by-frame. This catches failures that logs miss:

- **Race conditions** — Element appeared but wasn't interactive yet
- **Animation timing** — Button clicked during a CSS transition
- **Async state drift** — Data loaded after the assertion ran

The model watches the test fail in real-time and reasons about *when* things went wrong, not just *what* went wrong.

### The Silent Workflow

Kintsugi doesn't spam you with broken PRs. The iteration loop is:

```
Failure Detected → Analyze → Generate Fix → Commit to Branch → Re-run CI
                                                    ↓
                                          Still failing? Loop back.
                                          Passing? Open PR.
```

You only see a PR when CI confirms the fix works. No noise. No half-baked attempts cluttering your repo.

### Agentic Memory via Thought Signatures

Each analysis generates a **Thought Signature** — a compressed summary of what Kintsugi learned. On subsequent iterations:

- Previous attempts are passed as context
- The model explicitly avoids repeating failed strategies
- Session state persists across the entire fix cycle

This prevents the classic "LLM amnesia" problem where agents make the same mistake repeatedly.

---

## ⚙️ Configuration Reference

Full `.github/kintsugi.yml` example:

```yaml
version: 1
demo_password: "<provided-by-kintsugi-team>"

branches:
  allow: ["main", "develop", "feature/*"]
  ignore: ["dependabot/**"]

limits:
  max_attempts: 3        # How many fix iterations before giving up
  max_files_changed: 3   # Safety cap on files modified per fix

security:
  protected_paths:
    - ".github/**"
    - "package.json"
    - "*.lock"
  scan_enabled: true       # Semgrep scans all generated code
  block_on_critical: true  # Block commits with critical vulnerabilities

ai:
  mode: "smart"  # "smart" = Pro (deeper reasoning), "fast" = Flash (speed)
  extra_instructions: "Prefer data-testid selectors when available"

testing:
  command: "npx playwright test {test_file}"  # Optional: custom test command
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `demo_password` | — | Required during hackathon demo period |
| `branches.allow` | `["main", "master", "develop", "feature/*"]` | Branches Kintsugi will operate on |
| `branches.ignore` | `["dependabot/**"]` | Branches to ignore |
| `limits.max_attempts` | `3` | Max fix iterations per failure (1-5) |
| `limits.max_files_changed` | `2` | Max files to modify per fix |
| `security.protected_paths` | Common config files | Glob patterns Kintsugi cannot touch |
| `security.scan_enabled` | `true` | Run Semgrep on generated code |
| `ai.mode` | `"fast"` | `"smart"` for Pro, `"fast"` for Flash |
| `ai.extra_instructions` | — | Custom guidance for the AI |

---

## 💬 Human-in-the-Loop

Kintsugi PRs aren't fire-and-forget. You can **reply to refine the fix**.

### Example Interaction

**Kintsugi opens PR:**
> Fixed `login.spec.ts` by adding a 500ms wait before clicking the submit button.

**You comment:**
```
@kintsugi Don't use arbitrary waits. Use waitForSelector on the loading spinner instead.
```

**Kintsugi responds:**
> Updated the fix to wait for `[data-testid="loading-spinner"]` to disappear before proceeding.

The bot understands context from the PR diff, your comment, and the original failure. Amendments are committed directly to the same branch.

---

## 🔒 Security & Safety

### Semgrep Integration

Every line of AI-generated code is scanned with **Semgrep** before commit. Kintsugi blocks fixes containing:

- SQL injection patterns
- Command injection risks
- Hardcoded credentials
- Path traversal vulnerabilities

Critical findings are logged and the fix is rejected.

### Code Privacy

- Your code is sent to Google's Gemini API for analysis
- **No code is stored** beyond the API request lifecycle
- Kintsugi does not train on your data
- All communication uses HTTPS with webhook signature validation

### Protected Paths

By default, Kintsugi **cannot modify**:

- `.github/**` — Workflow files
- `package.json`, `package-lock.json` — Dependencies
- `Dockerfile`, `docker-compose.yml` — Infrastructure
- `*.lock` — Lock files

You can customize this list in your `kintsugi.yml`.

---

## 🧪 Supported Tech Stack

### Test Frameworks

| Framework | Status |
|-----------|--------|
| Playwright | ✅ Full support |
| Cypress | ✅ Full support |
| Pytest | 🔄 Planned |

### CI/CD

| Platform | Status |
|----------|--------|
| GitHub Actions | ✅ Supported |
| GitLab CI | 🔄 Planned |
| CircleCI | 🔄 Planned |

### AI Models

| Model | Mode | Best For |
|-------|------|----------|
| Gemini 3 Pro | `smart` | Complex failures, multi-file fixes |
| Gemini 3 Flash | `fast` | Simple selector issues, quick iteration |

---

## 📄 License & Credits

### The Name

**Kintsugi** (金継ぎ) is the Japanese art of repairing broken pottery with gold, embracing imperfection as part of the object's history. Similarly, this tool doesn't just fix tests — it makes them more resilient.

### License

**Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**

Free to use and modify for non-commercial purposes with attribution.

### Built For

**Google Gemini 3 Hackathon by Google DeepMind**

---

<p align="center">
  <em>Stop fighting flaky tests. Let Kintsugi heal them.</em>
</p>
