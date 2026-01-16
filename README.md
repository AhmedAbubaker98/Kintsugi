# Kintsugi

**The Autonomous QA Orchestrator for Playwright & Cypress**

> Uses Video/Image understanding to fix brittle E2E tests automatically.

## 🎯 Project Goal

Heal is an automated QA agent that fixes broken E2E tests. It listens for GitHub Actions failures, analyzes logs/artifacts using Gemini 3, and pushes fixes automatically.

## 🏗️ Project Structure

```
heal/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application entry point
│   ├── api/
│   │   ├── __init__.py
│   │   ├── router.py        # API router aggregation
│   │   └── endpoints/
│   │       ├── __init__.py
│   │       └── webhook.py   # GitHub webhook handler
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py        # Pydantic settings configuration
│   │   └── security.py      # Webhook signature validation
│   └── services/
│       ├── __init__.py
│       └── github_service.py # GitHub API interactions
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- A GitHub App configured with webhook secret

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/heal.git
   cd heal
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Run the development server**
   ```bash
   uvicorn app.main:app --reload
   ```

   Or directly:
   ```bash
   python -m app.main
   ```

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GITHUB_APP_ID` | Your GitHub App ID | ✅ |
| `GITHUB_PRIVATE_KEY` | GitHub App private key (PEM format) | ✅ |
| `WEBHOOK_SECRET` | Secret for webhook signature validation | ✅ |
| `GEMINI_API_KEY` | Google Gemini API key | ✅ |
| `DEBUG` | Enable debug mode (default: false) | ❌ |
| `API_HOST` | Server host (default: 0.0.0.0) | ❌ |
| `API_PORT` | Server port (default: 8000) | ❌ |

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/webhook` | GitHub webhook receiver |
| `GET` | `/health` | Health check endpoint |
| `GET` | `/docs` | OpenAPI documentation (debug mode only) |

## 🔒 Security

- All webhook payloads are validated using HMAC SHA-256 signatures
- GitHub App authentication uses JWT tokens
- Sensitive configuration is managed via environment variables

## 🛠️ Tech Stack

- **Framework**: FastAPI (Async)
- **Configuration**: Pydantic Settings
- **HTTP Client**: httpx (Async)
- **Server**: Uvicorn
- **AI**: Google Gemini 3

## 📋 Development Phases

- [x] **Phase 0**: Project scaffold and webhook receiver
- [ ] **Phase 1**: Ingestion (artifact download, log parsing)
- [ ] **Phase 2**: Intelligence (Gemini integration, prompt engineering)
- [ ] **Phase 3**: The Loop (patch, verify, commit)
- [ ] **Phase 4**: Polish (PR comments, demo)

## 📄 License

MIT License - see LICENSE file for details.
