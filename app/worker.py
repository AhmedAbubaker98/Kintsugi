"""
Kintsugi Worker - The "Brain" Container.

This module defines the arq worker that processes GitHub webhook jobs
asynchronously. It handles the heavy lifting of analyzing failures,
generating fixes, and creating pull requests.

The worker runs as a separate process/container from the API, allowing
the webhook endpoint to return immediately while jobs are processed
in the background.
"""

import logging
from typing import Any
from urllib.parse import urlparse

from arq.connections import RedisSettings

from app.core.config import settings

# Configure worker-specific logging
logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s - [WORKER] - %(name)s - %(levelname)s - %(message)s",
)

# Suppress noisy HTTP client logs
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("hpack").setLevel(logging.WARNING)
logging.getLogger("arq").setLevel(logging.INFO)

logger = logging.getLogger(__name__)


def get_redis_settings() -> RedisSettings:
    """
    Parse REDIS_URL and return arq-compatible RedisSettings.
    
    Handles both redis:// and rediss:// (SSL) schemes.
    Upstash requires SSL (rediss://).
    
    Returns:
        RedisSettings: Configuration for arq Redis connection.
    """
    url = urlparse(settings.redis_url)
    
    # Determine if SSL is required (rediss:// scheme)
    use_ssl = url.scheme == "rediss"
    
    # Extract password from URL (format: rediss://default:PASSWORD@host:port)
    password = url.password
    username = url.username if url.username != "default" else None
    
    redis_settings = RedisSettings(
        host=url.hostname or "localhost",
        port=url.port or 6379,
        username=username,
        password=password,
        ssl=use_ssl,
        ssl_cert_reqs="required" if use_ssl else "none",
        ssl_check_hostname=use_ssl,
        conn_timeout=30,
        conn_retries=5,
        conn_retry_delay=1,
    )
    
    logger.info(
        f"Redis configured: host={url.hostname}, port={url.port}, "
        f"ssl={use_ssl}"
    )
    
    return redis_settings


# =============================================================================
# LIFECYCLE HOOKS
# =============================================================================

async def startup(ctx: dict[str, Any]) -> None:
    """
    Worker startup hook.
    
    Initialize expensive resources that should be reused across jobs:
    - WorkflowProcessor (includes GeminiService, GitHubService)
    
    Args:
        ctx: Worker context dictionary for storing shared resources.
    """
    logger.info("🚀 Kintsugi Worker starting up...")
    
    # Import here to avoid circular imports and ensure fresh instances
    from app.services.workflow_processor import WorkflowProcessor
    
    # Create processor instance - this initializes all services
    processor = WorkflowProcessor()
    ctx["processor"] = processor
    
    logger.info("✅ Worker initialized with WorkflowProcessor")


async def shutdown(ctx: dict[str, Any]) -> None:
    """
    Worker shutdown hook.
    
    Clean up resources gracefully.
    
    Args:
        ctx: Worker context dictionary.
    """
    logger.info("🛑 Kintsugi Worker shutting down...")
    
    # Clean up processor if needed
    if "processor" in ctx:
        # WorkflowProcessor doesn't have explicit cleanup, but we log it
        del ctx["processor"]
    
    logger.info("✅ Worker shutdown complete")


# =============================================================================
# JOB FUNCTIONS
# =============================================================================

async def process_failure_task(
    ctx: dict[str, Any],
    installation_id: int,
    repo_full_name: str,
    run_id: int,
    branch: str,
) -> dict[str, Any]:
    """
    Process a failed workflow run.
    
    This job:
    1. Downloads test artifacts (screenshots, videos, traces, logs)
    2. Analyzes the failure using Gemini 3
    3. Generates and commits a fix
    4. Iterates if the fix fails (up to max_attempts)
    5. Opens a PR when the fix succeeds
    
    Args:
        ctx: Worker context containing the processor instance.
        installation_id: GitHub App installation ID.
        repo_full_name: Full repository name (owner/repo).
        run_id: The failed workflow run ID.
        branch: The branch where the failure occurred.
    
    Returns:
        dict: Result summary of the processing.
    """
    logger.info(
        f"📥 Processing failure job: repo={repo_full_name}, "
        f"run_id={run_id}, branch={branch}"
    )
    
    try:
        processor = ctx["processor"]
        await processor.process_failure(
            installation_id=installation_id,
            repo_full_name=repo_full_name,
            run_id=run_id,
            branch=branch,
        )
        
        logger.info(f"✅ Failure processing complete: {repo_full_name}#{run_id}")
        return {
            "status": "success",
            "repo": repo_full_name,
            "run_id": run_id,
        }
        
    except Exception as e:
        logger.error(
            f"❌ Failed to process failure: {repo_full_name}#{run_id} - {e}",
            exc_info=True,
        )
        # Re-raise to let arq handle retry logic
        raise


async def process_comment_task(
    ctx: dict[str, Any],
    installation_id: int,
    repo_full_name: str,
    pr_number: int,
    comment_body: str,
    comment_author: str,
) -> dict[str, Any]:
    """
    Process a comment mentioning @kintsugi-app.
    
    This job:
    1. Fetches the PR context and Kintsugi's previous changes
    2. Analyzes the user's feedback using Gemini 3
    3. Generates and commits amendments
    4. Posts a reply summarizing the changes
    
    Args:
        ctx: Worker context containing the processor instance.
        installation_id: GitHub App installation ID.
        repo_full_name: Full repository name (owner/repo).
        pr_number: The PR number where the comment was made.
        comment_body: The comment text.
        comment_author: GitHub username of the commenter.
    
    Returns:
        dict: Result summary of the processing.
    """
    logger.info(
        f"📥 Processing comment job: repo={repo_full_name}, "
        f"pr=#{pr_number}, author=@{comment_author}"
    )
    
    try:
        processor = ctx["processor"]
        await processor.process_comment(
            installation_id=installation_id,
            repo_full_name=repo_full_name,
            pr_number=pr_number,
            comment_body=comment_body,
            comment_author=comment_author,
        )
        
        logger.info(f"✅ Comment processing complete: {repo_full_name}#{pr_number}")
        return {
            "status": "success",
            "repo": repo_full_name,
            "pr_number": pr_number,
        }
        
    except Exception as e:
        logger.error(
            f"❌ Failed to process comment: {repo_full_name}#{pr_number} - {e}",
            exc_info=True,
        )
        # Re-raise to let arq handle retry logic
        raise


async def handle_success_task(
    ctx: dict[str, Any],
    installation_id: int,
    repo_full_name: str,
    branch: str,
) -> dict[str, Any]:
    """
    Handle successful workflow run on a Kintsugi branch.
    
    This job creates the PR with the full success report when
    a Kintsugi fix has been verified by CI.
    
    Args:
        ctx: Worker context containing the processor instance.
        installation_id: GitHub App installation ID.
        repo_full_name: Full repository name (owner/repo).
        branch: The Kintsugi branch name.
    
    Returns:
        dict: Result summary of the processing.
    """
    logger.info(
        f"📥 Processing success job: repo={repo_full_name}, branch={branch}"
    )
    
    try:
        processor = ctx["processor"]
        await processor.handle_kintsugi_success(
            installation_id=installation_id,
            repo_full_name=repo_full_name,
            branch=branch,
        )
        
        logger.info(f"✅ Success handling complete: {repo_full_name}@{branch}")
        return {
            "status": "success",
            "repo": repo_full_name,
            "branch": branch,
        }
        
    except Exception as e:
        logger.error(
            f"❌ Failed to handle success: {repo_full_name}@{branch} - {e}",
            exc_info=True,
        )
        # Re-raise to let arq handle retry logic
        raise


# =============================================================================
# WORKER SETTINGS
# =============================================================================

class WorkerSettings:
    """
    arq Worker configuration.
    
    This class defines all settings for the arq worker including:
    - Redis connection settings
    - Job functions to register
    - Lifecycle hooks
    - Retry behavior
    """
    
    # Redis connection
    redis_settings = get_redis_settings()
    
    # Register job functions
    functions = [
        process_failure_task,
        process_comment_task,
        handle_success_task,
    ]
    
    # Lifecycle hooks
    on_startup = startup
    on_shutdown = shutdown
    
    # Job retry configuration
    max_tries = 2  # Original attempt + 1 retry
    job_timeout = 600  # 10 minutes max per job (Gemini calls can be slow)
    
    # Queue settings
    queue_name = "kintsugi:queue"
    
    # Health check interval
    health_check_interval = 30


# For running with: arq app.worker.WorkerSettings
if __name__ == "__main__":
    # This allows running the worker directly for testing
    import asyncio
    from arq import run_worker
    
    asyncio.run(run_worker(WorkerSettings))
