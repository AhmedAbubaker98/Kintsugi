"""
GitHub webhook endpoint handler.

This module receives and validates incoming GitHub webhook events,
then enqueues jobs for the Worker to process asynchronously.

This is the "Producer" side of the Producer-Consumer architecture.
"""

import logging
from typing import Any

from arq.connections import ArqRedis
from fastapi import APIRouter, Header, HTTPException, Request, status

from app.core.security import verify_webhook_signature

logger = logging.getLogger(__name__)

router = APIRouter(tags=["webhooks"])


@router.post(
    "/webhook",
    status_code=status.HTTP_200_OK,
    summary="GitHub Webhook Receiver",
    description="Receives and processes GitHub webhook events.",
)
async def handle_webhook(
    request: Request,
    x_github_event: str = Header(..., description="GitHub event type"),
    x_hub_signature_256: str = Header(
        ...,
        description="HMAC SHA-256 signature for payload verification",
    ),
    x_github_delivery: str = Header(..., description="Unique delivery GUID"),
) -> dict[str, Any]:
    """
    Handle incoming GitHub webhook events.
    
    This endpoint:
    1. Validates the webhook signature (HMAC SHA-256)
    2. Parses the event type from headers
    3. Routes to appropriate service handlers
    
    Args:
        request: The FastAPI request object.
        x_github_event: The type of GitHub event (e.g., workflow_run).
        x_hub_signature_256: The HMAC SHA-256 signature.
        x_github_delivery: Unique identifier for this delivery.
    
    Returns:
        dict: Response indicating event was received and processed.
    
    Raises:
        HTTPException: 401 if signature validation fails.
        HTTPException: 400 if payload parsing fails.
    """
    # Read raw body for signature verification
    payload = await request.body()
    
    # Validate webhook signature - CRITICAL SECURITY CHECK
    if not verify_webhook_signature(payload, x_hub_signature_256):
        logger.warning(
            f"Invalid webhook signature for delivery {x_github_delivery}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )
    
    # Parse JSON payload
    try:
        event_payload = await request.json()
    except Exception as e:
        logger.error(f"Failed to parse webhook payload: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload",
        )
    
    logger.info(
        f"Received webhook: event={x_github_event}, "
        f"delivery={x_github_delivery}"
    )
    
    # Get Redis pool from app state
    redis: ArqRedis | None = getattr(request.app.state, "redis", None)
    
    # Route event to appropriate handler
    response = await route_event(
        event_type=x_github_event,
        payload=event_payload,
        delivery_id=x_github_delivery,
        redis=redis,
    )
    
    return response


async def route_event(
    event_type: str,
    payload: dict[str, Any],
    delivery_id: str,
    redis: ArqRedis | None,
) -> dict[str, Any]:
    """
    Route GitHub events to appropriate service handlers.
    
    Args:
        event_type: The GitHub event type.
        payload: The parsed webhook payload.
        delivery_id: Unique delivery identifier.
        redis: Redis connection pool for enqueueing jobs.
    
    Returns:
        dict: Response from the event handler.
    """
    logger.debug(f"Routing event: {event_type}")
    
    match event_type:
        case "workflow_run":
            return await handle_workflow_run(payload, delivery_id, redis)
        
        case "check_run":
            return await handle_check_run(payload, delivery_id)
        
        case "issue_comment":
            return await handle_issue_comment(payload, delivery_id, redis)
        
        case "ping":
            return handle_ping(payload)
        
        case _:
            logger.info(f"Ignoring unhandled event type: {event_type}")
            return {
                "status": "ignored",
                "event": event_type,
                "message": f"Event type '{event_type}' is not handled",
            }


async def handle_workflow_run(
    payload: dict[str, Any],
    delivery_id: str,
    redis: ArqRedis | None,
) -> dict[str, Any]:
    """
    Handle workflow_run events from GitHub Actions.
    
    This is the primary entry point for detecting failed E2E tests.
    We're interested in workflow runs that:
    - Have completed (action == "completed")
    - Have failed (conclusion == "failure")
    
    Args:
        payload: The workflow_run event payload.
        delivery_id: Unique delivery identifier.
        redis: Redis connection pool for enqueueing jobs.
    
    Returns:
        dict: Response indicating processing status.
    """
    action = payload.get("action")
    workflow_run = payload.get("workflow_run", {})
    conclusion = workflow_run.get("conclusion")
    workflow_name = workflow_run.get("name", "unknown")
    run_id = workflow_run.get("id")
    
    logger.info(
        f"Workflow run event: action={action}, "
        f"conclusion={conclusion}, "
        f"workflow={workflow_name}, "
        f"run_id={run_id}"
    )
    
    # We only care about completed workflow runs
    if action != "completed":
        return {
            "status": "ignored",
            "reason": f"Workflow action is '{action}', not 'completed'",
        }
    
    # Extract repository and installation info
    repository = payload.get("repository", {})
    installation = payload.get("installation", {})
    
    repo_full_name = repository.get("full_name", "unknown")
    installation_id = installation.get("id")
    
    # Extract the branch name for the commit
    head_branch = workflow_run.get("head_branch", "main")
    
    # Check if Redis is available
    if not redis:
        logger.error("❌ Redis not available - cannot enqueue job")
        return {
            "status": "error",
            "reason": "Job queue unavailable",
        }
    
    # Handle successful workflow runs on Kintsugi branches
    if conclusion == "success" and head_branch.startswith("kintsugi-fix"):
        logger.info(
            f"🎉 Kintsugi fix succeeded! repo={repo_full_name}, "
            f"branch={head_branch}, run_id={run_id}"
        )
        if installation_id and repo_full_name:
            await redis.enqueue_job(
                "handle_success_task",
                installation_id,
                repo_full_name,
                head_branch,
                _queue_name="kintsugi:queue",
            )
            logger.info(f"📤 Enqueued success job for {repo_full_name}@{head_branch}")
        return {
            "status": "queued",
            "event": "workflow_run",
            "delivery_id": delivery_id,
            "message": "Kintsugi success job enqueued",
        }
    
    if conclusion != "failure":
        return {
            "status": "ignored",
            "reason": f"Workflow conclusion is '{conclusion}', not 'failure'",
        }
    
    logger.info(
        f"Processing failed workflow: repo={repo_full_name}, "
        f"run_id={run_id}, installation_id={installation_id}"
    )
    
    if installation_id and repo_full_name and run_id:
        await redis.enqueue_job(
            "process_failure_task",
            installation_id,
            repo_full_name,
            run_id,
            head_branch,
            _queue_name="kintsugi:queue",
        )
        logger.info(f"📤 Enqueued failure job for {repo_full_name}#{run_id}")
    
    return {
        "status": "queued",
        "event": "workflow_run",
        "delivery_id": delivery_id,
        "workflow_run_id": run_id,
        "repository": repo_full_name,
        "message": "Failed workflow run queued for analysis",
    }


async def handle_check_run(
    payload: dict[str, Any],
    delivery_id: str,
) -> dict[str, Any]:
    """
    Handle check_run events.
    
    Check runs provide more granular information about individual
    checks within a workflow. This can be useful for identifying
    specific test failures.
    
    Args:
        payload: The check_run event payload.
        delivery_id: Unique delivery identifier.
    
    Returns:
        dict: Response indicating processing status.
    """
    action = payload.get("action")
    check_run = payload.get("check_run", {})
    
    logger.debug(f"Check run event: action={action}")
    
    # Placeholder for future implementation
    return {
        "status": "ignored",
        "event": "check_run",
        "message": "Check run events not yet implemented",
    }


def handle_ping(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Handle ping events from GitHub.
    
    GitHub sends a ping event when a webhook is first configured.
    This allows us to verify the webhook is set up correctly.
    
    Args:
        payload: The ping event payload.
    
    Returns:
        dict: Response confirming the ping was received.
    """
    hook_id = payload.get("hook_id")
    zen = payload.get("zen", "")
    
    logger.info(f"Received ping from GitHub: hook_id={hook_id}, zen='{zen}'")
    
    return {
        "status": "success",
        "event": "ping",
        "message": "Pong! Webhook is configured correctly.",
        "zen": zen,
    }


async def handle_issue_comment(
    payload: dict[str, Any],
    delivery_id: str,
    redis: ArqRedis | None,
) -> dict[str, Any]:
    """
    Handle issue_comment events from GitHub.
    
    This handles comments on PRs that mention @kintsugi-app, allowing
    users to request amendments to Kintsugi's fixes.
    
    Args:
        payload: The issue_comment event payload.
        delivery_id: Unique delivery identifier.
        redis: Redis connection pool for enqueueing jobs.
    
    Returns:
        dict: Response indicating processing status.
    """
    action = payload.get("action")
    comment = payload.get("comment", {})
    issue = payload.get("issue", {})
    repository = payload.get("repository", {})
    installation = payload.get("installation", {})
    
    comment_body = comment.get("body", "")
    comment_author = comment.get("user", {}).get("login", "unknown")
    issue_number = issue.get("number")
    repo_full_name = repository.get("full_name", "unknown")
    installation_id = installation.get("id")
    
    logger.info(
        f"Issue comment event: action={action}, "
        f"issue=#{issue_number}, author={comment_author}, "
        f"repo={repo_full_name}"
    )
    
    # Only process newly created comments
    if action != "created":
        return {
            "status": "ignored",
            "reason": f"Comment action is '{action}', not 'created'",
        }
    
    # Check if this is a PR (issues and PRs share the same comment API)
    if "pull_request" not in issue:
        return {
            "status": "ignored",
            "reason": "Comment is on an issue, not a pull request",
        }
    
    # Check if @kintsugi-app is mentioned (case-insensitive)
    if "@kintsugi-app" not in comment_body.lower():
        return {
            "status": "ignored",
            "reason": "Comment does not mention @kintsugi-app",
        }
    
    logger.info(
        f"🗣️ @kintsugi-app mentioned in PR #{issue_number} by {comment_author}: "
        f"'{comment_body[:100]}...'"
    )
    
    # Check if Redis is available
    if not redis:
        logger.error("❌ Redis not available - cannot enqueue job")
        return {
            "status": "error",
            "reason": "Job queue unavailable",
        }
    
    if installation_id and repo_full_name and issue_number:
        await redis.enqueue_job(
            "process_comment_task",
            installation_id,
            repo_full_name,
            issue_number,
            comment_body,
            comment_author,
            _queue_name="kintsugi:queue",
        )
        logger.info(f"📤 Enqueued comment job for {repo_full_name}#{issue_number}")
    
    return {
        "status": "queued",
        "event": "issue_comment",
        "delivery_id": delivery_id,
        "pr_number": issue_number,
        "repository": repo_full_name,
        "message": "@kintsugi-app mention queued for processing",
    }
