"""
GitHub webhook endpoint handler.

This module receives and validates incoming GitHub webhook events,
routing them to the appropriate service handlers based on event type.
"""

import logging
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request, status

from app.core.security import verify_webhook_signature
from app.services.github_service import GitHubService
from app.services.workflow_processor import WorkflowProcessor

logger = logging.getLogger(__name__)

router = APIRouter(tags=["webhooks"])

# Initialize GitHub service
github_service = GitHubService()


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
    
    # Route event to appropriate handler
    response = await route_event(
        event_type=x_github_event,
        payload=event_payload,
        delivery_id=x_github_delivery,
    )
    
    return response


async def route_event(
    event_type: str,
    payload: dict[str, Any],
    delivery_id: str,
) -> dict[str, Any]:
    """
    Route GitHub events to appropriate service handlers.
    
    Args:
        event_type: The GitHub event type.
        payload: The parsed webhook payload.
        delivery_id: Unique delivery identifier.
    
    Returns:
        dict: Response from the event handler.
    """
    logger.debug(f"Routing event: {event_type}")
    
    match event_type:
        case "workflow_run":
            return await handle_workflow_run(payload, delivery_id)
        
        case "check_run":
            return await handle_check_run(payload, delivery_id)
        
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
    
    # We only care about completed, failed workflow runs
    if action != "completed":
        return {
            "status": "ignored",
            "reason": f"Workflow action is '{action}', not 'completed'",
        }
    
    if conclusion != "failure":
        return {
            "status": "ignored",
            "reason": f"Workflow conclusion is '{conclusion}', not 'failure'",
        }
    
    # Extract repository and installation info
    repository = payload.get("repository", {})
    installation = payload.get("installation", {})
    
    repo_full_name = repository.get("full_name", "unknown")
    installation_id = installation.get("id")
    
    logger.info(
        f"Processing failed workflow: repo={repo_full_name}, "
        f"run_id={run_id}, installation_id={installation_id}"
    )
    
    if installation_id and repo_full_name and run_id:
        processor = WorkflowProcessor()
        # We await this directly so you can see the logs in your terminal immediately.
        # In production, we would use FastAPI BackgroundTasks here.
        await processor.process_failure(installation_id, repo_full_name, run_id)
    
    return {
        "status": "processing",
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
