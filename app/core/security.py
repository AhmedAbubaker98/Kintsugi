"""
Security utilities for webhook signature validation.

This module provides HMAC SHA-256 signature verification
for GitHub webhook payloads to ensure authenticity.
"""

import hashlib
import hmac
import logging
from typing import Optional

from app.core.config import settings

logger = logging.getLogger(__name__)


def verify_webhook_signature(
    payload: bytes,
    signature_header: Optional[str],
    secret: Optional[str] = None,
) -> bool:
    """
    Verify the GitHub webhook HMAC SHA-256 signature.
    
    GitHub sends a signature in the X-Hub-Signature-256 header
    in the format: sha256=<hex_digest>
    
    This function computes the expected signature using the webhook
    secret and compares it securely using constant-time comparison.
    
    Args:
        payload: The raw request body bytes.
        signature_header: The X-Hub-Signature-256 header value.
        secret: The webhook secret. If None, uses settings.webhook_secret.
    
    Returns:
        bool: True if the signature is valid, False otherwise.
    
    Example:
        >>> payload = b'{"action": "completed"}'
        >>> signature = "sha256=abc123..."
        >>> is_valid = verify_webhook_signature(payload, signature)
    """
    if not signature_header:
        logger.warning("Missing webhook signature header")
        return False
    
    # Use provided secret or fall back to settings
    webhook_secret = secret or settings.webhook_secret.get_secret_value()
    
    if not webhook_secret:
        logger.error("Webhook secret is not configured")
        return False
    
    # Parse the signature header (format: sha256=<hex_digest>)
    try:
        algorithm, expected_signature = signature_header.split("=", 1)
    except ValueError:
        logger.warning("Invalid signature header format")
        return False
    
    if algorithm != "sha256":
        logger.warning(f"Unsupported signature algorithm: {algorithm}")
        return False
    
    # Compute the expected signature
    computed_signature = hmac.new(
        key=webhook_secret.encode("utf-8"),
        msg=payload,
        digestmod=hashlib.sha256,
    ).hexdigest()
    
    # Use constant-time comparison to prevent timing attacks
    is_valid = hmac.compare_digest(computed_signature, expected_signature)
    
    if not is_valid:
        logger.warning("Webhook signature verification failed")
    else:
        logger.debug("Webhook signature verified successfully")
    
    return is_valid


def generate_webhook_signature(payload: bytes, secret: str) -> str:
    """
    Generate a webhook signature for testing purposes.
    
    Args:
        payload: The request body bytes.
        secret: The webhook secret.
    
    Returns:
        str: The signature in format sha256=<hex_digest>.
    """
    signature = hmac.new(
        key=secret.encode("utf-8"),
        msg=payload,
        digestmod=hashlib.sha256,
    ).hexdigest()
    
    return f"sha256={signature}"
