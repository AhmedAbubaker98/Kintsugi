"""
Kintsugi - The Autonomous QA Orchestrator.

Main FastAPI application entry point.
This is the "Producer" in the Producer-Consumer architecture.
It receives webhooks and enqueues jobs for the Worker to process.
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from arq import create_pool
from arq.connections import ArqRedis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.endpoints import webhook
from app.api.router import api_router
from app.core.config import settings

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s - [API] - %(name)s - %(levelname)s - %(message)s",
)

# Suppress noisy HTTP client logs
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("hpack").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan manager.
    
    Handles startup and shutdown events for the application.
    Initializes and cleans up the Redis connection pool for job enqueueing.
    
    Args:
        app: The FastAPI application instance.
    
    Yields:
        None
    """
    # Startup
    logger.info(f"Starting {settings.app_name}...")
    logger.info(f"Debug mode: {settings.debug}")
    logger.info(f"GitHub App ID: {settings.github_app_id}")
    
    # Initialize Redis pool for arq job enqueueing
    from app.worker import get_redis_settings
    redis_settings = get_redis_settings()
    
    try:
        redis_pool: ArqRedis = await create_pool(redis_settings)
        app.state.redis = redis_pool
        logger.info("✅ Redis connection pool initialized")
    except Exception as e:
        logger.error(f"❌ Failed to connect to Redis: {e}")
        # Allow app to start even without Redis for health checks
        app.state.redis = None
    
    yield
    
    # Shutdown
    logger.info(f"Shutting down {settings.app_name}...")
    
    # Close Redis pool
    if hasattr(app.state, "redis") and app.state.redis:
        await app.state.redis.close()
        logger.info("✅ Redis connection pool closed")


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.
    
    Returns:
        FastAPI: The configured application instance.
    """
    app = FastAPI(
        title=settings.app_name,
        description=(
            "The Autonomous QA Orchestrator for Playwright & Cypress. "
            "Uses Video/Image understanding to fix brittle E2E tests automatically."
        ),
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
    )
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if settings.debug else [],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Include API routes
    app.include_router(api_router) 
    app.include_router(webhook.router)

    # Health check endpoint 
    @app.get("/health", tags=["health"])
    async def health_check() -> dict[str, str]:
        """Health check endpoint."""
        return {"status": "healthy", "app": settings.app_name}
    
    return app


# Create the application instance
app = create_app()


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
    )
