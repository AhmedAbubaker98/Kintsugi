"""
API router aggregating all endpoint routers.
"""

from fastapi import APIRouter

from app.api.endpoints.webhook import router as webhook_router

# Main API router
api_router = APIRouter()

# Include endpoint routers
api_router.include_router(webhook_router)
