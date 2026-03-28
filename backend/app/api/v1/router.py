"""
ironclad/app/api/v1/router.py
Aggregates all v1 endpoint routers into a single include-able router.
Adding a new resource = import its router here, one line.
"""

from fastapi import APIRouter

from app.api.v1.endpoints import health, payloads

api_router = APIRouter()

api_router.include_router(health.router)
api_router.include_router(payloads.router)
