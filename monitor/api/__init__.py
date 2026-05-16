"""HTTP routes, one router per concern. Wired into the FastAPI app in
`monitor.app.create_app` via `include_router`. Each router pulls
state via the `monitor.state.get_state` FastAPI dependency.
"""

from .health import router as health_router
from .network import router as network_router
from .processes import router as processes_router
from .security import router as security_router
from .signal import router as signal_router
from .timeline import router as timeline_router

__all__ = [
    "health_router",
    "network_router",
    "processes_router",
    "security_router",
    "signal_router",
    "timeline_router",
]
