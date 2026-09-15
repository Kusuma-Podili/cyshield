"""Authentication & Identity Package."""

from cybershield.auth.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from cybershield.auth.dependencies import (
    get_current_user,
    require_role,
    require_permission,
    oauth2_scheme,
)
from cybershield.auth.routes import router as auth_router

__all__ = [
    "verify_password",
    "get_password_hash",
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "get_current_user",
    "require_role",
    "require_permission",
    "oauth2_scheme",
    "auth_router",
]
