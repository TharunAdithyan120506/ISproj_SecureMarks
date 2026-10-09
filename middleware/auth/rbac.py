"""Role and ownership checks (authorisation)."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..errors import ApiError


@dataclass(frozen=True)
class Principal:
    username: str
    role: str
    roll_no: str | None = None
    courses: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_claims(cls, claims: dict) -> "Principal":
        return cls(claims["sub"], claims["role"], claims.get("roll_no"), tuple(claims.get("courses") or ()))


def require_role(principal: Principal, roles: tuple[str, ...]) -> str:
    if principal.role not in roles:
        raise ApiError("forbidden", f"role '{principal.role}' may not call this endpoint (needs {'/'.join(roles)})")
    return f"role={principal.role} ∈ {{{', '.join(roles)}}}"


def require_course(principal: Principal, course: str) -> str:
    if course not in principal.courses:
        raise ApiError("forbidden", f"{principal.username} does not teach {course}")
    return f"{course} ∈ courses of {principal.username}"


def require_own_roll(principal: Principal, roll_no: str) -> str:
    if principal.roll_no != roll_no:
        raise ApiError("forbidden", f"{principal.username} may only view roll {principal.roll_no}", action="idor_blocked")
    return f"roll {roll_no} = token roll"
