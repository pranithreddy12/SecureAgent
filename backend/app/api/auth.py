from fastapi import APIRouter, HTTPException, Request, Response, status

from app.api.deps import CurrentUser, DbSession
from app.core.config import get_settings
from app.core.ratelimit import login_limiter
from app.core.security import COOKIE_NAME, create_access_token
from app.schemas.auth import LoginRequest, RegisterRequest, TokenOut, UserOut
from app.services import user_service

router = APIRouter(prefix="/auth", tags=["auth"])


# Public by design: this is how a new user creates an account.
@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(data: RegisterRequest, db: DbSession):  # secureagent: ignore
    try:
        return await user_service.create_user(db, data)
    except user_service.EmailAlreadyRegistered:
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered") from None


# Public by design: this is how a caller obtains a session.
@router.post("/login", response_model=TokenOut)
async def login(
    data: LoginRequest, request: Request, response: Response, db: DbSession
):  # secureagent: ignore
    client = request.client.host if request.client else "unknown"
    key = f"{client}|{data.email.lower()}"
    wait = login_limiter.retry_after(key)
    if wait:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many failed sign-in attempts. Try again later.",
            headers={"Retry-After": str(wait)},
        )
    user = await user_service.authenticate(db, data.email, data.password)
    if user is None:
        login_limiter.record_failure(key)
        # Same message for unknown email and wrong password (no account enumeration).
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    login_limiter.reset(key)
    settings = get_settings()
    token = create_access_token(user.id)
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=settings.access_token_expire_minutes * 60,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )
    return TokenOut(access_token=token, user=UserOut.model_validate(user))


# Needs no authorization: it only clears the caller's own cookie.
@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(response: Response) -> None:  # secureagent: ignore
    settings = get_settings()
    response.delete_cookie(
        COOKIE_NAME, path="/", httponly=True, secure=settings.cookie_secure, samesite="lax"
    )


@router.get("/me", response_model=UserOut)
async def me(user: CurrentUser):
    return user
