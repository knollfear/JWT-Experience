import jwt
import os
from jwt import InvalidTokenError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

SECRET_KEY =  os.environ.get("SECRET_KEY", "your_super_secret_key") # load from env in real life
ALGORITHM = os.environ.get("ALGORITHM", "HS256")

class JWTAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        token = request.cookies.get("auth_token")
        payload = None

        if token:
            try:
                payload = jwt.decode(
                    token,
                    SECRET_KEY,
                    algorithms=[ALGORITHM],
                )
            except InvalidTokenError:
                # Bad token – treat as unauthenticated
                payload = None

        # Attach the decoded payload (or None) to the request
        request.state.token_payload = payload

        response = await call_next(request)
        return response