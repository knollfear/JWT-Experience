from functools import wraps
from typing import Optional
from fastapi import Request
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="templates")


def claim_required(required: Optional[str] = None):
    """
    Decorator for FastAPI endpoints.

    - If `required` is None: just requires a valid token (authenticated user).
    - If `required` is a plain string, e.g. "read_loggedIn", require that claim.
    - If `required` is a format string with {…}, e.g. "{op}_{entity}",
      it will be formatted with the endpoint's kwargs (e.g. op, entity).

    Examples:

        @app.get("/logged-in")
        @claim_required("read_loggedIn")
        async def logged_in(request: Request): ...

        @app.get("/logged-in/claim/{op}/{entity}")
        @claim_required("{op}_{entity}")
        async def claim_page(request: Request, op: str, entity: str): ...
    """

    def decorator(endpoint):
        @wraps(endpoint)
        async def wrapper(*args, **kwargs):
            # Find the Request object
            request: Optional[Request] = kwargs.get("request")
            if request is None:
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break

            if request is None:
                raise RuntimeError(
                    "Endpoint decorated with @claim_required must include a 'request: Request' parameter."
                )

            payload = getattr(request.state, "token_payload", None)
            permissions = []
            if isinstance(payload, dict):
                permissions = payload.get("permissions", []) or []


            if not payload or payload == []:
                return templates.TemplateResponse(
                    "unauthorized.html",
                    {
                        "request": request,
                    },
                    status_code=401,
                )

            # Compute the actual required claim
            if "{" in required and "}" in required:
                # Template like "{op}_{entity}"
                try:
                    required_claim = required.format(**kwargs)
                except KeyError as e:
                    raise RuntimeError(
                        f"Missing path parameter {e!s} needed for claim template '{required}'"
                    )
            else:
                required_claim = required

            if required_claim not in permissions:
                context = {
                    "request": request,
                    "required_claim": required_claim,
                    "permissions": permissions,
                    "email": (payload or {}).get("sub"),
                }
                return templates.TemplateResponse(
                    "forbidden.html",
                    context,
                    status_code=403,
                )

            # Authorized → proceed
            return await endpoint(*args, **kwargs)

        return wrapper

    return decorator