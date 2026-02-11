import time
import json
import uuid
from typing import Dict, Any
from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
# Use the modern Authlib interface
from authlib.jose import jwt, JsonWebKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from starlette.responses import PlainTextResponse

router = APIRouter()
templates = Jinja2Templates(directory="templates")

# --- IMPROVED KEY GENERATION ---
# 1. Generate a real RSA Private Key object
_private_key_obj = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# 2. Derive the Public Key object
_public_key_obj = _private_key_obj.public_key()

# 3. Create a JWK (JSON Web Key) for the /jwks endpoint
# We add a 'kid' (Key ID) so Keycloak can identify the key
JWK_PUBLIC = json.loads(JsonWebKey.import_key(_public_key_obj, {'kty': 'RSA'}).as_json())
JWK_PUBLIC['kid'] = "mock-idp-key-id"

# 4. Export the Private Key in PEM format for signing tokens
PRIVATE_KEY_PEM = _private_key_obj.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# --- IN-MEMORY STORAGE ---
AUTH_CODES: Dict[str, Any] = {}

PERSONAS = {
    "default": {
        "sub": "user-001",
        "email": "tester@example.com",
        "preferred_username": "tester",
        "department": "QA",
        "roles": ["viewer"]
    },
    "admin": {
        "sub": "admin-999",
        "email": "admin@example.com",
        "preferred_username": "superuser",
        "department": "Engineering",
        "roles": ["admin", "editor", "viewer"],
        "is_internal": True
    }
}


def get_base_url(request: Request):
    # Dynamically determine base URL from request headers
    return str(request.base_url).rstrip('/')


@router.get("/", response_class=HTMLResponse)
async def root_dashboard(request: Request):
    base = str(request.base_url).rstrip('/')
    # These are dummy values that simulate a request coming from a client like Keycloak
    persona_url = f"{base}/idp/persona/oidc/authorize?redirect_uri={base}/idp/persona/oidc/callback-preview&state=test-123&nonce=12345"
    expert_url = f"{base}/idp/expert/oidc/authorize?redirect_uri={base}/idp/expert/oidc/callback-preview&state=test-123&nonce=12345"

    return templates.TemplateResponse("IDP/dashboard.html", {"request": request, 'persona_url': persona_url, 'expert_url':expert_url})


# A simple helper page to show you what the result would have looked like
@router.get("/{mode}/oidc/callback-preview", response_class=HTMLResponse)
async def callback_preview(request: Request, code: str, state: str):
    claims = AUTH_CODES.pop(code, None)
    payload={}
    if claims:
        now = int(time.time())
        payload = {
            "iss": "https://jwt.knollfear.com/idp/oidc",
            "aud": "my-keycloak-client",
            "iat": now,
            "exp": now + 3600,
            "sub": claims.get("sub", "user-default")
        }
        payload.update(claims)

        # Sign using the PEM string and the explicit Header
        header = {'alg': 'RS256', 'kid': JWK_PUBLIC['kid']}

        # Use the PEM key directly for signing
        token = jwt.encode(header, payload, PRIVATE_KEY_PEM).decode('utf-8')

    return f"""
    <div style="font-family:sans-serif; background:#111; color:#eee; padding:2rem; line-height:1.6;">
        <h2 style="color:#00d1b2;">Handshake Preview</h2>
        <p>This is what the IDP has prepared for Keycloak:</p>

        <div style="background:#222; padding:1rem; border-radius:8px; border:1px solid #444;">
            <h4 style="margin-top:0;">1. The ID Token (Encoded)</h4>
            <code style="word-break: break-all; color:#ffdd57;">{token}</code>
        </div>

        <div style="background:#222; padding:1rem; border-radius:8px; border:1px solid #444; margin-top:1rem;">
            <h4 style="margin-top:0;">2. Decoded Payload (Check 'iss' and 'aud')</h4>
            <pre style="color:#48c774;">{json.dumps(payload, indent=4)}</pre>
        </div>

        <p style="margin-top:1.5rem;">
            <strong>Next Step:</strong> Keycloak will call <code>/idp/oidc/token</code> using 
            Code: <code>{code}</code> to retrieve this exact data.
        </p>
        <a href="/idp/oidc/" style="color:#3273dc;">Back to Dashboard</a>
    </div>
    """
# --- OIDC ENDPOINTS ---

# idp_router.py

@router.get("/{mode}/.well-known/openid-configuration")
async def discovery(request: Request, mode: str):
    # The 'issuer' MUST match the URL Keycloak is configured with
    base = f"https://jwt.knollfear.com/idp/{mode}/oidc"
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "jwks_uri": f"{base}/jwks",
        # ... rest of your config
    }


@router.get("/{mode}/oidc/authorize", response_class=HTMLResponse)
async def authorize(request: Request, mode: str, redirect_uri: str, state: str, nonce: str = None):
    # Determine which UI to show
    is_persona = (mode == "persona")

    return templates.TemplateResponse("IDP/index.html", {
        "request": request,
        "is_persona": is_persona,  # Pass this to the template
        "mode": mode,
        "redirect_uri": redirect_uri,
        "state": state,
        "nonce": nonce,
        "personas": PERSONAS.keys(),
        "default_json": json.dumps(PERSONAS['default'], indent=4)
    })


@router.get("/jwks")
async def jwks():
    # Wrap the key in the "keys" array standard
    return {"keys": [JWK_PUBLIC]}


@router.post("/token")
async def token(request: Request, code: str = Form(...)):
    claims = AUTH_CODES.pop(code, None)
    if not claims:
        return JSONResponse(status_code=400, content={"error": "invalid_grant"})

    now = int(time.time())
    payload = {
        "iss": "https://jwt.knollfear.com/idp/oidc",
        "aud": "my-keycloak-client",
        "iat": now,
        "exp": now + 3600,
        "sub": claims.get("sub", "user-default")
    }
    payload.update(claims)

    # Sign using the PEM string and the explicit Header
    header = {'alg': 'RS256', 'kid': JWK_PUBLIC['kid']}

    # Use the PEM key directly for signing
    encoded_token = jwt.encode(header, payload, PRIVATE_KEY_PEM).decode('utf-8')

    return {
        "access_token": "mock-access-token",
        "id_token": encoded_token,
        "token_type": "Bearer",
        "expires_in": 3600
    }

@router.get("/persona-template", response_class=PlainTextResponse)
async def persona_template(persona: str = "default"):
    return json.dumps(PERSONAS.get(persona, PERSONAS['default']), indent=4)


@router.post("/{mode}/oidc/login-callback")
async def login_callback(
mode: str,
    persona_choice: str = Form(None),
    custom_claims: str = Form(None),
        redirect_uri: str = Form(...),
        state: str = Form(...),
        nonce: str = Form(None),  # <--- Receive the nonce

):
    if mode == "persona":
        # Use the static persona data only
        claims = PERSONAS.get(persona_choice, PERSONAS['default'])
    else:
        # Use the raw JSON from the textarea
        claims = json.loads(custom_claims)

    # If a nonce was provided, add it to the claims dictionary
    if nonce:
        claims["nonce"] = nonce

    code = str(uuid.uuid4())
    AUTH_CODES[code] = claims
    return RedirectResponse(url=f"{redirect_uri}?state={state}&code={code}", status_code=303)


@router.post("/token")
async def token(request: Request, code: str = Form(...)):
    claims = AUTH_CODES.pop(code, None)
    if not claims:
        return JSONResponse(status_code=400, content={"error": "invalid_grant"})

    now = int(time.time())
    payload = {
        "iss": "https://jwt.knollfear.com/idp/oidc",
        "aud": "my-keycloak-client",
        "iat": now,
        "exp": now + 3600,
    }
    # This will now include the 'nonce' if it was captured in the previous steps
    payload.update(claims)

    header = {'alg': 'RS256', 'kid': JWK_PUBLIC['kid']}
    token_bytes = jwt.encode(header, payload, PRIVATE_KEY_PEM)
    id_token = token_bytes.decode('utf-8') if isinstance(token_bytes, bytes) else token_bytes

    return {
        "access_token": "mock-access-token",
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 3600
    }