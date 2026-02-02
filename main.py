# main.py
from datetime import datetime, timedelta
from urllib.parse import urlparse

from Services.email import send_mail
from decorators import claim_required

import requests
from botocore.exceptions import ClientError
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from typing import List, Optional
import boto3
import os
import uuid
import resend
import jwt
from idp_router import router as idp_router
from middleware import JWTAuthMiddleware

resend.api_key = os.environ.get("RESEND_API_KEY")
ACCESS_KEY_ID= os.environ.get('AWS_ACCESS_KEY_ID')
SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
BUCKET_NAME = os.environ.get('AWS_S3_BUCKET_NAME')
ENDPOINT_URL = os.environ.get('AWS_ENDPOINT_URL')
S3_BASE = "https://storage.railway.app/optimized-eclair-jtgu25gw"
APP_URL = os.environ.get("RAILWAY_PUBLIC_DOMAIN")
RAILWAY_ENVIRONMENT_NAME = os.environ.get("RAILWAY_ENVIRONMENT_NAME")
SECRET_KEY =  os.environ.get("SECRET_KEY", "your_super_secret_key") # load from env in real life
ALGORITHM = "HS256"


s3_client = boto3.client('s3', endpoint_url=ENDPOINT_URL, aws_access_key_id=ACCESS_KEY_ID, aws_secret_access_key=SECRET_ACCESS_KEY)

app = FastAPI()
app.add_middleware(JWTAuthMiddleware)

templates = Jinja2Templates(directory="templates")

app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(idp_router, prefix="/idp/oidc", tags=["MockIdP"])
@app.get("/", response_class=HTMLResponse)
async def show_signup(request: Request, message: Optional[str] = None):
    if request.state.token_payload is not None:
        redirect_url = "/logged-in"  # your logged-in homepage
        response = RedirectResponse(url=redirect_url, status_code=302)
        return response

    msg = request.query_params.get("msg")
    need = request.query_params.get("need")

    alert = None
    if msg == "missing_claim" and need:
        alert = f"You were redirected because you do not have the '{need}' permission."
    elif msg == "missing_token":
        alert = "You must be logged in to view that page."

    # Example permissions
    available_permissions = [
        ("read_foo", "Read /foo"),
        ("write_foo", "Write /foo"),
        ("read_bar", "Read /bar"),
        ("write_bar", "Write /bar"),
    ]
    return templates.TemplateResponse(
        "signup.html",
        {
            "request": request,
            "message": alert,
            "available_permissions": available_permissions,
        },
    )


@app.post("/request-login", response_class=HTMLResponse)
async def request_login(
    request: Request,
    email: str = Form(...),
    expire_in: int = Form(...),
    permissions: List[str] = Form([]),  # multiple checkbox values
):
    """
    Handle the form submission:
    - Generate UUID
    - Generate JWT and upload to S3 as <UUID>.jwt
    - Send email via Resend with signed link containing UUID
    """

    request_id = str(uuid.uuid4())
    permissions.append("read_loggedIn") # always give this permission
    payload = {
        "user_id": request_id,
        "username": email,
        "exp": datetime.now() + timedelta(minutes=expire_in),  # Expiration time (1 hour from now)
        "permissions": ",".join(permissions),
    }

    encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


    object_key = f"{request_id}.jwt"

    try:
        # 2. Upload the signed JWT to S3
        s3_client.put_object(
            Bucket=BUCKET_NAME,
            Key=object_key,
            Body=encoded_jwt.encode("utf-8"),  # bytes
            ContentType="application/jwt",  # optional but nice
            Expires=datetime.now() + timedelta(minutes=5), # 5 minutes for E-mail verification
        )
    except ClientError as e:
        # Log and handle the error however you like
        # For a POC you can just raise HTTPException
        print("Error uploading JWT to S3:", e)
        raise HTTPException(status_code=500, detail="Failed to store login token")



    try:
        presigned = s3_client.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": BUCKET_NAME,
                "Key": object_key,
            },
            ExpiresIn=60*5,  # seconds
        )
    except ClientError as e:
        print("Error creating presigned URL:", e)
        raise

    # We only need the query string part (all the X-Amz-* params, etc.)
    parsed = urlparse(presigned)
    query_string = parsed.query  # e.g. "X-Amz-Algorithm=...&X-Amz-Credential=...&..."

    # Build the link we email to the user:
    login_link_path = f"/jwt/{request_id}.jwt?{query_string}"
    login_link = APP_URL + login_link_path

    body = f"""
    <div>
        <div>Thanks for Joining the JWT experience.</div>
        <div><a href="{login_link}">Click Here</a></div>
        <div>to retrieve your login token.</div>

    </div>
    """
    send_mail([email,], "Welcome to the JWT Experience", body)

    # Simple confirmation message for the user
    message = (
        f"If {email} is valid, we’ve sent a sign-in link. "
        f"Requested permissions: {', '.join(permissions) or 'none'}"
    )

    return templates.TemplateResponse(
        "thankyou.html",
        {"request": request,},
    )

@app.get("/jwt/{request_id}.jwt")
async def proxy_jwt(request_id: str, request: Request):
    # 1. Grab the query string (all the presigned URL params)
    query_string = request.url.query
    if not query_string:
        raise HTTPException(status_code=403, detail="Missing S3 signature parameters")

    # 2. Reconstruct the exact S3 URL we want to call
    object_key = f"{request_id}.jwt"
    s3_url = f"{S3_BASE}/{object_key}?{query_string}"

    # 3. Call S3 with that URL
    try:
        s3_response = requests.get(s3_url, timeout=5)
    except requests.RequestException as e:
        print("Error contacting S3:", e)
        raise HTTPException(status_code=502, detail="Error contacting storage")

    if s3_response.status_code != 200:
        # S3 will return 403/400/etc if the signature is invalid or expired
        raise HTTPException(status_code=403, detail="Invalid or expired login link")

    jwt_token = s3_response.content.decode("utf-8")

    # 4. Set cookie and redirect to logged-in page
    redirect_url = "/logged-in"  # your logged-in homepage
    response = RedirectResponse(url=redirect_url, status_code=302)

    response.set_cookie(
        key="auth_token",
        value=jwt_token,
        httponly=RAILWAY_ENVIRONMENT_NAME == "production",
        secure=RAILWAY_ENVIRONMENT_NAME == "production",       # only over HTTPS in real environments
        samesite="lax",
        path="/",
        max_age=60 * 60,   # todo, match this up to the token claim
    )

    return response

@app.get("/logged-in", response_class=HTMLResponse)
@claim_required("read_loggedIn")
async def logged_in(request: Request):
    return templates.TemplateResponse(
        "loggedIn.html",
        {"request": request,},
    )

@app.get("/logged-in/claim/{op}/{entity}", response_class=HTMLResponse)
@claim_required("{op}_{entity}")
async def logged_in(op:str, entity:str, request: Request):
    required_claim = f"{op}_{entity}"
    payload = getattr(request.state, "token_payload", {}) or {}
    permissions = payload.get("permissions", []) or []
    email = payload.get("sub")

    return templates.TemplateResponse(
        "claim_page.html",
        {
            "request": request,
            "op": op,
            "entity": entity,
            "required_claim": required_claim,
            "permissions": permissions,
            "email": email,
        },
    )

@app.get("/logged-in/showToken", response_class=HTMLResponse)
@claim_required("loggedIn")
async def logged_in(request: Request):
    payload = request.cookies.get('auth_token')

    return HTMLResponse(
        f"""
        <div id=hideToken>
         <button hx-get="/logged-in/hideToken" hx-target="#hideToken" swap="outerHTML">Hide my token</button>
         <code>{payload}</code>
         </div>"""
    )

@app.get("/logged-in/hideToken", response_class=HTMLResponse)
@claim_required("loggedIn")
async def logged_in(request: Request):

    return HTMLResponse(
        f"""
        <div id=showToken></div>"""
    )

@app.get("/logout", response_class=HTMLResponse)
@claim_required("loggedIn")
async def logged_in(request: Request):
    redirect_url = "/"  # your logged-in homepage
    response = RedirectResponse(url=redirect_url, status_code=302)

    response.set_cookie(
        key="auth_token",
        value="",
        httponly=RAILWAY_ENVIRONMENT_NAME == "production",
        secure=RAILWAY_ENVIRONMENT_NAME == "production",       # only over HTTPS in real environments
        samesite="lax",
        path="/",
        max_age=60 * 60,   # todo, match this up to the token claim
    )

    return response

