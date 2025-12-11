---
title: FastAPI
description: A FastAPI server
tags:
  - fastapi
  - hypercorn
  - python
---
🟣 The JWT Experience

A simple, transparent, developer-friendly approach to session management using raw JWTs.

This repository illustrates a clean and effective pattern for managing user sessions using raw JSON Web Tokens (JWTs). The goal is to walk a fine line between practical security and excellent developer experience while keeping the implementation easy to understand, debug, and extend.

Instead of relying on opaque token stores or heavyweight authentication frameworks, The JWT Experience leans into the strengths of JWTs:

Claims are readable and inspectable

Endpoints can explicitly declare their required permissions

No server-side session storage is needed

Token verification is fast and stateless

The system remains transparent and predictable for developers

If you want to understand JWTs, build with them, or extend them into your own services, this repo provides a straightforward blueprint.

🔍 What is a JWT?

A JWT (JSON Web Token) is a compact, URL-safe token format that contains a JSON payload and a cryptographic signature.
For a full explanation of JWTs, visit https://jwt.io

.

Briefly summarized:

The payload is readable JSON that contains claims — statements about the user or the session.

The token is signed, which means it cannot be altered without detection.

If the payload and computed signature do not match, the token is invalid.

Symmetric (HMAC) Signing

With symmetric signing (e.g., HS256), the same secret key is used to sign and validate the token.

In a secure design, this secret should never be shared.

Only the issuer should possess it.

This effectively means only the issuer can validate tokens, because sharing the secret would expand the trust boundary and is considered an anti-pattern.

Asymmetric Signing (Public/Private Keys)

JWTs can also be signed using public/private key algorithms such as RS256 or ES256.

The issuer signs with a private key

Any service can verify using the public key

This allows distributed verification without sharing secrets.

🎯 Design Philosophy

The JWT Experience aims to be:

Transparent — Claims are visible and understandable directly from the token.

Minimalistic — No frameworks, no session stores, no complexity.

Extensible — Easy to add new claim types, roles, or authorization logic.

Practical — A sweet spot between security and ease of development.

Declarative — Endpoints explicitly declare their required claims, making the code self-documenting.

It is intentionally not a full identity provider — it is a reference pattern for small to medium projects, internal tools, or developers learning how stateless authentication works.

🔐 Access Token Lifetime

JWT access tokens can be valid for any duration you choose. When deciding token validity, you must balance:

User convenience (how often they must re-authenticate)

Security considerations (impact of a stolen token)

JWTs are cryptographically secure when signed and managed correctly.
However, any token stored on a user’s device can be stolen:

through physical access

through malware

through XSS

via insecure storage mechanisms

The primary defense against misuse of a stolen token is limiting how long it remains valid.
Short-lived access tokens dramatically reduce the window of exposure and are considered best practice.

🧾 Claim-Based Authorization

Endpoints in this repo explicitly declare the claims they require. Claims are intended to be:

simple, readable JSON fields

easy to audit

easy to reason about

Role-based permissions can be implemented trivially by:

replacing claims with a role system, or

layering roles on top of claims

The authorization model is intentionally small and digestible.

🔁 Request Flow Overview

A typical request cycle looks like this:

User authenticates and receives a JWT.

The client stores the token (storage method depends on app design).

For each protected route, the client sends
Authorization: Bearer <token>

The server:

verifies the signature

checks expiration

verifies required claims

The server responds with:

200 OK if authorized

401 Unauthorized if no valid token

403 Forbidden if token is valid but missing required claims

This flow is intentionally explicit and easy to trace.

🛠 Debugging Tokens

One of the main benefits of using transparent JWTs is how easy they are to debug.

You can paste any token into:

👉 https://jwt.io

This will immediately show:

the header

the payload claims

the signature algorithm

validation status

This visibility is invaluable during development and makes it easy to inspect or diagnose authentication issues.

🚧 Limitations & Non-Goals

To keep things focused, this repository does not attempt to implement:

refresh tokens or rotation strategies

single sign-on (SSO)

revocation lists

CSRF protection (unless you choose cookie-based storage)

OAuth/OIDC flows

multi-factor authentication

If you need, or even think you might need any of these then the JWT experience might not be right for your project.



[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/-NvLj4?referralCode=CRJ8FE)
## ✨ Features

- FastAPI
- [Hypercorn](https://hypercorn.readthedocs.io/)
- Python 3

## 💁‍♀️ How to use

- Clone locally and install packages with pip using `pip install -r requirements.txt`
- Run locally using `hypercorn main:app --reload`

## 📝 Notes

- To learn about how to use FastAPI with most of its features, you can visit the [FastAPI Documentation](https://fastapi.tiangolo.com/tutorial/)
- To learn about Hypercorn and how to configure it, read their [Documentation](https://hypercorn.readthedocs.io/)
