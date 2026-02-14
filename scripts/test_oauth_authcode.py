import argparse
import base64
import hashlib
import json
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import httpx


def _fail(message):
    print("ERROR: {}".format(message), file=sys.stderr)
    sys.exit(1)


def _try_json(text):
    try:
        return json.loads(text)
    except Exception:
        return None


def _ensure_parent_dir(path):
    path.parent.mkdir(parents=True, exist_ok=True)


def _build_pkce_pair():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).decode("ascii").rstrip("=")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def _extract_code_from_callback_url(callback_url):
    parsed = urlparse(callback_url.strip())
    query = parse_qs(parsed.query)
    code = (query.get("code") or [None])[0]
    state = (query.get("state") or [None])[0]
    error = (query.get("error") or [None])[0]
    error_description = (query.get("error_description") or [None])[0]
    return code, state, error, error_description


def _write_cache(path, data):
    _ensure_parent_dir(path)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")


def main():
    parser = argparse.ArgumentParser(description="Run OAuth Authorization Code + PKCE flow and cache tokens.")
    parser.add_argument("--base-url", default="http://127.0.0.1:5000", help="Server base URL")
    parser.add_argument("--client-id", required=True, help="Google OAuth client ID")
    parser.add_argument("--client-secret", default=None, help="Google OAuth client secret (optional)")
    parser.add_argument(
        "--redirect-uri",
        default="http://localhost/oauth2/callback",
        help="Registered OAuth redirect URI",
    )
    parser.add_argument(
        "--cache-file",
        default="tmp/oauth_cache.json",
        help="Path to token cache JSON file",
    )
    args = parser.parse_args()
    cache_path = Path(args.cache_file)
    _ensure_parent_dir(cache_path)

    base_url = args.base_url.rstrip("/")
    metadata_url = base_url + "/.well-known/oauth-authorization-server"

    with httpx.Client(timeout=20) as client:
        meta_resp = client.get(metadata_url)
        if meta_resp.status_code != 200:
            _fail("failed to fetch metadata: status={} body={}".format(meta_resp.status_code, meta_resp.text))
        meta = _try_json(meta_resp.text)
        if not isinstance(meta, dict):
            _fail("metadata is not JSON: {}".format(meta_resp.text))

        authorization_endpoint = meta.get("authorization_endpoint")
        token_endpoint = meta.get("token_endpoint")
        if not authorization_endpoint or not token_endpoint:
            _fail("authorization_endpoint/token_endpoint missing in metadata")

        scopes_supported = meta.get("scopes_supported") or []
        scopes = " ".join(scopes_supported)
        if not scopes:
            _fail("OAuth scopes are empty. scopes_supported was not provided by MCP server metadata")

        state = secrets.token_urlsafe(24)
        code_verifier, code_challenge = _build_pkce_pair()

        query = {
            "client_id": args.client_id,
            "redirect_uri": args.redirect_uri,
            "response_type": "code",
            "scope": scopes,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "access_type": "offline",
            "prompt": "consent",
        }
        authorize_url = authorization_endpoint + "?" + urlencode(query)

        print("\n1) Open this URL in your browser and complete consent:\n")
        print(authorize_url)
        print("\n2) After redirect, copy the FULL callback URL and paste it here.")
        callback_url = input("callback URL> ").strip()
        if not callback_url:
            _fail("callback URL is empty")

        code, returned_state, oauth_error, oauth_error_description = _extract_code_from_callback_url(callback_url)
        if oauth_error:
            _fail("oauth error: {} {}".format(oauth_error, oauth_error_description or ""))
        if not code:
            _fail("authorization code not found in callback URL")
        if returned_state != state:
            _fail("state mismatch")

        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": args.client_id,
            "redirect_uri": args.redirect_uri,
            "code_verifier": code_verifier,
        }
        if args.client_secret:
            token_data["client_secret"] = args.client_secret

        token_resp = client.post(token_endpoint, data=token_data)
        token_json = _try_json(token_resp.text)
        if token_resp.status_code != 200 or not isinstance(token_json, dict):
            _fail("token exchange failed: status={} body={}".format(token_resp.status_code, token_resp.text))

        access_token = token_json.get("access_token")
        refresh_token = token_json.get("refresh_token")
        expires_in = token_json.get("expires_in")
        token_scope = token_json.get("scope")
        token_type = token_json.get("token_type")

        if not access_token:
            _fail("access_token missing in token response: {}".format(token_resp.text))

        cache = {
            "base_url": base_url,
            "authorization_endpoint": authorization_endpoint,
            "token_endpoint": token_endpoint,
            "client_id": args.client_id,
            "redirect_uri": args.redirect_uri,
            "scopes": token_scope or scopes,
            "token": {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": token_type,
                "expires_in": expires_in,
                "obtained_at_unix": int(time.time()),
            },
        }
        _write_cache(cache_path, cache)

        print("\nToken acquired successfully.")
        print("access_token:", access_token)
        print("refresh_token:", refresh_token or "(not returned)")
        print("expires_in:", expires_in)
        print("scope:", token_scope)
        print("\nWrote cache:", cache_path)
        print("Next: python scripts/test_auth.py --cache-file {}".format(cache_path))


if __name__ == "__main__":
    main()
