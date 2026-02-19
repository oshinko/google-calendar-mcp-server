import logging
import os
from datetime import datetime, timedelta
from urllib.parse import quote, urlencode

import httpx
from flask import Flask, Response, jsonify, redirect, request, send_from_directory

SUPPORTED_SCOPES = [
    "https://www.googleapis.com/auth/calendar.readonly",
    "offline_access"
]
DEFAULT_CALENDAR_ID = "primary"

GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_ISSUER = "https://accounts.google.com"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_EVENTS_ENDPOINT_TEMPLATE = "https://www.googleapis.com/calendar/v3/calendars/{calendar_id}/events"
GOOGLE_CALENDAR_LIST_ENDPOINT = "https://www.googleapis.com/calendar/v3/users/me/calendarList"

MCP_SERVER_NAME = "google-calendar-mcp-server"
MCP_SERVER_VERSION = "0.1.0"
MCP_PROTOCOL_VERSION = "2024-11-05"
TOOL_NAME_EVENTS = "google_calendar_events"
TOOL_NAME_CALENDAR_LIST = "google_calendar_list"

DEFAULT_RESOURCE = "http://127.0.0.1:5000"
DEFAULT_APP_HOST = "127.0.0.1"
DEFAULT_APP_PORT = "5000"
DEFAULT_APP_DEBUG = "true"
DEFAULT_ENABLE_AUTH_ENDPOINT_PROXY = "false"
DEFAULT_ENABLE_TOKEN_ENDPOINT_PROXY = "false"
OAUTH_AUTHORIZE_PROXY_PATH = "/oauth/authorize"
OAUTH_TOKEN_PROXY_PATH = "/oauth/token"
OAUTH_PROTECTED_RESOURCE_METADATA_PATH = "/.well-known/oauth-protected-resource"
APP_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

resource = os.getenv("RESOURCE", DEFAULT_RESOURCE)
app_host = os.getenv("APP_HOST", DEFAULT_APP_HOST)
app_port = int(os.getenv("APP_PORT", DEFAULT_APP_PORT))
app_debug = os.getenv("APP_DEBUG", DEFAULT_APP_DEBUG).lower() == "true"
enable_auth_endpoint_proxy = os.getenv("ENABLE_AUTH_ENDPOINT_PROXY", DEFAULT_ENABLE_AUTH_ENDPOINT_PROXY).lower() == "true"
enable_token_endpoint_proxy = os.getenv(
    "ENABLE_TOKEN_ENDPOINT_PROXY", DEFAULT_ENABLE_TOKEN_ENDPOINT_PROXY
).lower() == "true"
use_proxy_issuer = enable_auth_endpoint_proxy or enable_token_endpoint_proxy
oauth_server_issuer = resource.rstrip("/")
oauth_authorization_endpoint = oauth_server_issuer + OAUTH_AUTHORIZE_PROXY_PATH
oauth_token_endpoint = oauth_server_issuer + OAUTH_TOKEN_PROXY_PATH
oauth_protected_resource_metadata_endpoint = oauth_server_issuer + OAUTH_PROTECTED_RESOURCE_METADATA_PATH
tool_definitions = [
    {
        "name": TOOL_NAME_CALENDAR_LIST,
        "description": "List calendars the authenticated user can access.",
        "annotations": {
            "readOnlyHint": True,
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                "access_token": {
                    "type": "string",
                    "description": "Optional. If omitted, Authorization header Bearer token is used.",
                }
            },
            "additionalProperties": False,
        },
    },
    {
        "name": TOOL_NAME_EVENTS,
        "description": "Get Google Calendar events for a date or datetime range.",
        "annotations": {
            "readOnlyHint": True,
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                "access_token": {
                    "type": "string",
                    "description": "Optional. If omitted, Authorization header Bearer token is used.",
                },
                "calendar_id": {
                    "type": "string",
                    "description": "Optional. Target calendar ID. Defaults to primary.",
                },
                "date": {
                    "type": "string",
                    "description": "Optional. Date in YYYY-MM-DD. Fetches events for that local day.",
                },
                "time_min": {
                    "type": "string",
                    "description": "Optional. ISO-8601 datetime start. Must be used with time_max.",
                },
                "time_max": {
                    "type": "string",
                    "description": "Optional. ISO-8601 datetime end. Must be used with time_min.",
                },
            },
            "additionalProperties": False,
        },
    },
]

logger = logging.getLogger("google_calendar_mcp")
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.DEBUG if app_debug else logging.INFO)
else:
    logger.setLevel(logging.DEBUG if app_debug else logging.INFO)

app = Flask(__name__)


@app.get("/")
def index():
    """簡易的な稼働メッセージを返す。"""
    return jsonify({"message": "Google Calendar MCP server is running"})


@app.get("/health")
def health():
    """ヘルスチェック結果を返す。"""
    return jsonify({"status": "ok"})


@app.get("/favicon.svg")
def favicon_svg():
    return send_from_directory(APP_BASE_DIR, "favicon.svg", mimetype="image/svg+xml")


@app.get("/favicon.png")
def favicon_png():
    return send_from_directory(APP_BASE_DIR, "favicon.png", mimetype="image/png")


@app.get("/favicon.ico")
def favicon_ico():
    return send_from_directory(APP_BASE_DIR, "favicon.ico", mimetype="image/x-icon")


@app.get("/.well-known/oauth-authorization-server")
def oauth_authorization_server_metadata():
    """OAuth Authorization Server Metadata を返す。"""
    issuer = oauth_server_issuer if use_proxy_issuer else GOOGLE_ISSUER
    authorization_endpoint = oauth_authorization_endpoint if enable_auth_endpoint_proxy else GOOGLE_AUTH_ENDPOINT
    token_endpoint = oauth_token_endpoint if enable_token_endpoint_proxy else GOOGLE_TOKEN_ENDPOINT

    return jsonify(
        {
            "issuer": issuer,
            "authorization_endpoint": authorization_endpoint,
            "token_endpoint": token_endpoint,
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "scopes_supported": SUPPORTED_SCOPES,
        }
    )


@app.get(OAUTH_PROTECTED_RESOURCE_METADATA_PATH)
def oauth_protected_resource_metadata():
    """OAuth Protected Resource Metadata を返す。"""
    authorization_server = oauth_server_issuer if use_proxy_issuer else GOOGLE_ISSUER

    return jsonify(
        {
            "resource": resource,
            "authorization_servers": [authorization_server],
            "scopes_supported": SUPPORTED_SCOPES,
            "bearer_methods_supported": ["header"],
        }
    )


@app.get(OAUTH_AUTHORIZE_PROXY_PATH)
def oauth_authorize_proxy():
    """認可リクエストを Google の認可エンドポイントへ中継する。"""
    if not enable_auth_endpoint_proxy:
        return jsonify({"error": "disabled", "message": "ENABLE_AUTH_ENDPOINT_PROXY is false"}), 404

    params = request.args.to_dict(flat=False)

    # refresh_token が返らないときは prompt=consent を付けるとよく効く
    params["prompt"] = ["consent"]

    # offline_access を access_type=offline に置き換え
    raw_scopes = [y for x in params.get("scope", []) for y in x.split()]

    if "offline_access" in raw_scopes:
        # offline_access を除去
        scopes = [s for s in raw_scopes if s != "offline_access"]

        if scopes:
            params["scope"] = [" ".join(scopes)]
        else:
            params.pop("scope", None)  # scope が空になるなら消す

        params["access_type"] = ["offline"]  # access_type=offline を追加
        query_string = urlencode(params, doseq=True)
    else:
        query_string = request.query_string.decode("utf-8")

    if query_string:
        redirect_url = f"{GOOGLE_AUTH_ENDPOINT}?{query_string}"
    else:
        redirect_url = GOOGLE_AUTH_ENDPOINT

    logger.debug("oauth authorize proxy redirect=%s", redirect_url)
    return redirect(redirect_url, code=302)


@app.post(OAUTH_TOKEN_PROXY_PATH)
def oauth_token_proxy():
    """トークンリクエストを Google のトークンエンドポイントへ中継する。"""
    if not enable_token_endpoint_proxy:
        return jsonify({"error": "disabled", "message": "ENABLE_TOKEN_ENDPOINT_PROXY is false"}), 404

    outbound_headers = {}
    content_type = request.headers.get("Content-Type")
    if content_type:
        outbound_headers["Content-Type"] = content_type
    accept = request.headers.get("Accept")
    if accept:
        outbound_headers["Accept"] = accept

    form = request.form or {}

    logger.info(
        (
            "oauth token proxy request_summary "
            "content_type=%s "
            "grant_type=%s "
            "redirect_uri=%s "
            "scope=%s "
            "has_client_id=%s "
            "has_client_secret=%s "
            "has_code=%s "
            "has_code_verifier=%s "
            "has_refresh_token=%s"
        ),
        content_type,
        form.get("grant_type"),
        form.get("redirect_uri"),
        form.get("scope"),
        bool(form.get("client_id")),
        bool(form.get("client_secret")),
        bool(form.get("code")),
        bool(form.get("code_verifier")),
        bool(form.get("refresh_token")),
    )

    upstream_response = httpx.post(
        GOOGLE_TOKEN_ENDPOINT,
        data=form,
        headers=outbound_headers,
        timeout=30,
    )

    try:
        token_response = upstream_response.json()
    except ValueError:
        token_response = {}

    token_type = token_response.get("token_type")
    expires_in = token_response.get("expires_in")
    scope = token_response.get("scope")
    has_refresh_token = bool(token_response.get("refresh_token"))
    oauth_error = token_response.get("error")
    oauth_error_description = token_response.get("error_description")
    logger.info(
        (
            "oauth token proxy response_summary "
            "upstream_status=%s "
            "token_type=%s "
            "expires_in=%s "
            "scope=%s "
            "has_refresh_token=%s "
            "oauth_error=%s "
            "oauth_error_description=%s"
        ),
        upstream_response.status_code,
        token_type,
        expires_in,
        scope,
        has_refresh_token,
        oauth_error,
        oauth_error_description,
    )

    response = Response(upstream_response.content, status=upstream_response.status_code)
    for header_name in ("Content-Type", "Cache-Control", "Pragma", "WWW-Authenticate"):
        header_value = upstream_response.headers.get(header_name)
        if header_value:
            response.headers[header_name] = header_value

    return response


@app.post("/")
def mcp_endpoint():
    """MCP の JSON-RPC リクエストを処理する。"""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(_jsonrpc_error(None, -32700, "Invalid JSON-RPC payload")), 400

    method = payload.get("method")
    params = payload.get("params") or {}
    request_id = payload.get("id")

    logger.debug("id=%s", request_id)
    logger.debug("method=%s", method)

    if request_id is None and method == "notifications/initialized":
        return "", 204

    if method == "initialize":
        return _handle_initialize(request_id)
    if method == "tools/list":
        return _mcp_result_response(request_id, {"tools": tool_definitions})
    if method == "tools/call":
        return _handle_tools_call(request_id, params)

    return jsonify(_jsonrpc_error(request_id, -32601, "Method not found")), 404


def _handle_initialize(request_id):
    result = {
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {"tools": {}},
        "serverInfo": {
            "name": MCP_SERVER_NAME,
            "version": MCP_SERVER_VERSION,
        },
    }
    return _mcp_result_response(request_id, result)


def _handle_tools_call(request_id, params):
    tool_name = params.get("name")
    arguments = params.get("arguments") or {}
    logger.debug("tool=%s argument_keys=%s", tool_name, sorted(arguments.keys()))

    access_token = _extract_access_token(arguments)
    if not access_token:
        return _mcp_auth_required(request_id, "Missing access token")

    if tool_name == TOOL_NAME_CALENDAR_LIST:
        return _handle_tool_calendar_list(request_id, access_token)

    if tool_name == TOOL_NAME_EVENTS:
        return _handle_tool_events(request_id, access_token, arguments)

    return jsonify(_jsonrpc_error(request_id, -32602, "Unknown tool")), 400


def _handle_tool_calendar_list(request_id, access_token):
    calendars_resp = _fetch_calendar_list(access_token)
    if calendars_resp.get("error"):
        if _is_google_unauthorized(calendars_resp):
            return _mcp_auth_required(request_id, "Invalid or expired access token")
        return _mcp_tool_error(request_id, "Google API error: {}".format(calendars_resp["error"]), status=502)

    result = {
        "content": [{"type": "text", "text": _format_calendar_list_text(calendars_resp)}],
        "structuredContent": _build_calendar_list_structured_content(calendars_resp),
    }
    logger.debug("google_calendar_list succeeded")
    return _mcp_result_response(request_id, result)


def _handle_tool_events(request_id, access_token, arguments):
    time_range = _resolve_time_range(arguments)
    if time_range.get("error"):
        return _mcp_tool_error(request_id, time_range["error"], status=400)

    calendar_id = _resolve_calendar_id(arguments)
    events_resp = _fetch_events(access_token, calendar_id, time_range["time_min"], time_range["time_max"])
    if events_resp.get("error"):
        if _is_google_unauthorized(events_resp):
            return _mcp_auth_required(request_id, "Invalid or expired access token")
        return _mcp_tool_error(request_id, "Google API error: {}".format(events_resp["error"]), status=502)

    result = {
        "content": [
            {
                "type": "text",
                "text": _format_events_text(events_resp, time_range["label"], calendar_id),
            }
        ],
        "structuredContent": _build_events_structured_content(events_resp, time_range, calendar_id),
    }
    logger.debug("google_calendar_events succeeded")
    return _mcp_result_response(request_id, result)


def _extract_access_token(arguments):
    access_token = arguments.get("access_token")
    if access_token:
        return access_token

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header.replace("Bearer ", "", 1).strip()
    return None


def _mcp_result_response(request_id, result):
    return jsonify(_jsonrpc_result(request_id, result))


def _is_google_unauthorized(response_obj):
    error = response_obj.get("error") if isinstance(response_obj, dict) else None
    if not isinstance(error, dict):
        return False
    return error.get("status_code") == 401


def _mcp_auth_required(request_id, message):
    result = {
        "isError": True,
        "content": [{"type": "text", "text": message}],
    }
    response = _mcp_result_response(request_id, result)
    response.status_code = 401
    response.headers["WWW-Authenticate"] = _build_www_authenticate_header()
    return response


def _build_www_authenticate_header():
    scope_value = " ".join(SUPPORTED_SCOPES)
    return "Bearer resource_metadata=\"{}\", scope=\"{}\"".format(
        oauth_protected_resource_metadata_endpoint, scope_value
    )


def _mcp_tool_error(request_id, message, status=400):
    result = {
        "isError": True,
        "content": [{"type": "text", "text": message}],
    }
    return _mcp_result_response(request_id, result), status


def _jsonrpc_result(request_id, result):
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _jsonrpc_error(request_id, code, message):
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _format_events_text(events_resp, label, calendar_id):
    lines = ["Events for {} (calendar: {}):".format(label, calendar_id)]
    items = events_resp.get("items", []) or []
    lines.append("count: {}".format(len(items)))
    for event in items:
        start = _event_start_for_display(event)
        summary = event.get("summary") or "(no title)"
        description = (event.get("description") or "").strip()
        lines.append("- {} {}".format(start, summary))
        if description:
            lines.append("  description: {}".format(description))
    return "\n".join(lines)


def _format_calendar_list_text(calendars_resp):
    items = calendars_resp.get("items", []) or []
    lines = ["Available calendars:", "count: {}".format(len(items))]
    for calendar in items:
        summary = calendar.get("summary") or "(no title)"
        calendar_id = calendar.get("id") or "(no id)"
        lines.append("- {} ({})".format(summary, calendar_id))
    return "\n".join(lines)


def _build_events_structured_content(events_resp, time_range, calendar_id):
    items = events_resp.get("items", []) or []
    events = []
    for event in items:
        start_obj = event.get("start") or {}
        end_obj = event.get("end") or {}
        events.append(
            {
                "id": event.get("id"),
                "status": event.get("status"),
                "summary": event.get("summary") or "(no title)",
                "description": event.get("description"),
                "start": _event_start_for_display(event),
                "startDateTime": start_obj.get("dateTime"),
                "startDate": start_obj.get("date"),
                "endDateTime": end_obj.get("dateTime"),
                "endDate": end_obj.get("date"),
                "isRecurring": bool(event.get("recurringEventId")),
                "recurringEventId": event.get("recurringEventId"),
                "htmlLink": event.get("htmlLink"),
            }
        )

    return {
        "calendarId": calendar_id,
        "range": {
            "label": time_range.get("label"),
            "timeMin": time_range.get("time_min"),
            "timeMax": time_range.get("time_max"),
        },
        "count": len(events),
        "events": events,
    }


def _build_calendar_list_structured_content(calendars_resp):
    items = calendars_resp.get("items", []) or []
    calendars = []
    for item in items:
        calendars.append(
            {
                "id": item.get("id"),
                "summary": item.get("summary"),
                "description": item.get("description"),
                "timeZone": item.get("timeZone"),
                "primary": bool(item.get("primary")),
                "accessRole": item.get("accessRole"),
                "selected": bool(item.get("selected")),
            }
        )

    return {
        "count": len(calendars),
        "calendars": calendars,
    }


def _event_start_for_display(event):
    # For recurring instances, Google returns originalStartTime for the specific occurrence.
    original_start = event.get("originalStartTime") or {}
    start = event.get("start") or {}
    return (
        original_start.get("dateTime")
        or original_start.get("date")
        or start.get("dateTime")
        or start.get("date")
        or "(unknown start)"
    )


def _resolve_calendar_id(arguments):
    calendar_id = (arguments.get("calendar_id") or "").strip()
    return calendar_id or DEFAULT_CALENDAR_ID


def _resolve_time_range(arguments):
    time_min_raw = arguments.get("time_min")
    time_max_raw = arguments.get("time_max")
    date_raw = arguments.get("date")

    if (time_min_raw and not time_max_raw) or (time_max_raw and not time_min_raw):
        return {"error": "time_min and time_max must be provided together"}

    if time_min_raw and time_max_raw:
        try:
            time_min_dt = _parse_iso_datetime(time_min_raw)
            time_max_dt = _parse_iso_datetime(time_max_raw)
        except ValueError:
            return {"error": "time_min/time_max must be valid ISO-8601 datetimes"}
        if time_min_dt >= time_max_dt:
            return {"error": "time_min must be before time_max"}
        return {
            "time_min": time_min_dt.isoformat(),
            "time_max": time_max_dt.isoformat(),
            "label": "{} to {}".format(time_min_dt.isoformat(), time_max_dt.isoformat()),
        }

    if date_raw:
        try:
            start, end = _day_range_for_date(date_raw)
        except ValueError:
            return {"error": "date must be in YYYY-MM-DD format"}
        return {"time_min": start.isoformat(), "time_max": end.isoformat(), "label": date_raw}

    start, end = _today_range()
    return {"time_min": start, "time_max": end, "label": "today"}


def _parse_iso_datetime(value):
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        local_tz = datetime.now().astimezone().tzinfo
        dt = dt.replace(tzinfo=local_tz)
    return dt


def _day_range_for_date(date_str):
    date_obj = datetime.strptime(date_str, "%Y-%m-%d").date()
    local_tz = datetime.now().astimezone().tzinfo
    start = datetime(date_obj.year, date_obj.month, date_obj.day, tzinfo=local_tz)
    end = start + timedelta(days=1)
    return start, end


def _today_range():
    now = datetime.now().astimezone()
    start = datetime(now.year, now.month, now.day, tzinfo=now.tzinfo)
    end = start + timedelta(days=1)
    return start.isoformat(), end.isoformat()


def _fetch_events(access_token, calendar_id, time_min, time_max):
    safe_calendar_id = quote(calendar_id, safe="")
    endpoint = GOOGLE_EVENTS_ENDPOINT_TEMPLATE.format(calendar_id=safe_calendar_id)
    headers = {"Authorization": "Bearer {}".format(access_token)}
    params = {
        "timeMin": time_min,
        "timeMax": time_max,
        "singleEvents": "true",
        "orderBy": "startTime",
        "maxResults": "50",
    }
    resp = httpx.get(endpoint, headers=headers, params=params, timeout=30)
    if not resp.is_success:
        return {"error": {"status_code": resp.status_code, "body": resp.text}}
    return resp.json()


def _fetch_calendar_list(access_token):
    headers = {"Authorization": "Bearer {}".format(access_token)}
    params = {
        "maxResults": "250",
        "showHidden": "false",
        "showDeleted": "false",
    }
    resp = httpx.get(GOOGLE_CALENDAR_LIST_ENDPOINT, headers=headers, params=params, timeout=30)
    if not resp.is_success:
        return {"error": {"status_code": resp.status_code, "body": resp.text}}
    return resp.json()


if __name__ == "__main__":
    app.run(host=app_host, port=app_port, debug=app_debug)
