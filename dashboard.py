"""Admin dashboard for the Browser Extension Security Analyzer.

Run with ``streamlit run dashboard.py``. The backend is expected at
``API_BASE_URL`` (default: http://localhost:8000/monitor). Each viewer signs in with
an administrator password and an authenticator-app code. The backend issues a
short-lived bearer session after both steps succeed.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any

import altair as alt
import httpx
import streamlit as st


API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000/monitor").strip().rstrip("/")
TIMEOUT_SECONDS = 12.0
SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Informational", "Unknown")
SESSION_TOKEN_KEY = "admin_session_token"
SESSION_EXPIRES_KEY = "admin_session_expires_at"
CHALLENGE_TOKEN_KEY = "admin_challenge_token"
CHALLENGE_EXPIRES_KEY = "admin_challenge_expires_at"


def _expires_at(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _expired(value: Any) -> bool:
    expires = _expires_at(value)
    return expires is None or datetime.now(timezone.utc) >= expires


def _clear_challenge() -> None:
    st.session_state.pop(CHALLENGE_TOKEN_KEY, None)
    st.session_state.pop(CHALLENGE_EXPIRES_KEY, None)


def _clear_session() -> None:
    st.session_state.pop(SESSION_TOKEN_KEY, None)
    st.session_state.pop(SESSION_EXPIRES_KEY, None)


def _auth_post(path: str, payload: dict[str, str] | None = None, token: str | None = None) -> httpx.Response | None:
    headers = {"Authorization": f"Bearer {token}"} if token else None
    try:
        return httpx.post(
            f"{API_BASE_URL}{path}",
            json=payload,
            headers=headers,
            timeout=TIMEOUT_SECONDS,
        )
    except httpx.RequestError:
        st.sidebar.error("The dashboard could not reach the backend. Check that the API is running.")
        return None


def _auth_payload(response: httpx.Response, token_field: str) -> tuple[str, str] | None:
    try:
        payload = response.json()
    except ValueError:
        payload = None
    if not isinstance(payload, dict):
        st.sidebar.error("The backend returned an invalid sign-in response.")
        return None
    token = payload.get(token_field)
    expires_at = payload.get("expires_at")
    if not isinstance(token, str) or not token or _expired(expires_at):
        st.sidebar.error("The backend returned an invalid or expired sign-in response.")
        return None
    return token, expires_at


def admin_sign_in() -> str | None:
    """Guide each dashboard viewer through password and TOTP authentication."""
    token = st.session_state.get(SESSION_TOKEN_KEY)
    if token and _expired(st.session_state.get(SESSION_EXPIRES_KEY)):
        _clear_session()
        token = None
        st.sidebar.warning("Your administrator session expired. Please sign in again.")
    if token:
        st.sidebar.success("Signed in with two-factor authentication")
        if st.sidebar.button("Sign out", key="admin_sign_out"):
            response = _auth_post("/api/admin/logout", token=token)
            _clear_session()
            _clear_challenge()
            if response is None or response.status_code >= 500:
                st.sidebar.warning("The backend could not confirm sign-out. The session may remain active until it expires.")
            return None
        return token

    challenge = st.session_state.get(CHALLENGE_TOKEN_KEY)
    if challenge and _expired(st.session_state.get(CHALLENGE_EXPIRES_KEY)):
        _clear_challenge()
        challenge = None
        st.sidebar.warning("The sign-in code step expired. Enter your password again.")

    st.sidebar.subheader("Administrator sign-in")
    if challenge:
        st.sidebar.caption("Step 2 of 2 · Enter the six-digit code from your authenticator app.")
        with st.sidebar.form("admin_totp_form", clear_on_submit=True):
            code = st.text_input("One-time code", type="password", max_chars=6, autocomplete="one-time-code")
            verify = st.form_submit_button("Verify and sign in")
        if st.sidebar.button("Start sign-in again", key="admin_restart_sign_in"):
            _clear_challenge()
            st.rerun()
        if verify:
            response = _auth_post(
                "/api/admin/verify",
                {"challenge_token": challenge, "totp_code": code.strip()},
            )
            if response is not None:
                if response.status_code in (401, 403, 422):
                    _clear_challenge()
                    st.sidebar.error("The code was invalid or expired. Sign in again to request a new code step.")
                elif response.status_code == 429:
                    _clear_challenge()
                    st.sidebar.error("Too many sign-in attempts. Please try again later.")
                elif response.is_error:
                    st.sidebar.error(f"Sign-in failed with HTTP {response.status_code}.")
                else:
                    issued = _auth_payload(response, "access_token")
                    if issued is not None:
                        st.session_state[SESSION_TOKEN_KEY] = issued[0]
                        st.session_state[SESSION_EXPIRES_KEY] = issued[1]
                        _clear_challenge()
                        st.rerun()
        return None

    st.sidebar.caption("Step 1 of 2 · Enter your administrator credentials.")
    with st.sidebar.form("admin_password_form", clear_on_submit=True):
        username = st.text_input("Username", autocomplete="username")
        password = st.text_input("Password", type="password", autocomplete="current-password")
        begin = st.form_submit_button("Continue")
    if begin:
        response = _auth_post("/api/admin/login", {"username": username.strip(), "password": password})
        if response is not None:
            if response.status_code in (401, 403, 422):
                st.sidebar.error("The username or password was not accepted.")
            elif response.status_code == 429:
                st.sidebar.error("Too many sign-in attempts. Please try again later.")
            elif response.is_error:
                st.sidebar.error(f"Sign-in failed with HTTP {response.status_code}.")
            else:
                issued = _auth_payload(response, "challenge_token")
                if issued is not None:
                    st.session_state[CHALLENGE_TOKEN_KEY] = issued[0]
                    st.session_state[CHALLENGE_EXPIRES_KEY] = issued[1]
                    st.rerun()
    return None


def display(value: Any) -> str:
    """Show absent API values as Unknown without hiding meaningful zeroes."""
    if value is None or value == "":
        return "Unknown"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (list, tuple)):
        return ", ".join(display(item) for item in value) or "Unknown"
    return str(value)


def severity(value: Any) -> str:
    label = display(value)
    if label == "Unknown":
        return label
    return label.capitalize()


def severity_choices(items: list[dict[str, Any]], field: str) -> list[str]:
    present = {severity(item.get(field)) for item in items}
    ordered = [label for label in SEVERITY_ORDER if label in present]
    ordered.extend(sorted(label for label in present if label not in ordered))
    return ordered


def count(value: Any) -> int | str:
    if isinstance(value, bool):
        return "Unknown"
    try:
        number = int(value)
    except (TypeError, ValueError):
        return "Unknown"
    return number if number >= 0 else "Unknown"


def records(value: Any) -> list[dict[str, Any]]:
    """Keep valid records and make malformed data visible to administrators."""
    if not isinstance(value, list):
        return []
    valid = [item for item in value if isinstance(item, dict)]
    if len(valid) != len(value):
        st.warning("Some records could not be displayed because the backend returned invalid data.")
    return valid


def fetch(path: str, token: str, expected: type) -> Any | None:
    try:
        response = httpx.get(
            f"{API_BASE_URL}{path}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=TIMEOUT_SECONDS,
        )
    except httpx.RequestError:
        st.error("The dashboard could not reach the backend. Check that the API is running.")
        return None

    if response.status_code in (401, 403):
        _clear_session()
        st.error("Your administrator session was denied or expired. Please sign in again.")
        return None
    if response.is_error:
        st.error(f"The backend returned HTTP {response.status_code} for this view.")
        return None

    try:
        payload = response.json()
    except ValueError:
        st.error("The backend returned an invalid response for this view.")
        return None
    if not isinstance(payload, expected):
        st.error("The backend returned an unexpected data format for this view.")
        return None
    return payload


def post_admin(path: str, token: str, payload: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Submit an administrator change using the verified backend session."""
    timeout = 90.0 if path.endswith("/generate") else 30.0 if path.endswith("/send") else TIMEOUT_SECONDS
    try:
        response = httpx.post(
            f"{API_BASE_URL}{path}",
            headers={"Authorization": f"Bearer {token}"},
            json=payload,
            timeout=timeout,
        )
    except httpx.RequestError:
        st.error("The dashboard could not reach the backend. Check that the API is running.")
        return None
    if response.status_code in (401, 403):
        _clear_session()
        st.error("Your administrator session was denied or expired. Please sign in again.")
        return None
    if response.is_error:
        try:
            detail = response.json().get("detail")
        except (ValueError, AttributeError):
            detail = None
        if isinstance(detail, str) and detail:
            st.error(f"Change was not saved: {detail}")
        else:
            st.error(f"Change was not saved. The backend returned HTTP {response.status_code}.")
        return None
    try:
        result = response.json()
    except ValueError:
        st.error("The backend returned an invalid response after the change.")
        return None
    if not isinstance(result, dict):
        st.error("The backend returned an unexpected response after the change.")
        return None
    return result


def severity_filter(items: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    choices = severity_choices(items, "severity")
    selected = st.selectbox("Severity", ["All", *choices], key=key)
    if selected == "All":
        return items
    return [item for item in items if severity(item.get("severity")) == selected]


def highest_severity_filter(items: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    choices = severity_choices(items, "highest_severity")
    selected = st.selectbox("Highest severity", ["All", *choices], key=key)
    if selected == "All":
        return items
    return [item for item in items if severity(item.get("highest_severity")) == selected]


def search_filter(items: list[dict[str, Any]], fields: tuple[str, ...], key: str) -> list[dict[str, Any]]:
    query = st.text_input("Search", key=key, placeholder="Search this view").strip().casefold()
    if not query:
        return items
    return [
        item
        for item in items
        if any(query in display(item.get(field)).casefold() for field in fields)
    ]


def show_table(rows: list[dict[str, Any]], empty_message: str) -> None:
    if rows:
        st.dataframe(rows, hide_index=True, use_container_width=True)
    else:
        st.info(empty_message)


def show_event_table(items: list[dict[str, Any]]) -> None:
    rows = [
        {
            "Time": display(item.get("created_at")),
            "Event": display(item.get("event_type")),
            "Severity": severity(item.get("severity")),
            "Score": display(item.get("score")),
            "Completeness": display(item.get("completeness")),
            "Message": display(item.get("message")),
            "Device ID": display(item.get("device_id")),
            "Scan ID": display(item.get("scan_id")),
            "Event ID": display(item.get("id")),
        }
        for item in items
    ]
    show_table(rows, "No security events are available for this selection.")


def show_severity_counts(data: dict[str, Any]) -> None:
    raw_counts = data.get("severity_counts")
    if isinstance(raw_counts, dict) and raw_counts:
        normalized = {severity(key): count(value) for key, value in raw_counts.items()}
        ordered = [item for item in SEVERITY_ORDER if item in normalized]
        ordered.extend(sorted(item for item in normalized if item not in ordered))
        columns = st.columns(min(len(ordered), 6))
        for index, label in enumerate(ordered):
            columns[index % len(columns)].metric(label, normalized[label])
    else:
        st.info("Severity totals are unavailable.")


def show_overview(token: str) -> None:
    st.header("Overview")
    data = fetch("/api/overview", token, dict)
    if data is None:
        return

    first = st.columns(3)
    first[0].metric("Total scans", count(data.get("total_scans")))
    first[1].metric("High-risk scans", count(data.get("high_risk")))
    first[2].metric("Open alerts", count(data.get("open_alerts")))
    second = st.columns(2)
    second[0].metric("Devices", count(data.get("devices")))
    second[1].metric("Extensions", count(data.get("extensions")))

    st.subheader("Risk severity")
    show_severity_counts(data)

    st.subheader("Recent security events")
    recent_events = data.get("recent_events")
    if isinstance(recent_events, list):
        show_event_table(records(recent_events))
    else:
        st.info("Recent security events are unavailable.")


def show_risk_levels(token: str) -> None:
    st.header("Risk levels")
    st.caption("The score adds confirmed findings, up to 100. Checks that could not finish remain Unknown.")
    overview = fetch("/api/overview", token, dict)
    if overview is not None:
        st.metric("High-risk scans", count(overview.get("high_risk")))
        st.subheader("Severity distribution")
        show_severity_counts(overview)
        raw_counts = overview.get("severity_counts", {})
        if isinstance(raw_counts, dict):
            chart_data = [
                {"Severity": label, "Scans": count(raw_counts.get(label, 0))}
                for label in ("Low", "Medium", "High", "Critical", "Unknown")
            ]
            chart = alt.Chart(alt.Data(values=chart_data)).mark_bar(color="#39D3A2").encode(
                x=alt.X("Severity:N", sort=["Low", "Medium", "High", "Critical", "Unknown"]),
                y=alt.Y("Scans:Q", scale=alt.Scale(domainMin=0), axis=alt.Axis(tickMinStep=1)),
                tooltip=["Severity:N", "Scans:Q"],
            ).properties(height=190)
            st.altair_chart(chart, use_container_width=True)

    with st.expander("How the risk score works"):
        st.table([
            {"Score": "0–29", "Level": "Low", "Action": "Review during normal monitoring"},
            {"Score": "30–59", "Level": "Medium", "Action": "Investigate the finding"},
            {"Score": "60–79", "Level": "High", "Action": "Prioritize investigation; alert created"},
            {"Score": "80–100", "Level": "Critical", "Action": "Investigate urgently; alert created"},
            {"Score": "No assessable checks", "Level": "Unknown", "Action": "Retry or review the failed checks"},
        ])
        st.caption("Confirmed signals: sensitive permission +20, broad host access +15, obfuscated code +25, external data transfer +25, malicious URL +80, suspicious URL +30, new domain +15, malicious downloaded-file hash +90, suspicious downloaded-file hash +40.")

    st.subheader("Device risk")
    devices = fetch("/api/devices", token, list)
    if devices is not None:
        device_rows = [
            {
                "Device": display(item.get("name")),
                "Device ID": display(item.get("id")),
                "Highest severity": severity(item.get("highest_severity")),
                "Scans": count(item.get("scan_count")),
            }
            for item in records(devices)
        ]
        show_table(device_rows, "No device risk results are available.")

    st.subheader("Extension risk")
    extensions = fetch("/api/extensions", token, list)
    if extensions is not None:
        extension_rows = [
            {
                "Extension": display(item.get("name")),
                "Extension ID": display(item.get("id")),
                "Device ID": display(item.get("device_id")),
                "Highest severity": severity(item.get("highest_severity")),
                "Scans": count(item.get("scan_count")),
            }
            for item in records(extensions)
        ]
        show_table(extension_rows, "No extension risk results are available.")


def show_devices(token: str) -> None:
    st.header("Devices")
    data = fetch("/api/devices", token, list)
    if data is None:
        return
    items = records(data)
    items = highest_severity_filter(items, "device_severity")
    items = search_filter(items, ("id", "name"), "device_search")
    rows = [
        {
            "Device": display(item.get("name")),
            "Device ID": display(item.get("id")),
            "Last seen": display(item.get("last_seen")),
            "Scans": count(item.get("scan_count")),
            "Highest severity": severity(item.get("highest_severity")),
        }
        for item in items
    ]
    show_table(rows, "No devices match this selection.")


def show_extensions(token: str) -> None:
    st.header("Extensions")
    data = fetch("/api/extensions", token, list)
    if data is None:
        return
    items = records(data)
    device_ids = sorted({display(item.get("device_id")) for item in items})
    selected_device = st.selectbox("Device", ["All", *device_ids], key="extension_device")
    if selected_device != "All":
        items = [item for item in items if display(item.get("device_id")) == selected_device]
    items = highest_severity_filter(items, "extension_severity")
    items = search_filter(items, ("id", "name", "version", "device_id"), "extension_search")
    rows = [
        {
            "Extension": display(item.get("name")),
            "Version": display(item.get("version")),
            "Extension ID": display(item.get("id")),
            "Device ID": display(item.get("device_id")),
            "Scans": count(item.get("scan_count")),
            "Highest severity": severity(item.get("highest_severity")),
        }
        for item in items
    ]
    show_table(rows, "No extensions match this selection.")


def show_findings(token: str) -> None:
    st.header("Findings")
    data = fetch("/api/findings", token, list)
    if data is None:
        return
    items = records(data)
    items = severity_filter(items, "finding_severity")
    items = search_filter(
        items,
        ("id", "scan_id", "device_id", "extension_id", "signal_code", "title", "detail"),
        "finding_search",
    )
    rows = [
        {
            "Time": display(item.get("created_at")),
            "Finding": display(item.get("title")),
            "Severity": severity(item.get("severity")),
            "Points": count(item.get("points")),
            "Signal": display(item.get("signal_code")),
            "Device ID": display(item.get("device_id")),
            "Extension ID": display(item.get("extension_id")),
            "Scan ID": display(item.get("scan_id")),
            "Finding ID": display(item.get("id")),
        }
        for item in items
    ]
    show_table(rows, "No findings match this selection.")
    if items:
        chosen = st.selectbox(
            "Finding details",
            range(len(items)),
            format_func=lambda index: f"{display(items[index].get('title'))} · {display(items[index].get('id'))}",
            key="finding_detail",
        )
        finding = items[chosen]
        st.write(display(finding.get("detail")))


def show_scans(token: str) -> None:
    st.header("Scan history")
    data = fetch("/api/scans", token, list)
    if data is None:
        return
    items = records(data)
    items = severity_filter(items, "scan_severity")
    items = search_filter(
        items,
        ("id", "device_id", "extension_id", "target_kind", "target_display", "completeness", "finding_codes", "override_id"),
        "scan_search",
    )
    rows = [
        {
            "Time": display(item.get("created_at")),
            "Target": display(item.get("target_display")),
            "Type": display(item.get("target_kind")),
            "Severity": severity(item.get("severity")),
            "Score": display(item.get("score")),
            "Completeness": display(item.get("completeness")),
            "Findings": ", ".join(item.get("finding_codes") or []),
            "Exception ID": display(item.get("override_id")),
            "Device ID": display(item.get("device_id")),
            "Extension ID": display(item.get("extension_id")),
            "Scan ID": display(item.get("id")),
        }
        for item in items
    ]
    show_table(rows, "No scans match this selection.")


def show_alerts(token: str) -> None:
    st.header("Alerts")
    data = fetch("/api/alerts", token, list)
    if data is None:
        return
    items = records(data)
    statuses = sorted({display(item.get("status")) for item in items})
    selected_status = st.selectbox("Status", ["All", *statuses], key="alert_status")
    if selected_status != "All":
        items = [item for item in items if display(item.get("status")) == selected_status]
    items = severity_filter(items, "alert_severity")
    items = search_filter(items, ("id", "scan_id", "message", "status"), "alert_search")
    rows = [
        {
            "Time": display(item.get("created_at")),
            "Severity": severity(item.get("severity")),
            "Status": display(item.get("status")),
            "Message": display(item.get("message")),
            "Scan ID": display(item.get("scan_id")),
            "Alert ID": display(item.get("id")),
        }
        for item in items
    ]
    show_table(rows, "No alerts match this selection.")


def show_events(token: str) -> None:
    st.header("Security event log")
    data = fetch("/api/events", token, list)
    if data is None:
        return
    items = records(data)
    types = sorted({display(item.get("event_type")) for item in items})
    selected_type = st.selectbox("Event type", ["All", *types], key="event_type")
    if selected_type != "All":
        items = [item for item in items if display(item.get("event_type")) == selected_type]
    items = severity_filter(items, "event_severity")
    items = search_filter(items, ("id", "event_type", "message", "scan_id"), "event_search")
    show_event_table(items)


def _override_rows(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for item in items:
        match_key = display(item.get("match_key"))
        if item.get("kind") == "url" and len(match_key) > 16:
            match_key = f"{match_key[:16]}…"
        state = "Effective" if item.get("effective") else (
            "Expired" if item.get("active") else "Deactivated"
        )
        rows.append({
            "Status": state,
            "Type": display(item.get("kind")),
            "Host": display(item.get("target_display")),
            "Match reference": match_key,
            "Reason": display(item.get("reason")),
            "Expires": display(item.get("expires_at")),
            "Created by": display(item.get("created_by")),
            "Created": display(item.get("created_at")),
            "Exception ID": display(item.get("id")),
        })
    return rows


def show_overrides(token: str) -> None:
    st.header("Whitelist & overrides")
    st.caption(
        "Domain exceptions match one exact hostname, never its subdomains. "
        "URL exceptions match one exact full HTTP(S) URL; only its fingerprint "
        "and hostname are stored. Risk scores and findings remain visible. "
        "A matching high-risk alert is marked suppressed and its external notification is not sent."
    )

    st.subheader("Create an exception")
    with st.form("override_create", clear_on_submit=True):
        kind = st.selectbox("Exception type", ("domain", "url"), format_func=str.title)
        target = st.text_input(
            "Domain or URL",
            help="For a domain, enter the exact hostname. For a URL, enter the exact full HTTP(S) address. The URL path and query are not stored.",
        )
        reason = st.text_area(
            "Reason",
            help="Explain why this exception is justified. Do not put a full URL or private information in the reason.",
            max_chars=2000,
        )
        expiry_days = st.number_input("Expires after (days)", min_value=1, max_value=90, value=30, step=1)
        submitted = st.form_submit_button("Create exception")
    if submitted:
        if not target.strip() or not reason.strip():
            st.error("Enter a target and a reason before creating an exception.")
        else:
            expiry = datetime.now(timezone.utc) + timedelta(days=int(expiry_days))
            created = post_admin(
                "/api/overrides",
                token,
                {
                    "kind": kind,
                    "target": target,
                    "reason": reason.strip(),
                    "expires_at": expiry.isoformat(),
                },
            )
            if created is not None:
                st.success(f"Exception created for {display(created.get('target_display'))}.")

    data = fetch("/api/overrides", token, list)
    if data is None:
        return
    items = records(data)
    effective = [item for item in items if item.get("effective") is True]
    history = [item for item in items if item.get("effective") is not True]

    st.subheader("Effective exceptions")
    show_table(_override_rows(effective), "No exceptions are currently effective.")

    if effective:
        options = {item["id"]: item for item in effective if isinstance(item.get("id"), str)}
        if options:
            selected = st.selectbox(
                "Select an exception to deactivate",
                options,
                format_func=lambda item_id: (
                    f"{display(options[item_id].get('kind')).title()} · "
                    f"{display(options[item_id].get('target_display'))} · {item_id[:8]}"
                ),
            )
            if st.button("Deactivate selected exception", type="secondary"):
                changed = post_admin(f"/api/overrides/{selected}/deactivate", token)
                if changed is not None:
                    st.session_state["override_change_notice"] = "Exception deactivated."
                    st.rerun()

    st.subheader("Expired and deactivated history")
    show_table(_override_rows(history), "No exception history is available.")

    st.subheader("Administrator change log")
    audit = fetch("/api/overrides/audit", token, list)
    if audit is not None:
        audit_rows = []
        for item in records(audit):
            details = item.get("details") if isinstance(item.get("details"), dict) else {}
            audit_rows.append({
                "Time": display(item.get("created_at")),
                "Action": display(item.get("action")),
                "Administrator": display(item.get("actor")),
                "Type": display(details.get("kind")),
                "Host": display(details.get("target_display")),
                "Exception ID": display(item.get("override_id")),
            })
        show_table(audit_rows, "No administrator exception changes are recorded.")


def show_monthly_reports(token: str) -> None:
    st.header("Monthly reports")
    st.caption(
        "Review aggregate statistics for a completed UTC month, generate an LLM summary, "
        "then send the saved report to administrators. The summary uses counts and finding "
        "categories, without visited URLs or device names."
    )

    now = datetime.now(timezone.utc)
    previous_year = now.year - 1 if now.month == 1 else now.year
    previous_month = 12 if now.month == 1 else now.month - 1
    latest_year = now.year if now.month > 1 else now.year - 1
    years = list(range(latest_year, 1999, -1))
    year = st.selectbox(
        "Report year (UTC)", years, index=years.index(previous_year), key="report_year"
    )
    latest_month = now.month - 1 if year == now.year else 12
    months = list(range(latest_month, 0, -1))
    month = st.selectbox(
        "Completed month (UTC)", months,
        index=months.index(previous_month) if year == previous_year else 0,
        format_func=lambda number: datetime(2000, number, 1).strftime("%B"),
        key="report_month",
    )
    period = f"{year:04d}-{month:02d}"

    notice = st.session_state.pop("report_notice", None)
    if isinstance(notice, dict):
        if notice.get("status") == "sent":
            st.success("The report was sent to the configured administrators.")
        elif notice.get("status") == "draft":
            st.success("The report draft was generated and saved.")
        else:
            st.warning("The report was not sent. Review the delivery results and email settings.")

    st.subheader(f"Statistics · {period}")
    stats = fetch(f"/api/reports/monthly/stats?year={year}&month={month}", token, dict)
    if stats is not None:
        metrics = st.columns(5)
        metrics[0].metric("Scans", count(stats.get("total_scans")))
        metrics[1].metric("High / Critical", count(stats.get("high_risk_scans")))
        severity_counts = stats.get("severity_counts")
        unknown = severity_counts.get("Unknown") if isinstance(severity_counts, dict) else None
        metrics[2].metric("Unknown", count(unknown))
        metrics[3].metric("Alerts", count(stats.get("alerts_total")))
        metrics[4].metric("Devices", count(stats.get("unique_devices")))

        st.markdown("**Risk severity**")
        show_severity_counts(stats)
        breakdowns = st.columns(3)
        for column, title, key, label in (
            (breakdowns[0], "Scan types", "target_kind_counts", "Type"),
            (breakdowns[1], "Assessment completeness", "completeness_counts", "Completeness"),
            (breakdowns[2], "Confirmed findings", "findings_by_signal", "Signal"),
        ):
            with column:
                st.markdown(f"**{title}**")
                values = stats.get(key)
                if isinstance(values, dict) and values:
                    rows = [
                        {label: display(name).replace("_", " ").title(), "Count": count(value)}
                        for name, value in values.items()
                    ]
                    rows.sort(key=lambda item: item["Count"] if isinstance(item["Count"], int) else -1, reverse=True)
                    st.dataframe(rows, hide_index=True, use_container_width=True)
                else:
                    st.info("No results for this category.")

    reports_data = fetch("/api/reports/monthly", token, list)
    if reports_data is None:
        return
    reports = records(reports_data)
    selected = next((item for item in reports if item.get("period") == period), None)
    st.subheader("Saved report")
    if selected is None:
        st.info("No report has been generated for this month.")
        if st.button("Generate LLM draft", key="generate_monthly_report"):
            generated = post_admin(
                "/api/reports/monthly/generate", token, {"year": year, "month": month}
            )
            if generated is not None:
                st.session_state["report_notice"] = {"status": "draft"}
                st.rerun()
    else:
        st.write(f"**Status:** {display(selected.get('status')).title()}")
        st.caption(
            f"Generated: {display(selected.get('generated_at'))} · "
            f"Sent: {display(selected.get('sent_at'))}"
        )
        st.write(f"**Subject:** {display(selected.get('subject'))}")
        body = selected.get("body")
        st.text_area(
            "Saved report body (read-only)",
            value=body if isinstance(body, str) else "",
            height=260,
            disabled=True,
            key=f"monthly_report_body_{period}",
        )
        if selected.get("status") != "sent":
            st.caption("Sending uses this saved draft. Review it before choosing Send.")
            if st.button("Send report to administrators", type="primary", key="send_monthly_report"):
                result = post_admin(f"/api/reports/monthly/{period}/send", token)
                if result is not None:
                    st.session_state["report_notice"] = {"status": result.get("status")}
                    st.rerun()
        else:
            st.success("This report was sent. It cannot be sent again from this view.")

        outcomes = selected.get("delivery_outcomes")
        if isinstance(outcomes, list) and outcomes:
            st.markdown("**Delivery results**")
            show_table([
                {
                    "Channel": display(item.get("channel")),
                    "Status": display(item.get("status")),
                    "Reason": display(item.get("reason") or item.get("error_type")),
                }
                for item in outcomes if isinstance(item, dict)
            ], "No delivery results are available.")

    st.subheader("Previous reports")
    previous_rows = []
    for item in reports:
        item_stats = item.get("stats") if isinstance(item.get("stats"), dict) else {}
        previous_rows.append({
            "Period": display(item.get("period")),
            "Status": display(item.get("status")).title(),
            "Scans": count(item_stats.get("total_scans")),
            "High / Critical": count(item_stats.get("high_risk_scans")),
            "Generated": display(item.get("generated_at")),
            "Sent": display(item.get("sent_at")),
        })
    show_table(previous_rows, "No monthly reports have been generated yet.")


def main() -> None:
    st.set_page_config(page_title="Security Analyzer Admin", page_icon="🛡️", layout="wide")
    st.title("Browser Extension Security Analyzer")
    st.caption("Administrator dashboard · scan results, risks, alerts, and security history")

    st.sidebar.header("Dashboard")
    view = st.sidebar.radio(
        "View",
        ("Overview", "Risk levels", "Devices", "Extensions", "Scan history", "Findings", "Alerts", "Security events", "Whitelist & overrides", "Monthly reports"),
    )
    st.sidebar.caption(f"API: {API_BASE_URL}")
    token = admin_sign_in()

    if not token:
        st.info("Sign in with your administrator password and authenticator code to view security data.")
        return

    st.sidebar.button("Refresh data")

    notice = st.session_state.pop("override_change_notice", None)
    if notice:
        st.success(notice)

    views = {
        "Overview": show_overview,
        "Risk levels": show_risk_levels,
        "Devices": show_devices,
        "Extensions": show_extensions,
        "Scan history": show_scans,
        "Findings": show_findings,
        "Alerts": show_alerts,
        "Security events": show_events,
        "Whitelist & overrides": show_overrides,
        "Monthly reports": show_monthly_reports,
    }
    views[view](token)


if __name__ == "__main__":
    main()
