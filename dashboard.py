"""Admin dashboard for the Browser Extension Security Analyzer.

Run with ``streamlit run dashboard.py``. The backend is expected at
``API_BASE_URL`` (default: http://localhost:8000/monitor). Each viewer signs in with
an administrator password and an authenticator-app code. The backend issues a
short-lived bearer session after both steps succeed.
"""

from __future__ import annotations

import os
import json
import re
from html import escape
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Any

import altair as alt
import httpx
import pandas as pd
import streamlit as st
from functools import partial
from dashboard_governance import render as render_governance
from alba_security.authenticator_qr import authenticator_qr_png


API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000/monitor").strip().rstrip("/")
TIMEOUT_SECONDS = 12.0
SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Informational", "Unknown")
SESSION_TOKEN_KEY = "admin_session_token"
SESSION_EXPIRES_KEY = "admin_session_expires_at"
CHALLENGE_TOKEN_KEY = "admin_challenge_token"
CHALLENGE_EXPIRES_KEY = "admin_challenge_expires_at"
SEVERITY_COLORS = {"Critical": "#b4233a", "High": "#c34a10", "Medium": "#916400", "Low": "#087c69", "Informational": "#306b9b", "Unknown": "#64748b"}
MAX_FILE_BYTES = 32 * 1024 * 1024
BRAND = '''<div class="scope-brand"><svg class="scope-logo" viewBox="0 0 40 46" aria-hidden="true"><path d="M20 2L37 9v14c0 10-9 17-17 21C12 40 3 33 3 23V9Z" fill="#007f78"/><path d="m11 22 6 6 13-14" fill="none" stroke="#b9ffed" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/></svg><div><strong>ExtSecure</strong><small>Security operations</small></div></div>'''


def page_heading(title: str, description: str) -> None:
    st.header(title)
    st.caption(description)


def risk_badge(value: Any) -> None:
    label = severity(value)
    color = SEVERITY_COLORS.get(label, SEVERITY_COLORS["Unknown"])
    st.markdown(f'<span class="scope-pill" style="color:{color};background:{color}0d">{escape(label)} risk</span>', unsafe_allow_html=True)


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
    # Clear unsent investigation notes and governance form values too, so the
    # next administrator on a shared browser does not inherit private drafts.
    for key in list(st.session_state):
        st.session_state.pop(key, None)


def _open_case_for_scan(scan_id: str) -> None:
    st.session_state['case_source_id'] = scan_id
    st.session_state['workspace_view'] = 'Incident cases'


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
        st.error("The security service is unavailable. Check the connection and try again.")
        return None


def _auth_payload(response: httpx.Response, token_field: str) -> tuple[str, str] | None:
    try:
        payload = response.json()
    except ValueError:
        payload = None
    if not isinstance(payload, dict):
        st.error("The service returned an invalid sign-in response. Please try again.")
        return None
    token = payload.get(token_field)
    expires_at = payload.get("expires_at")
    if not isinstance(token, str) or not token or _expired(expires_at):
        st.error("The service returned an invalid or expired sign-in response. Please try again.")
        return None
    return token, expires_at


def admin_register() -> None:
    st.caption('Create an account and verify your authenticator.')
    enrollment = st.session_state.get('registration_enrollment')
    if isinstance(enrollment, dict) and _expired(enrollment.get('expires_at')):
        st.session_state.pop('registration_enrollment', None)
        enrollment = None
        st.warning('Enrollment expired. Start registration again.')
    if isinstance(enrollment, dict):
        st.write('Scan this QR code with your authenticator app, then enter its six-digit code below.')
        try:
            qr_image = authenticator_qr_png(enrollment.get('provisioning_uri', ''), secret=enrollment.get('totp_secret', ''))
        except ValueError as error:
            st.error(str(error))
            st.session_state.pop('registration_enrollment', None)
            return
        st.image(qr_image, width=280, caption='ExtSecure · Authenticator setup QR code')
        st.caption('In your authenticator app, choose Add account → Scan QR code. Keep this QR code and setup key private.')
        with st.expander('Cannot scan? Enter the setup key manually'):
            st.write('Choose a time-based account, use your ExtSecure username, and paste this key. This sets up the same authenticator as the QR code.')
            st.code(enrollment['totp_secret'], language=None)
        st.caption('Setup expires after 15 minutes. Access still requires approval from the Head of Administrator.')
        with st.form('register_verify_form', clear_on_submit=True):
            code = st.text_input('Registration verification code', type='password', max_chars=6)
            submit = st.form_submit_button('Verify and create account', type='primary')
        if st.button('Cancel enrollment'):
            result = _auth_post('/api/admin/register/cancel', {'enrollment_token':enrollment['enrollment_token']})
            if result is not None and not result.is_error:
                st.session_state.pop('registration_enrollment', None)
                st.rerun()
        if submit:
            result = _auth_post('/api/admin/register/verify', {'enrollment_token':enrollment['enrollment_token'], 'totp_code':code.strip()})
            if result is not None:
                if result.is_error:
                    st.error('Enrollment could not be verified. Check the code; expired enrollments need to be restarted.')
                else:
                    st.session_state.pop('registration_enrollment', None)
                    st.session_state['registration_complete'] = True
                    st.rerun()
        return
    st.info('After authenticator setup, the Head of Administrator must approve access and assign your role.')
    with st.form('register_start_form', clear_on_submit=True):
        username = st.text_input('New username', max_chars=80)
        password = st.text_input('New password', type='password', autocomplete='new-password')
        confirm = st.text_input('Confirm password', type='password', autocomplete='new-password')
        submit = st.form_submit_button('Set up authenticator', type='primary')
    if submit:
        if password != confirm:
            st.error('Passwords must match.')
        elif len(password) < 12:
            st.error('Use a password with at least 12 characters.')
        else:
            result = _auth_post('/api/admin/register', {'username':username.strip().lower(), 'password':password})
            if result is not None:
                if result.is_error:
                    st.error('Registration could not start. Check the username and password, or wait for an existing enrollment to expire.')
                else:
                    issued = _auth_payload(result, 'enrollment_token')
                    if issued:
                        payload = result.json()
                        if isinstance(payload.get('totp_secret'), str) and isinstance(payload.get('provisioning_uri'), str):
                            st.session_state['registration_enrollment'] = payload
                            st.rerun()
                        else:
                            st.error('The service did not return authenticator setup details.')


def show_accounts(token: str) -> None:
    page_heading('Accounts', 'Head of Administrator · Review access requests and assign permissions.')
    st.info('Every account requires your approval. Choose the minimum role needed. All roles use password and authenticator verification.')
    roles = {'normal_user':'Normal user', 'manager':'Manager', 'administrator':'Administrator'}
    show_table([
        {'Role':'Normal user','Privileges':'Personal file checks, own results, account and security guidance'},
        {'Role':'Manager','Privileges':'Monitoring, reports and ML review, alert reviews and incident cases'},
        {'Role':'Administrator','Privileges':'Security operations, scans, exceptions, policies, privacy and report delivery'},
        {'Role':'Head of Administrator','Privileges':'All workflows plus account approval, roles and access revocation'},
    ], '')
    requests = fetch('/api/admin/registrations', token, list)
    accounts = fetch('/api/admin/accounts', token, list)
    if requests is not None:
        st.subheader('Pending access requests')
        show_table(requests, 'No accounts are waiting for approval.')
        if requests:
            chosen = st.selectbox('Registration to review', [r['username'] for r in requests])
            confirmed = st.checkbox('I verified this person’s identity and authorized their access')
            with st.form('review_registration'):
                role = st.selectbox('Approved role', list(roles), format_func=roles.get)
                reason = st.text_area('Account review reason', max_chars=500)
                approve = st.form_submit_button('Approve access', disabled=not confirmed)
                reject = st.form_submit_button('Reject registration')
            if approve or reject:
                action = 'approve' if approve else 'reject'
                if post_admin('/api/admin/registrations/'+chosen+'/'+action, token, {'reason':reason,'role':role}) is not None: st.rerun()
    if accounts is not None:
        st.subheader('Approved accounts')
        show_table(accounts, 'No accounts available.')
        editable = [r['username'] for r in accounts if r.get('role') != 'head_administrator']
        if editable:
            chosen = st.selectbox('Account to manage', editable)
            current = next(r.get('role','normal_user') for r in accounts if r['username'] == chosen)
            with st.form('account_role_change'):
                role = st.selectbox('New role', list(roles), index=list(roles).index(current), format_func=roles.get)
                reason = st.text_area('Reason for changing access', max_chars=500)
                change = st.form_submit_button('Save role and revoke existing sessions')
            if change:
                if post_admin('/api/admin/accounts/'+chosen+'/role', token, {'reason':reason,'role':role}) is not None: st.rerun()
            confirmed = st.checkbox('Revoke this account’s access and all existing sessions')
            if st.button('Disable account', disabled=not confirmed):
                if post_admin('/api/admin/accounts/'+chosen+'/disable', token) is not None: st.rerun()


def show_my_account(token: str) -> None:
    account = st.session_state.get('account_profile', {})
    page_heading('My account', 'Your access is assigned by the Head of Administrator.')
    st.write('**Account:** ' + account.get('display_name', ''))
    st.write('**Username:** ' + account.get('username', ''))
    st.write('**Role:** ' + account.get('role_label', ''))
    st.success('Password and authenticator verification completed for this session.')
    st.write('Your available workspaces are listed in the sidebar. Contact the main administrator if your responsibilities change.')


def show_personal_history(token: str) -> None:
    page_heading('My file history', 'Only checks submitted through your own account appear here.')
    rows = fetch('/api/my/scans', token, list)
    if rows is None: return
    show_table(rows, 'No personal file checks have been recorded.')
    if rows:
        scan_id = st.selectbox('Your scan to review', [r['id'] for r in rows])
        result = fetch('/api/my/scans/'+scan_id, token, dict)
        if result:
            risk_badge(result.get('severity'))
            st.write(result.get('suggested_action', ''))
            show_table(result.get('findings', []), 'No confirmed findings.')


def admin_sign_in() -> str | None:
    """Guide each dashboard viewer through password and TOTP authentication."""
    token = st.session_state.get(SESSION_TOKEN_KEY)
    if token and _expired(st.session_state.get(SESSION_EXPIRES_KEY)):
        _clear_session()
        token = None
        st.warning("Your administrator session expired. Please sign in again.")
    if token:
        st.sidebar.caption("Account · 2FA verified")
        if st.sidebar.button("Sign out", key="admin_sign_out"):
            response = _auth_post("/api/admin/logout", token=token)
            _clear_session()
            _clear_challenge()
            if response is None or response.status_code >= 500:
                st.session_state["auth_notice"] = "Local sign-out completed. The service could not confirm session revocation; it will expire automatically."
            st.rerun()
        return token

    challenge = st.session_state.get(CHALLENGE_TOKEN_KEY)
    if challenge and _expired(st.session_state.get(CHALLENGE_EXPIRES_KEY)):
        _clear_challenge()
        challenge = None
        st.warning("The sign-in code step expired. Enter your password again.")

    st.subheader("Sign in to ExtSecure")
    if st.session_state.pop('registration_complete', False):
        st.session_state['account_access'] = 'Log in'
        st.success('Registration completed. The main administrator must approve access before you can log in.')
    if not challenge:
        access = st.radio('Account access', ['Log in', 'Register new account'], horizontal=True, key='account_access')
        if access == 'Register new account':
            admin_register()
            return None
    if challenge:
        st.caption("STEP 02 / 02 · Verify your identity")
        st.write("Enter the six-digit code from your authenticator app.")
        with st.form("admin_totp_form", clear_on_submit=True):
            code = st.text_input("One-time code", type="password", max_chars=6, autocomplete="one-time-code")
            verify = st.form_submit_button("Verify and sign in", type="primary", use_container_width=True)
        if st.button("Start sign-in again", key="admin_restart_sign_in"):
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
                    st.error("The code was invalid or expired. Sign in again to request a new code step.")
                elif response.status_code == 429:
                    _clear_challenge()
                    st.error("Too many sign-in attempts. Please try again later.")
                elif response.is_error:
                    st.error(f"Sign-in failed with HTTP {response.status_code}.")
                else:
                    issued = _auth_payload(response, "access_token")
                    if issued is not None:
                        st.session_state[SESSION_TOKEN_KEY] = issued[0]
                        st.session_state[SESSION_EXPIRES_KEY] = issued[1]
                        _clear_challenge()
                        st.rerun()
        return None

    st.caption("STEP 01 / 02 · Your credentials")
    with st.form("admin_password_form", clear_on_submit=True):
        username = st.text_input("Username", autocomplete="username")
        password = st.text_input("Password", type="password", autocomplete="current-password")
        begin = st.form_submit_button("Continue securely", type="primary", use_container_width=True)
    if begin:
        response = _auth_post("/api/admin/login", {"username": username.strip(), "password": password})
        if response is not None:
            if response.status_code in (401, 403, 422):
                st.error("The username or password was not accepted.")
            elif response.status_code == 429:
                st.error("Too many sign-in attempts. Please try again later.")
            elif response.is_error:
                st.error(f"Sign-in failed with HTTP {response.status_code}.")
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
        _clear_challenge()
        st.error("Your administrator session was denied or expired. Please sign in again.")
        st.button("Return to sign-in", key="denied_fetch")
        st.stop()
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


def post_admin(path: str, token: str, payload: dict[str, Any] | None = None,
               *, upload: tuple[str, bytes, str] | None = None) -> dict[str, Any] | None:
    """Submit an administrator change using the verified backend session."""
    timeout = 90.0 if path.endswith("/generate") else 60.0 if "/downloads/" in path else 30.0 if path.endswith("/send") else TIMEOUT_SECONDS
    body = {"data": payload, "files": {"file": upload}} if upload else {"json": payload}
    try:
        response = httpx.post(
            f"{API_BASE_URL}{path}",
            headers={"Authorization": f"Bearer {token}"},
            **body,
            timeout=timeout,
        )
    except httpx.RequestError:
        st.error("The dashboard could not reach the backend. Check that the API is running.")
        return None
    if response.status_code == 401:
        _clear_session()
        _clear_challenge()
        st.session_state["auth_notice"] = "Your administrator session was denied or expired. Please sign in again."
        st.rerun()
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
        frame = pd.DataFrame(rows)
        severity_columns = [name for name in ("Severity", "Highest severity") if name in frame.columns]
        if severity_columns:
            def style_risk(value):
                color = SEVERITY_COLORS.get(str(value), SEVERITY_COLORS["Unknown"])
                return f"color: {color}; background-color: {color}12; font-weight: 700"
            frame = frame.style.map(style_risk, subset=severity_columns)
        st.dataframe(frame, hide_index=True, use_container_width=True)
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
            "Administrator": display(item.get("actor")),
            "Review note": display(item.get("reason")),
            "Status": display(item.get("status")),
            "Channel": display(item.get("channel")),
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
    st.markdown('<div class="scope-hero"><div class="scope-eyebrow">Security overview</div><h1>Focus on what needs attention.</h1><p>Follow confirmed threats, inspect the evidence, and keep a clear record of every decision.</p></div>', unsafe_allow_html=True)
    data = fetch("/api/overview", token, dict)
    if data is None:
        return

    pending = count(data.get("pending_alerts", data.get("open_alerts")))
    if isinstance(pending, int) and pending > 0:
        st.warning(f"{pending} alert{'s' if pending != 1 else ''} need review. Open Alerts to acknowledge, investigate, or resolve them.")
    elif pending == 0:
        st.info("No alerts are waiting for review. Scan activity and incomplete checks remain available below.")
    first = st.columns(5)
    first[0].metric("Total scans", count(data.get("total_scans")))
    first[1].metric("High-risk scans", count(data.get("high_risk")))
    first[2].metric("Awaiting review", pending)
    first[3].metric("Devices seen", count(data.get("devices")))
    first[4].metric("Extensions seen", count(data.get("extensions")))
    st.caption("Lifetime totals from recorded scans. A low score describes available evidence; it does not guarantee safety.")

    st.subheader("Risk severity")
    show_severity_counts(data)

    activity = records(data.get("daily_activity", []))
    if activity:
        st.subheader("Activity over the last 14 days")
        chart = alt.Chart(alt.Data(values=activity)).transform_fold(
            ["scans", "high_risk"], as_=["Series", "Count"]
        ).mark_line(point=True, strokeWidth=2.5).encode(
            x=alt.X("date:T", title=None, axis=alt.Axis(format="%d %b")),
            y=alt.Y("Count:Q", title="Scans", scale=alt.Scale(domainMin=0), axis=alt.Axis(tickMinStep=1)),
            color=alt.Color("Series:N", title=None, scale=alt.Scale(domain=["scans", "high_risk"], range=["#007f78", "#b4233a"])),
            tooltip=[alt.Tooltip("date:T", title="Day (UTC)"), "Series:N", "Count:Q"],
        ).properties(height=210)
        st.altair_chart(chart, use_container_width=True)

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
            chart = alt.Chart(alt.Data(values=chart_data)).mark_bar(cornerRadiusTopLeft=5, cornerRadiusTopRight=5).encode(
                x=alt.X("Severity:N", sort=["Low", "Medium", "High", "Critical", "Unknown"]),
                y=alt.Y("Scans:Q", scale=alt.Scale(domainMin=0), axis=alt.Axis(tickMinStep=1)),
                tooltip=["Severity:N", "Scans:Q"],
                color=alt.Color("Severity:N", scale=alt.Scale(domain=list(SEVERITY_COLORS), range=list(SEVERITY_COLORS.values())), legend=None),
            ).properties(height=190)
            st.altair_chart(chart, use_container_width=True)

    policy = fetch("/api/risk-policy", token, dict)
    if policy is not None:
        with st.expander("How the risk score works"):
            st.caption(f"Policy {display(policy.get('version'))} · Score capped at {display(policy.get('score_cap'))}")
            show_table([{"Severity": item.get("severity"), "From": item.get("min_score"), "To": item.get("max_score")} for item in records(policy.get("severity_bands", []))], "Risk bands are unavailable.")
            st.write(display(policy.get("unknown_policy")))
            show_table([{"Signal": item.get("title"), "Points": item.get("points"), "Meaning": item.get("description")} for item in records(policy.get("signals", []))], "Signal definitions are unavailable.")

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
    page_heading("Devices", "Devices observed in submitted scans, with their most severe recorded result. Last seen reflects scan activity, not continuous connectivity.")
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
    page_heading("Extensions", "Review extensions reported by connected clients and trace their findings back to a device.")
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
    page_heading("Findings", "Confirmed signals behind each risk score. Use the scan reference to investigate the full assessment.")
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
    page_heading("Scan history", "Trace assessed URLs, addresses, extensions, and file hashes. Partial and Unknown results need further evidence.")
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
    if items:
        st.subheader("Inspect scan evidence")
        selected = st.selectbox("Scan to inspect", range(len(items)),
            format_func=lambda index: f"{severity(items[index].get('severity'))} · {display(items[index].get('target_display'))} · {display(items[index].get('created_at'))}", key="scan_evidence")
        st.button("Investigate in a case", key="case_from_scan", on_click=_open_case_for_scan, args=(items[selected]['id'],))
        if st.button("Open evidence", key="open_scan_evidence"):
            detail = fetch(f"/api/scans/{items[selected]['id']}", token, dict)
            if detail is not None:
                with st.container(border=True):
                    risk_badge(detail.get("severity"))
                    st.write(display(detail.get("suggested_action")))
                    st.caption(f"Policy: {display(detail.get('risk_policy_version'))} · Completeness: {display(detail.get('completeness'))}")
                    show_table([{"Signal": value.get("code"), "Outcome": value.get("status")} for value in records(detail.get("signals", []))], "No signal details are available.")
                    show_table([{"Finding": value.get("title"), "Severity": value.get("severity"), "Points": value.get("points"), "Evidence": value.get("detail")} for value in records(detail.get("findings", []))], "No confirmed findings were recorded. Review completeness before drawing conclusions.")
                    st.markdown("**Related events**")
                    show_event_table(records(detail.get("events", [])))


def show_alerts(token: str) -> None:
    page_heading("Alerts", "Triage High and Critical findings. Every status change requires a reason and is recorded in the security event log.")
    notice = st.session_state.pop("alert_change_notice", None)
    if notice:
        st.success(notice)
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
    actionable = [item for item in items if item.get("status") in {"open", "acknowledged", "resolved"} and isinstance(item.get("id"), str)]
    if actionable:
        st.subheader("Review an alert")
        chosen = st.selectbox("Alert to review", range(len(actionable)),
            format_func=lambda index: f"{severity(actionable[index].get('severity'))} · {display(actionable[index].get('message'))} · {actionable[index]['id'][:8]}", key="triage_alert")
        selected = actionable[chosen]
        risk_badge(selected.get("severity"))
        st.caption(f"Current status: {display(selected.get('status')).title()} · Scan: {display(selected.get('scan_id'))}")
        if isinstance(selected.get('scan_id'), str):
            st.button("Investigate in a case", key="case_from_alert", on_click=_open_case_for_scan, args=(selected['scan_id'],))
        with st.form("alert_triage"):
            current = selected["status"]
            statuses = [value for value in ("acknowledged", "resolved", "open") if value != current]
            new_status = st.selectbox("Next status", statuses, format_func=lambda value: {"acknowledged": "Acknowledge — investigation started", "resolved": "Resolve — review completed", "open": "Reopen — needs another review"}[value])
            reason = st.text_area("Review note", max_chars=500, help="Describe the investigation or decision in 8–500 characters. Avoid private browsing data.")
            submitted = st.form_submit_button("Save review", type="primary")
        if submitted:
            if len(reason.strip()) < 8:
                st.error("Add a review note of at least 8 characters.")
            else:
                changed = post_admin(f"/api/alerts/{selected['id']}/status", token,
                    {"status": new_status, "reason": reason.strip(), "expected_status": current})
                if changed is not None:
                    st.session_state["alert_change_notice"] = f"Alert marked {display(changed.get('status'))}."
                    st.rerun()
    if any(item.get("status") == "suppressed" for item in items):
        st.caption("Suppressed alerts are governed by an exception. Review the exception in Whitelist & overrides; the recorded risk remains unchanged.")


def show_events(token: str) -> None:
    page_heading("Security event log", "A chronological record of scan outcomes, threats, administrator decisions, and notification delivery. Times are shown in UTC.")
    data = fetch("/api/events", token, list)
    if data is None:
        return
    items = records(data)
    types = sorted({display(item.get("event_type")) for item in items})
    selected_type = st.selectbox("Event type", ["All", *types], key="event_type")
    if selected_type != "All":
        items = [item for item in items if display(item.get("event_type")) == selected_type]
    items = severity_filter(items, "event_severity")
    items = search_filter(items, ("id", "event_type", "message", "scan_id", "actor", "reason", "status"), "event_search")
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

    st.subheader('Machine-learning activity review')
    st.caption('Learns from the 90 days before the selected month. Flags unusual daily activity for review; it does not change scan risk scores.')
    if st.button('Run monthly ML analysis', key='monthly_ml_run'):
        analysis = fetch(f'/api/reports/monthly/ml?year={year}&month={month}', token, dict)
        if analysis is not None:
            st.session_state['monthly_ml_result'] = analysis
    analysis = st.session_state.get('monthly_ml_result')
    if isinstance(analysis, dict) and analysis.get('period') == period:
        if analysis.get('status') == 'ready':
            st.metric('Unusual activity days', len(analysis.get('unusual_days', [])))
            st.caption(f"Model: {analysis['model']} · Active historical days: {analysis['active_training_days']}")
            st.dataframe(analysis['daily_results'], hide_index=True, use_container_width=True)
            st.info(analysis['limitation'])
        else:
            st.warning(analysis.get('reason', 'Machine-learning analysis is unavailable.'))
        st.download_button('Download ML evidence', json.dumps(analysis, indent=2), file_name=f'extsecure-ml-{period}.json', mime='application/json')

    reports_data = fetch("/api/reports/monthly", token, list)
    if reports_data is None:
        return
    reports = records(reports_data)
    selected = next((item for item in reports if item.get("period") == period), None)
    st.subheader("Saved report")
    if not st.session_state.get("account_profile", {}).get("can_manage_reports"):
        st.caption("Manager access: review reports and ML evidence. Administrators prepare and send reports.")
    if selected is None:
        st.info("No report has been generated for this month.")
        if st.session_state.get("account_profile", {}).get("can_manage_reports") and st.button("Generate LLM draft", key="generate_monthly_report"):
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
            if st.session_state.get("account_profile", {}).get("can_manage_reports") and st.button("Send report to administrators", type="primary", key="send_monthly_report"):
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


def show_downloads(token: str) -> None:
    page_heading("Downloaded-file checks", "Look up a file's SHA-256 reputation and keep the result in scan history. Files are never executed.")
    st.info("Hash checks only identify files already known to the reputation provider. Unknown means the lookup could not establish a verdict; it does not mean the file is safe.")
    mode = st.radio("Check method", ("SHA-256 hash", "Upload a file"), horizontal=True, key="download_mode")
    with st.form("download_scan", clear_on_submit=True):
        if mode == "SHA-256 hash":
            digest = st.text_input("SHA-256 hash", max_chars=64, placeholder="64 hexadecimal characters")
            uploaded = None
            st.caption("Only the hash is sent to the backend and the reputation provider.")
        else:
            uploaded = st.file_uploader("Downloaded file", help="Maximum 32 MB. File content is sent to the backend to compute SHA-256, then discarded; only the hash is sent to VirusTotal.")
            digest = ""
            st.caption("Up to 32 MB. The backend computes the hash and discards the file content. VirusTotal receives only the hash.")
        if st.session_state.get('account_profile', {}).get('role') == 'normal_user':
            device_id, device_name = 'personal-workbench', 'Personal file checks'
            st.caption('This result is linked to your account. Device identity is assigned by the backend.')
        else:
            device_id = st.text_input("Device reference", value="admin-workbench", max_chars=100, help="Use the device's registered reference to associate this review with its history.")
            device_name = st.text_input("Device name", value="Administrator workbench", max_chars=120)
        submit = st.form_submit_button("Check file reputation", type="primary")
    if submit:
        # Always clear a previous verdict before a new attempt, including invalid input.
        st.session_state.pop("download_result", None)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}", device_id.strip()) or not device_name.strip():
            st.error("Enter a device name and a valid reference using letters, numbers, dots, colons, underscores, or hyphens.")
        elif mode == "SHA-256 hash" and not re.fullmatch(r"[0-9a-fA-F]{64}", digest.strip()):
            st.error("Enter a valid SHA-256 hash containing exactly 64 hexadecimal characters.")
        elif mode == "Upload a file" and uploaded is None:
            st.error("Choose a file before starting the check.")
        elif uploaded is not None and uploaded.size > MAX_FILE_BYTES:
            st.error("The file exceeds the 32 MB limit. Use its SHA-256 hash instead.")
        else:
            metadata = {"device_id": device_id.strip(), "device_name": device_name.strip()}
            with st.spinner("Checking reputation and recording the assessment…"):
                if uploaded is not None:
                    result = post_admin("/api/admin/downloads/scan-file", token, metadata,
                        upload=("download.bin", uploaded.getvalue(), "application/octet-stream"))
                else:
                    result = post_admin("/api/admin/downloads/scan", token,
                        {**metadata, "sha256": digest.strip().lower()})
            if result is not None:
                st.session_state["download_result"] = result
    result = st.session_state.get("download_result")
    if isinstance(result, dict):
        with st.container(border=True):
            st.subheader("Latest assessment")
            risk_badge(result.get("severity"))
            columns = st.columns(3)
            columns[0].metric("Risk score / 100", display(result.get("score")))
            columns[1].metric("Completeness", display(result.get("completeness")).title())
            lookup = result.get("file_lookup") if isinstance(result.get("file_lookup"), dict) else {}
            columns[2].metric("Reputation", display(lookup.get("verdict")).title())
            if result.get("severity") == "Unknown" or result.get("completeness") != "complete":
                st.warning("The assessment is incomplete. Keep the file under review and retry when reputation data is available.")
            elif result.get("severity") in {"High", "Critical"}:
                st.error("A high-risk reputation result was recorded. Avoid opening the file and review the linked alert.")
            else:
                st.info("This lookup found no high-severity result. A reputation check alone cannot guarantee file safety.")
            if lookup.get("reason"):
                st.caption(f"Lookup detail: {display(lookup.get('reason')).replace('_', ' ')}")
            if lookup.get("retry_after_seconds") is not None:
                st.caption(f"Suggested retry delay: {display(lookup.get('retry_after_seconds'))} seconds.")
            st.caption(f"Scan reference: {display(result.get('id'))} · {'Cached reputation' if lookup.get('cache_hit') else 'Provider lookup'}")
            show_table([{"Finding": item.get("title"), "Points": item.get("points"), "Evidence": item.get("detail")} for item in records(result.get("findings", []))], "No confirmed findings were recorded for this assessment.")


def main() -> None:
    st.set_page_config(page_title="ExtSecure · Security console", page_icon="🛡️", layout="wide", initial_sidebar_state="auto")
    style = Path(__file__).with_name("dashboard.css").read_text(encoding="utf-8")
    st.markdown(f"<style>{style}</style>", unsafe_allow_html=True)
    if os.getenv("EXTSECURE_DEMO") == "1":
        st.info("Demonstration workspace · Synthetic data and simulated reputation results. External notifications are disabled.")

    # A local expiry check is for presentation only; every data request is still
    # authorized by the backend. No dashboard-wide credential is used.
    if st.session_state.get(SESSION_TOKEN_KEY) and _expired(st.session_state.get(SESSION_EXPIRES_KEY)):
        _clear_session()
        _clear_challenge()
        st.session_state["auth_notice"] = "Your administrator session expired. Please sign in again."
    if not st.session_state.get(SESSION_TOKEN_KEY):
        notice = st.session_state.pop("auth_notice", None)
        if notice:
            st.warning(notice)
        left, right = st.columns([1.3, 1], gap="large")
        with left:
            st.markdown(BRAND, unsafe_allow_html=True)
            st.markdown('''<div class="scope-login"><div class="scope-eyebrow">Your security workspace</div><h1>Clarity for every security decision.</h1><p>Bring risk signals, file checks, and administrator actions together in one focused workspace.</p><div class="scope-proof"><i>01</i><div><b>Evidence before action</b><span>Trace every finding back to the original assessment.</span></div></div><div class="scope-proof"><i>02</i><div><b>Controlled access</b><span>Approved roles with password and authenticator verification.</span></div></div><div class="scope-proof"><i>03</i><div><b>Accountable decisions</b><span>Review alerts, manage exceptions, and prepare reports.</span></div></div></div>''', unsafe_allow_html=True)
        with right:
            admin_sign_in()
            st.caption("Use your approved account and authenticator. New accounts need approval from the Head of Administrator.")
        return

    st.sidebar.markdown(BRAND, unsafe_allow_html=True)
    token = admin_sign_in()
    if not token:
        return
    account = fetch('/api/admin/me', token, dict)
    if account is None or not isinstance(account.get('views'), list):
        st.error('Your account permissions could not be loaded. Refresh to try again.')
        return
    previous = st.session_state.get('account_profile', {})
    if previous and previous.get('role') != account.get('role'):
        for key in ('download_result', 'monthly_ml_result', 'report_notice'):
            st.session_state.pop(key, None)
    st.session_state['account_profile'] = account
    st.sidebar.caption(account.get('display_name', '') + ' · ' + account.get('role_label', ''))
    views = {
        "Website access": lambda token: st.info('Website approvals are managed in the Chrome extension. Open ExtSecure, choose Open console, then Website access.'),
        "My account": show_my_account,
        "My file history": show_personal_history,
        "Overview": show_overview,
        "Alerts": show_alerts,
        "Findings": show_findings,
        "Risk levels": show_risk_levels,
        "Downloaded-file checks": show_downloads,
        "Scan history": show_scans,
        "Devices": show_devices,
        "Extensions": show_extensions,
        "Security events": show_events,
        "Whitelist & overrides": show_overrides,
        "Monthly reports": show_monthly_reports,
        "Accounts": show_accounts,
    }
    for governance_view in (
        "Incident cases", "Security policies", "Privacy governance", "Detection evaluation",
        "Usability and accessibility", "Security guidance",
    ):
        views[governance_view] = partial(render_governance, governance_view, fetch=fetch, post=post_admin)
    views = {name: action for name, action in views.items() if name in account['views']}
    if not views:
        st.error('No workspace access has been assigned.')
        return
    if st.session_state.get('workspace_view') not in views:
        st.session_state['workspace_view'] = 'Overview' if 'Overview' in views else next(iter(views))
    st.sidebar.divider()
    view = st.sidebar.radio("Workspace", tuple(views), key="workspace_view", label_visibility="collapsed")
    st.sidebar.divider()
    st.sidebar.button("Refresh data", use_container_width=True)
    st.sidebar.caption("Evidence stays visible. Exceptions change notification handling, never the recorded risk.")
    notice = st.session_state.pop("override_change_notice", None)
    if notice:
        st.success(notice)
    views[view](token)
    st.markdown('<div class="scope-note">ExtSecure · Administrator console &nbsp; / &nbsp; All activity timestamps use UTC.</div>', unsafe_allow_html=True)


if __name__ == "__main__":
    main()
