"""Server-owned roles and explicit route grants; unlisted routes fail closed."""
ROLE_LABELS = {
    'head_administrator': 'Head of Administrator',
    'administrator': 'Administrator',
    'manager': 'Manager',
    'normal_user': 'Normal user',
}

ROLE_LEVELS = {'normal_user': 0, 'manager': 1, 'administrator': 2, 'head_administrator': 3}

def can_approve_role(reviewer_role, requester_role, *, own=False):
    if reviewer_role not in ROLE_LEVELS or requester_role not in ROLE_LEVELS:
        return False
    if own:
        return reviewer_role == requester_role == 'head_administrator'
    return ROLE_LEVELS[reviewer_role] > ROLE_LEVELS[requester_role]

ACCESS_READS = {'/api/access/requests', '/api/access/whitelist'}
ACCESS_WRITES = {'/api/access/requests', '/api/access/check', '/api/access/consume'}
ACCESS_REVIEWS = {'/api/access/requests/{request_id}/review', '/api/access/whitelist/{entry_id}/revoke'}

READ_ROUTES = {
    '/api/overview', '/api/risk-policy', '/api/devices', '/api/extensions',
    '/api/findings', '/api/scans', '/api/scans/{scan_id}', '/api/overrides',
    '/api/overrides/audit', '/api/reports/monthly/stats', '/api/reports/monthly/ml',
    '/api/reports/monthly', '/api/alerts', '/api/events', '/api/governance/audit',
    '/api/policies', '/api/cases', '/api/cases/{case_id}', '/api/privacy',
    '/api/privacy/retention-preview', '/api/evaluations', '/api/usability',
    '/api/threat-blocks', '/api/case-assignees', '/api/my/scans', '/api/my/scans/{scan_id}',
    '/api/workflow/rules', '/api/workflow/notifications', '/api/controls/effectiveness', '/api/controls/reviews',
    '/api/operations/status',
}
ADMIN_WRITES = {
    '/api/threat-blocks/{block_id}/release',
    '/api/admin/downloads/scan', '/api/admin/downloads/scan-file',
    '/api/overrides', '/api/overrides/{override_id}/deactivate',
    '/api/reports/monthly/generate', '/api/reports/monthly/{period}/send',
    '/api/alerts/{alert_id}/status', '/api/policies',
    '/api/policies/{revision_id}/review', '/api/policies/{revision_id}/activate',
    '/api/cases', '/api/cases/{case_id}/notes', '/api/cases/{case_id}/status',
    '/api/privacy', '/api/privacy/retention-apply', '/api/evaluations',
    '/api/usability', '/api/usability/{record_id}/status',
    '/api/workflow/rules', '/api/workflow/rules/{rule_id}/update', '/api/workflow/run',
    '/api/workflow/notifications/{notice_id}/acknowledge', '/api/controls/reviews',
}
MANAGER_WRITES = {
    '/api/cases', '/api/cases/{case_id}/notes', '/api/cases/{case_id}/status',
    '/api/alerts/{alert_id}/status',
    '/api/workflow/notifications/{notice_id}/acknowledge',
}
MANAGER_READS = READ_ROUTES - {
    '/api/overrides', '/api/overrides/audit', '/api/policies', '/api/privacy',
    '/api/privacy/retention-preview', '/api/evaluations', '/api/usability',
    '/api/governance/audit',
    '/api/workflow/rules',
}
OWNER_ROUTES = {
    ('POST', '/api/admin/accounts/{username}/disable'),
    ('POST', '/api/admin/accounts/{username}/role'),
}

def allowed(role, method, route):
    if method == 'POST' and route == '/api/controls/navigation':
        return role in ROLE_LABELS
    if method == 'GET' and route == '/api/ai-jobs/{job_id}':
        return role in ROLE_LABELS
    if role in ROLE_LABELS:
        if (method, route) in {('GET', '/api/inventory/self'), ('POST', '/api/inventory/pair'), ('POST', '/api/inventory/sync'), ('POST', '/api/inventory/connect')}:
            return True
        if method == 'POST' and route in {'/api/inventory/devices', '/api/inventory/devices/{device_id}/status', '/api/inventory/devices/{device_id}/pairing-code'}:
            return role in {'head_administrator', 'administrator'}
    if (method, route) in {('GET', '/api/admin/accounts'), ('GET', '/api/admin/registrations'),
                          ('POST', '/api/admin/registrations/{username}/approve'),
                          ('POST', '/api/admin/registrations/{username}/reject')}:
        return role in {'head_administrator', 'administrator', 'manager'}
    if role in ROLE_LABELS and route in {'/api/intelligence/scans/{scan_id}', '/api/intelligence/scans/{scan_id}/explain'}:
        return (method == 'GET' and route.endswith('{scan_id}')) or (method == 'POST' and route.endswith('/explain'))
    if route == '/api/intelligence/reports':
        return method == 'GET' and role in {'head_administrator','administrator','manager'}
    if route == '/api/intelligence/reports/generate':
        return method == 'POST' and role in {'head_administrator','administrator'}
    if role in ROLE_LABELS:
        if (method == 'GET' and route in ACCESS_READS) or (method == 'POST' and route in ACCESS_WRITES):
            return True
        if method == 'POST' and route in ACCESS_REVIEWS:
            return role in {'head_administrator', 'administrator', 'manager'}
    if (method, route) in {('GET', '/api/admin/me'), ('POST', '/api/admin/logout')}:
        return role in ROLE_LABELS
    if (method, route) in OWNER_ROUTES:
        return role == 'head_administrator'
    if role == 'normal_user':
        return (method == 'GET' and route in {'/api/risk-policy', '/api/my/scans', '/api/my/scans/{scan_id}'}) or (method == 'POST' and route in {'/api/admin/downloads/scan', '/api/admin/downloads/scan-file'})
    if role in {'head_administrator', 'administrator'}:
        return (method == 'GET' and route in READ_ROUTES) or (method == 'POST' and route in ADMIN_WRITES)
    if role == 'manager':
        return (method == 'GET' and route in MANAGER_READS) or (method == 'POST' and route in MANAGER_WRITES)
    return False

ALL_VIEWS = [
    'Threat blocklist', 'Overview', 'Alerts', 'Findings', 'Risk levels', 'Downloaded-file checks',
    'Scan history', 'Devices', 'Extensions', 'Security events', 'Whitelist & overrides',
    'Reports', 'Accounts', 'Incident cases', 'Security policies',
    'Privacy governance', 'Detection evaluation', 'Usability and accessibility',
    'Security guidance', 'My account', 'My file history', 'Website access',
    'Workflow automation', 'Control effectiveness',
]

def profile(username, role):
    views = list(ALL_VIEWS)
    if role not in ROLE_LABELS: views = []
    elif role == 'manager':
        views = [v for v in views if v not in {'Downloaded-file checks',
            'Whitelist & overrides', 'Security policies', 'Privacy governance',
            'Detection evaluation', 'Usability and accessibility'}]
    elif role == 'normal_user': views = ['Downloaded-file checks', 'My file history', 'Security guidance', 'My account', 'Website access']
    return {'username': username, 'display_name': 'Head of Administrator' if role == 'head_administrator' else username,
            'role': role, 'role_label': ROLE_LABELS.get(role, 'No access'), 'views': views,
            'can_manage_accounts': role == 'head_administrator',
            'approvable_roles': [r for r in ('normal_user', 'manager', 'administrator') if can_approve_role(role, r)],
            'can_manage_reports': role in {'head_administrator', 'administrator'}}
