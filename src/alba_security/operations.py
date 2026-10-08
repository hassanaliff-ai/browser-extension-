"""Audited incident automation and evidence-based control evaluation.

Rules never approve websites, bypass blocking, change scores, or resolve cases.
Notifications are durable in-app messages to verified operators.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import math
import statistics
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Literal

from fastapi import Depends, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import Field, model_validator
from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column

from alba_security.governance import GovernanceAudit, IncidentCase, Input, Reason, audit, iso
from alba_security.models import Alert, Base, Scan, SecurityEvent, new_id, utc_now
from alba_security.website_access import WebsiteRequest

SEVERITY = {'Low': 0, 'Medium': 1, 'High': 2, 'Critical': 3}
logger = logging.getLogger(__name__)
OPERATIONS_CAPABILITIES = ['incident_assignment', 'reviewer_notifications', 'case_escalation',
                           'control_effectiveness', 'navigation_observations', 'evidence_assessments']


class WorkflowRule(Base):
    __tablename__ = 'incident_workflow_rules'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120))
    enabled: Mapped[bool] = mapped_column(default=False)
    priority: Mapped[int] = mapped_column(Integer, default=50)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    settings: Mapped[dict] = mapped_column(JSON)
    author: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class WorkflowLink(Base):
    __tablename__ = 'incident_workflow_links'
    case_id: Mapped[str] = mapped_column(ForeignKey('incident_cases.id'), primary_key=True)
    rule_id: Mapped[str] = mapped_column(ForeignKey('incident_workflow_rules.id'), index=True)


class WorkflowNotice(Base):
    __tablename__ = 'incident_workflow_notices'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey('incident_cases.id'), index=True)
    rule_id: Mapped[str] = mapped_column(ForeignKey('incident_workflow_rules.id'))
    recipient: Mapped[str] = mapped_column(String(120), index=True)
    phase: Mapped[str] = mapped_column(String(24))
    details: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ControlReview(Base):
    __tablename__ = 'security_control_reviews'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    control: Mapped[str] = mapped_column(String(24), index=True)
    reference_type: Mapped[str] = mapped_column(String(24))
    reference_id: Mapped[str] = mapped_column(String(36), index=True)
    outcome: Mapped[str] = mapped_column(String(24))
    ground_truth: Mapped[str] = mapped_column(String(16))
    evidence: Mapped[str] = mapped_column(Text)
    actor: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class NavigationEvidence(Base):
    __tablename__ = 'security_navigation_evidence'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    actor: Mapped[str] = mapped_column(String(120), index=True)
    device_id: Mapped[str | None] = mapped_column(String(100))
    target_fingerprint: Mapped[str] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)


class RuleInput(Reason):
    name: str = Field(min_length=4, max_length=120)
    enabled: bool = Field(default=False, strict=True)
    priority: int = Field(default=50, strict=True, ge=1, le=100)
    minimum_severity: Literal['Low', 'Medium', 'High', 'Critical'] = 'High'
    target_kind: Literal['any', 'url', 'file'] = 'any'
    auto_create: bool = Field(default=True, strict=True)
    assignee: str = Field(min_length=1, max_length=120)
    notify_reviewer: bool = Field(default=True, strict=True)
    reviewer: str = Field(min_length=1, max_length=120)
    escalate_after_hours: int = Field(default=24, strict=True, ge=1, le=720)
    escalate_to: str = Field(min_length=1, max_length=120)


class RuleUpdate(RuleInput):
    expected_revision: int = Field(strict=True, ge=1)


class ReviewInput(Input):
    control: Literal['blocking', 'approvals', 'exceptions', 'alerts']
    reference_type: Literal['scan', 'access_request', 'alert']
    reference_id: str = Field(min_length=1, max_length=36)
    outcome: Literal['effective', 'missed', 'unnecessary', 'inconclusive']
    ground_truth: Literal['threat', 'benign', 'unknown'] = 'unknown'
    evidence: str = Field(min_length=20, max_length=2000)

    @model_validator(mode='after')
    def relevant_reference(self):
        allowed = {'blocking': {'scan', 'access_request'}, 'approvals': {'access_request'},
                   'exceptions': {'scan'}, 'alerts': {'alert'}}
        if self.reference_type not in allowed[self.control]:
            raise ValueError('Choose a reference that belongs to this security control')
        return self


class NavigationInput(Input):
    event_id: str = Field(pattern=r'^[a-f0-9]{64}$')
    target: str = Field(min_length=8, max_length=2048)
    outcome: Literal['blocked', 'opened']


def utc(value):
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def matches(rule, scan):
    return (rule.enabled and scan.severity in SEVERITY
            and SEVERITY[scan.severity] >= SEVERITY[rule.settings['minimum_severity']]
            and rule.settings['target_kind'] in {'any', scan.target_kind})


def configured_rules(db):
    return list(db.scalars(select(WorkflowRule).where(WorkflowRule.enabled.is_(True))
                           .order_by(WorkflowRule.priority, WorkflowRule.created_at, WorkflowRule.id)))


def eligible(rule, db, directory):
    people = directory.operators(db)
    return all(rule.settings[key] in people for key in ('assignee', 'reviewer', 'escalate_to'))


def add_notice(db, rule, case, phase, recipient, cycle='initial', **details):
    key = hashlib.sha256(f'{case.id}:{phase}:{cycle}'.encode()).hexdigest()
    if db.get(WorkflowNotice, key):
        return False
    db.add(WorkflowNotice(id=key, case_id=case.id, rule_id=rule.id, recipient=recipient,
                         phase=phase, details={'rule_revision': rule.revision, **details}))
    audit(db, 'workflow', case.id, 'system', phase, rule_id=rule.id, recipient=recipient, **details)
    return True


def attach_workflow(db, case, directory, *, rules=None):
    if db.get(WorkflowLink, case.id):
        return
    scan = db.get(Scan, case.scan_id)
    rule = next((r for r in (rules if rules is not None else configured_rules(db))
                 if matches(r, scan) and eligible(r, db, directory)), None)
    if not rule:
        return
    db.add(WorkflowLink(case_id=case.id, rule_id=rule.id))
    if rule.settings['notify_reviewer']:
        add_notice(db, rule, case, 'review_requested', rule.settings['reviewer'], assignee=case.assignee)


def automate_scan(db, scan, directory):
    """Use the first eligible rule; historical scans are not backfilled."""
    rule = next((r for r in configured_rules(db) if r.settings['auto_create']
                 and matches(r, scan) and not scan.override_id and eligible(r, db, directory)), None)
    if not rule or db.scalar(select(IncidentCase.id).where(IncidentCase.scan_id == scan.id)):
        return
    case = IncidentCase(scan_id=scan.id, title=f'{scan.severity} {scan.target_kind} scan investigation',
                        assignee=rule.settings['assignee'])
    db.add(case)
    db.flush()
    db.add(WorkflowLink(case_id=case.id, rule_id=rule.id))
    audit(db, 'case', case.id, 'system', 'created', scan_id=scan.id, assignee=case.assignee, rule_id=rule.id)
    add_notice(db, rule, case, 'assigned', case.assignee)
    if rule.settings['notify_reviewer']:
        add_notice(db, rule, case, 'review_requested', rule.settings['reviewer'], assignee=case.assignee)


def run_workflows(app, now=None):
    """A local lock and database uniqueness/revision checks prevent repeat actions."""
    if not app.state.workflow_lock.acquire(blocking=False):
        return {'busy': True, 'escalated': 0}
    now = now or utc_now()
    escalated = 0
    try:
        with app.state.session_factory() as db:
            rules = configured_rules(db)
            if rules:
                for case in db.scalars(select(IncidentCase).where(IncidentCase.status != 'resolved')):
                    try:
                        with db.begin_nested():
                            attach_workflow(db, case, app.state.admin_directory, rules=rules)
                            db.flush()
                            link = db.get(WorkflowLink, case.id)
                            rule = db.get(WorkflowRule, link.rule_id) if link else None
                            if (not rule or not rule.enabled or app.state.admin_directory.role(db, rule.settings['escalate_to'])
                                    not in {'head_administrator', 'administrator'}):
                                continue
                            # Notes and reassignment never postpone the unresolved-case deadline.
                            # Find latest explicit reopen, ignoring unrelated state changes.
                            changes = db.scalars(select(GovernanceAudit).where(GovernanceAudit.area == 'case',
                                GovernanceAudit.reference == case.id, GovernanceAudit.action == 'status_changed')
                                .order_by(GovernanceAudit.created_at.desc(), GovernanceAudit.id.desc()))
                            reopen = next((a for a in changes if a.details.get('previous_status') == 'resolved'
                                           and a.details.get('status') == 'open'), None)
                            start = utc(reopen.created_at if reopen else case.created_at)
                            cycle = reopen.id if reopen else 'initial'
                            key = hashlib.sha256(f'{case.id}:escalated:{cycle}'.encode()).hexdigest()
                            if now < start + timedelta(hours=rule.settings['escalate_after_hours']) or db.get(WorkflowNotice, key):
                                continue
                            changed = db.execute(update(IncidentCase).where(IncidentCase.id == case.id,
                                IncidentCase.revision == case.revision, IncidentCase.status != 'resolved')
                                .values(assignee=rule.settings['escalate_to'], revision=case.revision + 1, updated_at=now))
                            if changed.rowcount != 1:
                                continue
                            add_notice(db, rule, case, 'escalated', rule.settings['escalate_to'], cycle,
                                       deadline=iso(start + timedelta(hours=rule.settings['escalate_after_hours'])))
                            escalated += 1
                    except IntegrityError:
                        # Another worker already attached/escalated this case; savepoint rolls back.
                        continue
                db.commit()
        app.state.workflow_status = {'last_run': iso(now), 'status': 'ready', 'escalated': escalated}
        return {'busy': False, **app.state.workflow_status}
    finally:
        app.state.workflow_lock.release()


@asynccontextmanager
async def workflow_lifespan(app):
    async def loop():
        while True:
            try:
                await run_in_threadpool(run_workflows, app)
            except Exception as error:
                app.state.workflow_status = {'status': 'failed', 'error_type': type(error).__name__}
                logger.error('Incident workflow sweep failed: %s', type(error).__name__)
            await asyncio.sleep(60)
    task = asyncio.create_task(loop())
    app.state.workflow_running = True
    try:
        yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        app.state.workflow_running = False


def latency(samples):
    values = sorted(value for value in samples if value >= 0)
    return {'samples': len(values), 'median_seconds': round(statistics.median(values), 2) if values else None,
            'p95_seconds': round(values[max(0, math.ceil(len(values) * .95) - 1)], 2) if values else None}


def effectiveness(db, days, now=None):
    now = now or utc_now()
    cutoff = now - timedelta(days=days)
    scans = list(db.scalars(select(Scan).where(Scan.created_at >= cutoff, Scan.created_at <= now)))
    alerts = list(db.scalars(select(Alert).where(Alert.created_at >= cutoff, Alert.created_at <= now)))
    requests = list(db.scalars(select(WebsiteRequest).where(WebsiteRequest.created_at >= cutoff, WebsiteRequest.created_at <= now)))
    cases = list(db.scalars(select(IncidentCase).where(IncidentCase.created_at >= cutoff, IncidentCase.created_at <= now)))
    audits = list(db.scalars(select(GovernanceAudit).where(GovernanceAudit.created_at >= cutoff, GovernanceAudit.created_at <= now)
                            .order_by(GovernanceAudit.created_at, GovernanceAudit.id)))
    events = list(db.scalars(select(SecurityEvent).where(SecurityEvent.created_at >= cutoff, SecurityEvent.created_at <= now)
                            .order_by(SecurityEvent.created_at, SecurityEvent.id)))
    navigations = list(db.scalars(select(NavigationEvidence).where(NavigationEvidence.created_at >= cutoff, NavigationEvidence.created_at <= now)))
    approval_responses, case_responses, alert_responses = {}, {}, {}
    for item in audits:
        if item.area == 'website_access' and item.action in {'approved', 'rejected'}:
            approval_responses.setdefault(item.reference, item)
        if item.area == 'case' and item.action == 'status_changed' and item.details.get('status') == 'resolved':
            case_responses.setdefault(item.reference, item)
    for item in events:
        if item.event_type == 'alert_status_changed' and item.details.get('status') in {'acknowledged', 'resolved'}:
            alert_responses.setdefault(item.details.get('alert_id'), item)
    approval_times = []
    for request in requests:
        reviewed = approval_responses.get(request.id)
        if reviewed:
            approval_times.append((utc(reviewed.created_at) - utc(request.created_at)).total_seconds())
    alert_times = []
    for alert in alerts:
        response = alert_responses.get(alert.id)
        if response:
            alert_times.append((utc(response.created_at) - utc(alert.created_at)).total_seconds())
    case_times = []
    for case in cases:
        response = case_responses.get(case.id)
        if response:
            case_times.append((utc(response.created_at) - utc(case.created_at)).total_seconds())
    repeated = {}
    for scan in scans:
        if scan.severity in {'High', 'Critical'}:
            key = (scan.device_id, scan.target_fingerprint)
            repeated[key] = repeated.get(key, 0) + 1
    reviews = list(db.scalars(select(ControlReview).where(ControlReview.created_at >= cutoff, ControlReview.created_at <= now)
                             .order_by(ControlReview.created_at.desc(), ControlReview.id.desc())))
    latest, labels = {}, {}
    for review in reviews:
        latest.setdefault((review.control, review.reference_type, review.reference_id), review)
        source = db.get(Scan, review.reference_id) if review.reference_type == 'scan' else None
        if review.reference_type == 'alert':
            alert = db.get(Alert, review.reference_id)
            source = db.get(Scan, alert.scan_id) if alert else None
        if source:
            labels.setdefault(source.id, (source, review.ground_truth))
    control_rows = []
    for control in ('blocking', 'approvals', 'exceptions', 'alerts'):
        group = [r for r in latest.values() if r.control == control]
        outcomes = {kind: sum(r.outcome == kind for r in group) for kind in ('effective', 'missed', 'unnecessary', 'inconclusive')}
        assessed = len(group) - outcomes['inconclusive']
        control_rows.append({'control': control, 'reviewed': len(group), **outcomes,
                             'effectiveness_percent': round(100 * outcomes['effective'] / assessed, 1) if assessed else None})
    labelled = [(s, label) for s, label in labels.values() if label != 'unknown']
    assessed_labels = [(s, label) for s, label in labelled if s.severity != 'Unknown']
    return {'days': days, 'start': iso(cutoff), 'end': iso(now), 'controls': control_rows,
            'blocking': {'blocked_reports': sum(n.outcome == 'blocked' for n in navigations),
                         'opened_reports': sum(n.outcome == 'opened' for n in navigations), 'source': 'extension_reported'},
            'approvals': {'submitted': len(requests), 'approved': sum(r.decision not in {None, 'reject'} for r in requests),
                          'rejected': sum(r.decision == 'reject' for r in requests),
                          'pending': sum(r.status == 'pending' and utc(r.expires_at) > now for r in requests),
                          'response_time': latency(approval_times)},
            'exceptions': {'suppressed_scans': sum(bool(s.override_id) for s in scans),
                           'suppressed_alerts': sum(a.status == 'suppressed' for a in alerts),
                           'whitelist_visits': sum(a.area == 'website_access' and a.action == 'whitelist_visit' for a in audits)},
            'alerts': {'created': len(alerts), 'open': sum(a.status == 'open' for a in alerts),
                       'response_time': latency(alert_times),
                       'delivery_sent': sum(e.event_type == 'notification_delivery' and e.details.get('status') == 'sent' for e in events),
                       'delivery_failed': sum(e.event_type == 'notification_delivery' and e.details.get('status') == 'failed' for e in events)},
            'incidents': {'created': len(cases), 'unresolved': sum(c.status != 'resolved' for c in cases),
                          'repeated_detections': sum(max(0, count - 1) for count in repeated.values()),
                          'repeated_targets': sum(count > 1 for count in repeated.values()), 'resolution_time': latency(case_times)},
            'detection': {'labelled_scans': len(labelled), 'assessed_scans': len(assessed_labels),
                          'unknown_scans': sum(s.severity == 'Unknown' for s, _ in labelled),
                          'missed_warnings': sum(label == 'threat' and s.severity not in {'High', 'Critical'} for s, label in assessed_labels),
                          'unnecessary_warnings': sum(label == 'benign' and s.severity in {'High', 'Critical'} for s, label in assessed_labels)},
            'notes': ['Activity uses records created within the selected UTC window; latency samples require a recorded response.',
                      'Navigation counts are authenticated extension reports, not independent proof of browser enforcement.',
                      'Effectiveness percentages use latest reviewer assessments per control/reference, excluding inconclusive outcomes.',
                      'Warnings use the latest reviewer label and the High/Critical warning threshold; Unknown results and unverified labels are unassessed.',
                      'Repeated detections mean the same device and target fingerprint; they are not necessarily separate attacks.']}


def install_operations(app, session_scope, require_actor, directory):
    app.state.workflow_lock = Lock()
    app.state.workflow_status = {'status': 'waiting', 'last_run': None}
    app.state.workflow_running = False
    Actor, DB = Depends(require_actor), Depends(session_scope)

    def rule_record(row):
        return {'id': row.id, 'name': row.name, 'enabled': row.enabled, 'priority': row.priority,
                'revision': row.revision, 'author': row.author, 'created_at': iso(row.created_at), **row.settings}

    def validated_settings(payload, db, existing=None):
        settings = payload.model_dump(exclude={'reason', 'name', 'enabled', 'priority', 'expected_revision'})
        # Pausing must remain possible after a referenced operator is revoked.
        # Re-enabling or changing recipients still requires active identities.
        if existing is not None and not payload.enabled and settings == existing.settings:
            return settings
        people = directory.operators(db)
        if any(getattr(payload, key) not in people for key in ('assignee', 'reviewer', 'escalate_to')):
            raise HTTPException(422, 'Choose active managers or administrators for every workflow role')
        if directory.role(db, payload.escalate_to) not in {'head_administrator', 'administrator'}:
            raise HTTPException(422, 'Escalation must go to an active administrator or head administrator')
        return settings

    @app.get('/api/operations/status')
    def operations_status(actor: str = Actor):
        runner = app.state.workflow_status
        running = app.state.workflow_running
        status = 'ready' if running and runner.get('status') == 'ready' else 'starting' if running and runner.get('status') == 'waiting' else 'degraded'
        return {'api_version': app.version, 'status': status, 'capabilities': OPERATIONS_CAPABILITIES,
                'workflow': {**runner, 'running': running, 'interval_seconds': 60},
                'notifications': {'channel': 'in_app'},
                'evaluation': {'period_days': [7, 30, 90, 365], 'requires_reviewed_labels': True}}

    @app.get('/api/workflow/rules')
    def rules(actor: str = Actor, db: Session = DB):
        return {'rules': [rule_record(r) for r in db.scalars(select(WorkflowRule).order_by(WorkflowRule.priority, WorkflowRule.created_at))],
                'runner': {**app.state.workflow_status, 'interval_seconds': 60}}

    @app.post('/api/workflow/rules', status_code=201)
    def create_rule(payload: RuleInput, actor: str = Actor, db: Session = DB):
        if len(list(db.scalars(select(WorkflowRule.id)))) >= 50:
            raise HTTPException(409, 'The workflow rule limit is 50; update an existing rule')
        row = WorkflowRule(name=payload.name, enabled=payload.enabled, priority=payload.priority,
                           settings=validated_settings(payload, db), author=actor)
        db.add(row)
        db.flush()
        audit(db, 'workflow', row.id, actor, 'rule_created', reason=payload.reason, enabled=row.enabled,
              name=row.name, priority=row.priority, settings=row.settings, revision=1)
        db.commit()
        return rule_record(row)

    @app.post('/api/workflow/rules/{rule_id}/update')
    def update_rule(rule_id: str, payload: RuleUpdate, actor: str = Actor, db: Session = DB):
        existing = db.get(WorkflowRule, rule_id)
        if existing is None or existing.revision != payload.expected_revision:
            raise HTTPException(409, 'Workflow rule changed; refresh before updating')
        settings = validated_settings(payload, db, existing)
        changed = db.execute(update(WorkflowRule).where(WorkflowRule.id == rule_id, WorkflowRule.revision == payload.expected_revision)
                             .values(name=payload.name, enabled=payload.enabled, priority=payload.priority,
                                     settings=settings, revision=payload.expected_revision + 1))
        if changed.rowcount != 1:
            raise HTTPException(409, 'Workflow rule changed; refresh before updating')
        audit(db, 'workflow', rule_id, actor, 'rule_updated', reason=payload.reason, enabled=payload.enabled,
              revision=payload.expected_revision + 1, name=payload.name, priority=payload.priority, settings=settings)
        db.commit()
        return rule_record(db.get(WorkflowRule, rule_id))

    @app.post('/api/workflow/run')
    def run(payload: Reason, actor: str = Actor, db: Session = DB):
        audit(db, 'workflow', 'runner', actor, 'manual_run', reason=payload.reason)
        db.commit()
        return run_workflows(app)

    @app.get('/api/workflow/notifications')
    def notices(actor: str = Actor, db: Session = DB):
        query = select(WorkflowNotice)
        if directory.role(db, actor) == 'manager':
            query = query.where(WorkflowNotice.recipient == actor)
        return [{'id': r.id, 'case_id': r.case_id, 'rule_id': r.rule_id, 'recipient': r.recipient, 'phase': r.phase,
                 'details': r.details, 'created_at': iso(r.created_at), 'acknowledged_at': iso(r.acknowledged_at)}
                for r in db.scalars(query.order_by(WorkflowNotice.created_at.desc(), WorkflowNotice.id.desc()).limit(200))]

    @app.post('/api/workflow/notifications/{notice_id}/acknowledge')
    def acknowledge(notice_id: str, actor: str = Actor, db: Session = DB):
        row = db.get(WorkflowNotice, notice_id)
        if not row:
            raise HTTPException(404, 'Notification not found')
        if row.recipient != actor and directory.role(db, actor) not in {'head_administrator', 'administrator'}:
            raise HTTPException(403, 'Only the recipient or an administrator can acknowledge this notification')
        changed = db.execute(update(WorkflowNotice).where(WorkflowNotice.id == notice_id, WorkflowNotice.acknowledged_at.is_(None))
                             .values(acknowledged_at=utc_now()))
        if changed.rowcount:
            audit(db, 'workflow', notice_id, actor, 'notification_acknowledged')
            db.commit()
        return {'acknowledged': True}

    @app.post('/api/controls/navigation', status_code=201)
    def navigation(payload: NavigationInput, request: Request, actor: str = Actor, db: Session = DB):
        from alba_security.website_access import clean_url
        try:
            target = clean_url(payload.target)
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        key = hashlib.sha256(f'{actor}:{payload.event_id}'.encode()).hexdigest()
        if db.get(NavigationEvidence, key):
            return {'recorded': False}
        try:
            with db.begin_nested():
                db.add(NavigationEvidence(id=key, actor=actor, device_id=getattr(request.state, 'inventory_device_id', None),
                                         target_fingerprint=hashlib.sha256(target.encode()).hexdigest(), outcome=payload.outcome))
                db.flush()
        except IntegrityError:
            return {'recorded': False}
        db.commit()
        return {'recorded': True, 'source': 'extension_reported'}

    @app.get('/api/controls/effectiveness')
    def evaluate(actor: str = Actor, db: Session = DB, days: int = Query(default=30, ge=1, le=365)):
        return effectiveness(db, days)

    @app.get('/api/controls/reviews')
    def reviews(actor: str = Actor, db: Session = DB):
        return [{'id': r.id, 'control': r.control, 'reference_type': r.reference_type, 'reference_id': r.reference_id,
                 'outcome': r.outcome, 'ground_truth': r.ground_truth, 'evidence': r.evidence, 'actor': r.actor, 'created_at': iso(r.created_at)}
                for r in db.scalars(select(ControlReview).order_by(ControlReview.created_at.desc(), ControlReview.id.desc()).limit(200))]

    @app.post('/api/controls/reviews', status_code=201)
    def review(payload: ReviewInput, actor: str = Actor, db: Session = DB):
        model = {'scan': Scan, 'access_request': WebsiteRequest, 'alert': Alert}[payload.reference_type]
        source = db.get(model, payload.reference_id)
        if not source:
            raise HTTPException(404, 'Referenced security evidence not found')
        if payload.control == 'exceptions' and not source.override_id:
            raise HTTPException(422, 'Choose a scan with an applied exception')
        row = ControlReview(**payload.model_dump(), actor=actor)
        db.add(row)
        db.flush()
        audit(db, 'controls', row.id, actor, 'review_recorded', control=row.control, outcome=row.outcome,
              reference_type=row.reference_type, reference_id=row.reference_id)
        db.commit()
        return {'id': row.id, 'recorded': True}
