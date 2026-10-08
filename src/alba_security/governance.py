"""Versioned decisions, incident investigations and privacy administration."""
from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal
from fastapi import Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text, delete, select, update
from sqlalchemy.orm import Mapped, Session, mapped_column
from sqlalchemy.exc import IntegrityError
from alba_security.models import Alert, Base, Finding, Scan, SecurityEvent, new_id, utc_now
from alba_security.risk import SignalInput, assess, risk_policy


class GovernanceAudit(Base):
    __tablename__ = 'governance_audit'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    area: Mapped[str] = mapped_column(String(24), index=True)
    reference: Mapped[str] = mapped_column(String(100))
    actor: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(50))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class GovernanceState(Base):
    __tablename__ = 'governance_state'
    id: Mapped[str] = mapped_column(String(24), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    data: Mapped[dict] = mapped_column(JSON)


class PolicyRevision(Base):
    __tablename__ = 'security_policy_revisions'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    base_version: Mapped[str] = mapped_column(String(60))
    author: Mapped[str] = mapped_column(String(120))
    reviewer: Mapped[str | None] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(20), default='draft')
    reason: Mapped[str] = mapped_column(Text)
    review_reason: Mapped[str | None] = mapped_column(Text)
    policy: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class IncidentCase(Base):
    __tablename__ = 'incident_cases'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey('scans.id'), index=True)
    title: Mapped[str] = mapped_column(String(160))
    assignee: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(20), default='open')
    resolution: Mapped[str | None] = mapped_column(Text)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class CaseNote(Base):
    __tablename__ = 'incident_case_notes'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(ForeignKey('incident_cases.id'), index=True)
    author: Mapped[str] = mapped_column(String(120))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class EvaluationRun(Base):
    __tablename__ = 'detection_evaluations'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    dataset_version: Mapped[str] = mapped_column(String(80))
    policy_version: Mapped[str] = mapped_column(String(60))
    actor: Mapped[str] = mapped_column(String(120))
    results: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class EvaluationDataset(Base):
    __tablename__ = 'evaluation_datasets'
    version: Mapped[str] = mapped_column(String(80), primary_key=True)
    digest: Mapped[str] = mapped_column(String(64))
    fixtures: Mapped[list] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class UsabilityRecord(Base):
    __tablename__ = 'usability_records'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    actor: Mapped[str] = mapped_column(String(120))
    task: Mapped[str] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(30))
    outcome: Mapped[str] = mapped_column(String(24))
    observation: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(24), default='open')
    revision: Mapped[int] = mapped_column(Integer, default=1)
    verification: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class Input(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)


class Reason(Input):
    reason: str = Field(min_length=8, max_length=2000)


class PolicyDraft(Reason):
    base_version: str = Field(min_length=1, max_length=60)
    weights: dict[str, Annotated[int, Field(strict=True, ge=1, le=100)]]
    medium: int = Field(strict=True, ge=1, le=98)
    high: int = Field(strict=True, ge=2, le=99)
    critical: int = Field(strict=True, ge=3, le=100)

    @model_validator(mode='after')
    def valid_policy(self):
        expected = {row['code'] for row in risk_policy()['signals']}
        if set(self.weights) != expected or any(type(v) is not int or not 1 <= v <= 100 for v in self.weights.values()):
            raise ValueError('Provide every known signal with an integer weight from 1 to 100')
        if not self.medium < self.high < self.critical:
            raise ValueError('Severity thresholds must increase: Medium < High < Critical')
        return self


class PolicyReview(Reason):
    decision: Literal['approved', 'rejected']


class CaseCreate(Input):
    scan_id: str = Field(min_length=1, max_length=36)
    title: str = Field(min_length=8, max_length=160)
    assignee: str = Field(min_length=1, max_length=120)


class CaseChange(Reason):
    expected_revision: int = Field(strict=True, ge=1)
    status: Literal['open', 'investigating', 'resolved']
    assignee: str = Field(min_length=1, max_length=120)


class NoteCreate(Input):
    body: str = Field(min_length=8, max_length=4000)


class PrivacyChange(Reason):
    expected_revision: int = Field(strict=True, ge=1)
    retention_days: int = Field(strict=True, ge=7, le=3650)
    show_hostnames: bool = Field(strict=True)
    collection_purpose: str = Field(min_length=15, max_length=1000)


class RetentionApply(Input):
    expected_revision: int = Field(strict=True, ge=1)
    confirm: Literal[True]

    @field_validator('confirm', mode='before')
    @classmethod
    def explicit_confirmation(cls, value):
        # Literal[True] also accepts the equal integer 1. Destructive cleanup
        # requires an explicit JSON Boolean from the confirmation control.
        if value is not True:
            raise ValueError('Explicit confirmation is required')
        return value


class EvaluationScenario(Input):
    name: str = Field(min_length=1, max_length=120)
    expected: Literal['benign', 'threat', 'unknown']
    signals: list[SignalInput] = Field(min_length=1, max_length=11)

    @field_validator('signals')
    @classmethod
    def safe_signals(cls, signals):
        # Evaluation fixtures never retain supplied evidence text or identifiers.
        if len({s.code for s in signals}) != len(signals):
            raise ValueError('Duplicate signals are not allowed')
        return [SignalInput(code=s.code, status=s.status) for s in signals]


class EvaluationCreate(Input):
    dataset_version: str = Field(min_length=1, max_length=80)
    scenarios: list[EvaluationScenario] = Field(min_length=1, max_length=200)

    @field_validator('scenarios')
    @classmethod
    def unique_names(cls, rows):
        if len({r.name for r in rows}) != len(rows):
            raise ValueError('Scenario names must be unique')
        return rows


class UsabilityCreate(Input):
    task: str = Field(min_length=8, max_length=200)
    category: Literal['keyboard', 'contrast', 'screen_reader', 'comprehension', 'workflow']
    outcome: Literal['passed', 'failed', 'blocked']
    observation: str = Field(min_length=8, max_length=2000)


class UsabilityChange(Input):
    expected_revision: int = Field(strict=True, ge=1)
    status: Literal['open', 'fixed', 'verified']
    verification: str = Field(min_length=8, max_length=2000)


def iso(value):
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc).isoformat() if value.tzinfo is None else value.isoformat()


def audit(db, area, reference, actor, action, **details):
    db.add(GovernanceAudit(area=area, reference=reference, actor=actor, action=action, details=details))


def initialize_governance(db: Session):
    for key, data in [('policy', risk_policy()), ('privacy', {
        'retention_days': 90, 'show_hostnames': True,
        'collection_purpose': 'Investigate browser security findings and prepare aggregate security reports.',
    })]:
        if db.get(GovernanceState, key) is None:
            db.add(GovernanceState(id=key, version=1, data=data))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        if any(db.get(GovernanceState, key) is None for key in ('policy', 'privacy')):
            raise


def active_policy(db: Session):
    row = db.get(GovernanceState, 'policy', populate_existing=True)
    return copy.deepcopy(row.data) if row else risk_policy()


def privacy_settings(db: Session):
    row = db.get(GovernanceState, 'privacy', populate_existing=True)
    return {**row.data, 'revision': row.version}


def evaluate(scenarios, policy):
    counts = dict(true_positives=0, false_positives=0, true_negatives=0, false_negatives=0,
                  unknown_outcomes=0, unlabelled_for_confusion=0)
    rows = []
    for scenario in scenarios:
        result = assess(scenario.signals, policy)
        prediction = 'unknown' if result.severity == 'Unknown' else ('threat' if result.severity in {'High', 'Critical'} else 'benign')
        if prediction == 'unknown':
            counts['unknown_outcomes'] += 1
        elif scenario.expected == 'unknown':
            counts['unlabelled_for_confusion'] += 1
        else:
            key = {('threat', 'threat'): 'true_positives', ('benign', 'threat'): 'false_positives',
                   ('benign', 'benign'): 'true_negatives', ('threat', 'benign'): 'false_negatives'}[(scenario.expected, prediction)]
            counts[key] += 1
        rows.append({'name': scenario.name, 'expected': scenario.expected, 'prediction': prediction,
                     'severity': result.severity, 'score': result.score, 'completeness': result.completeness})
    tp, fp, fn = counts['true_positives'], counts['false_positives'], counts['false_negatives']
    return {**counts, 'precision': tp / (tp + fp) if tp + fp else None,
            'recall': tp / (tp + fn) if tp + fn else None,
            'coverage': (len(rows) - counts['unknown_outcomes']) / len(rows), 'scenarios': rows,
            'decision_rule': 'High/Critical = threat; Low/Medium = benign; Unknown excluded from confusion matrix',
            'limitation': 'Labelled test scenarios evaluate scoring behavior, not real-world malware detection accuracy.'}


def scoring_recommendations(scenarios, current, baseline):
    """Evidence for human policy review, never an automatic scoring change."""
    recommendations = []
    for expected, prediction, category, action in [
        ('benign', 'threat', 'false_positive',
         'Confirm the benign label and check contributing signal evidence. Compare a lower weight or a higher High threshold in a separate evaluation; check missed threats before proposing a change.'),
        ('threat', 'benign', 'missed_threat',
         'Confirm the threat label and check for missing detection signals. Compare a higher relevant weight or a lower High threshold in a separate evaluation; check incorrect warnings before proposing a change.'),
    ]:
        affected = [r['name'] for r in current['scenarios']
                    if (r['expected'], r['prediction']) == (expected, prediction)]
        if affected:
            codes = sorted({s.code for fixture in scenarios if fixture.name in affected
                            for s in fixture.signals if s.status == 'detected'})
            recommendations.append({'category': category, 'scenarios': affected,
                                    'signal_codes': codes, 'action': action})
    unknown = [r['name'] for r in current['scenarios'] if r['prediction'] == 'unknown']
    if unknown:
        recommendations.append({'category': 'incomplete_evidence', 'scenarios': unknown,
                                'signal_codes': [],
                                'action': 'Restore unavailable checks or add evidence. Keep Unknown separate; changing a threshold cannot establish that a missing check is safe.'})
    if (current['false_positives'] > baseline['false_positives'] or
            current['false_negatives'] > baseline['false_negatives']):
        recommendations.append({'category': 'baseline_regression', 'scenarios': [], 'signal_codes': [],
                                'action': 'The active policy increased incorrect warnings or missed threats against the baseline on this dataset. Review both error counts and coverage before approving another policy.'})
    if not recommendations:
        recommendations.append({'category': 'expand_validation', 'scenarios': [], 'signal_codes': [],
                                'action': 'No actionable scoring error appeared in these scenarios. Add independently labelled representative cases before drawing conclusions about detection quality.'})
    return recommendations


def retention_candidates(db: Session):
    settings = privacy_settings(db)
    cutoff = utc_now() - timedelta(days=settings['retention_days'])
    # Every linked case is an investigation hold, including resolved cases.
    # High-severity evidence stays while any alert remains open/acknowledged.
    held_cases = select(IncidentCase.scan_id)
    held_alerts = select(Alert.scan_id).where(Alert.status.in_(['open', 'acknowledged']))
    query = select(Scan.id).where(Scan.created_at < cutoff, Scan.id.not_in(held_cases), Scan.id.not_in(held_alerts))
    return list(db.scalars(query).all()), cutoff, settings


def install_governance(app, session_scope, require_actor, directory):
    Admin = Depends(require_actor)

    @app.get('/api/admin/accounts')
    def accounts(actor: str = Admin, db: Session = Depends(session_scope)):
        from alba_security.permissions import ROLE_LABELS, can_approve_role
        return [{'username': name, 'source': 'configured' if name in directory.accounts else 'registered',
                 'role':directory.role(db,name), 'role_label':ROLE_LABELS[directory.role(db,name)]}
                for name in directory.all_accounts(db)
                if actor == directory.primary.username or can_approve_role(directory.role(db,actor), directory.role(db,name))]

    @app.get('/api/case-assignees', dependencies=[Admin])
    def assignees(db: Session = Depends(session_scope)):
        return [{'username':name, 'role':directory.role(db,name)} for name in directory.operators(db)]

    @app.get('/api/governance/audit', dependencies=[Admin])
    def audit_history(db: Session = Depends(session_scope), limit: int = Query(200, ge=1, le=500)):
        return [{'id': r.id, 'area': r.area, 'reference': r.reference, 'actor': r.actor, 'action': r.action,
                 'details': r.details, 'created_at': iso(r.created_at)}
                for r in db.scalars(select(GovernanceAudit).order_by(GovernanceAudit.created_at.desc()).limit(limit))]

    def revision_record(r):
        return {'id': r.id, 'base_version': r.base_version, 'author': r.author, 'reviewer': r.reviewer,
                'status': r.status, 'reason': r.reason, 'review_reason': r.review_reason, 'policy': r.policy,
                'created_at': iso(r.created_at)}

    @app.get('/api/policies', dependencies=[Admin])
    def policies(db: Session = Depends(session_scope)):
        active = active_policy(db)
        return {'active': active, 'baseline': risk_policy(), 'revisions': [revision_record(r)
                for r in db.scalars(select(PolicyRevision).order_by(PolicyRevision.created_at.desc()).limit(200))],
                'independent_review_available': sum(directory.role(db,name) in {'head_administrator','administrator'} for name in directory.all_accounts(db)) > 1}

    @app.post('/api/policies', status_code=201)
    def draft(payload: PolicyDraft, actor: str = Admin, db: Session = Depends(session_scope)):
        current = active_policy(db)
        if payload.base_version != current['version']:
            raise HTTPException(409, 'Active policy changed; refresh before drafting')
        policy = copy.deepcopy(current)
        identifier = new_id()
        policy['version'] = identifier
        for signal in policy['signals']:
            signal['points'] = payload.weights[signal['code']]
        bounds = [0, payload.medium, payload.high, payload.critical, 101]
        policy['severity_bands'] = [{'severity': label, 'min_score': bounds[i], 'max_score': bounds[i + 1] - 1}
                                    for i, label in enumerate(['Low', 'Medium', 'High', 'Critical'])]
        row = PolicyRevision(id=identifier, base_version=payload.base_version, author=actor, reason=payload.reason, policy=policy)
        db.add(row)
        audit(db, 'policy', identifier, actor, 'draft_created', base_version=payload.base_version, reason=payload.reason)
        db.commit()
        return revision_record(row)

    @app.post('/api/policies/{revision_id}/review')
    def review(revision_id: str, payload: PolicyReview, actor: str = Admin, db: Session = Depends(session_scope)):
        row = db.get(PolicyRevision, revision_id)
        if row is None:
            raise HTTPException(404, 'Policy draft not found')
        if row.author == actor:
            raise HTTPException(403, 'A different administrator must review this draft')
        changed = db.execute(update(PolicyRevision).where(PolicyRevision.id == revision_id, PolicyRevision.status == 'draft')
                             .values(status=payload.decision, reviewer=actor, review_reason=payload.reason))
        if changed.rowcount != 1:
            db.rollback()
            raise HTTPException(409, 'This draft has already been reviewed')
        audit(db, 'policy', revision_id, actor, payload.decision, reason=payload.reason)
        db.commit()
        db.refresh(row)
        return revision_record(row)

    @app.post('/api/policies/{revision_id}/activate')
    def activate(revision_id: str, payload: Reason, actor: str = Admin, db: Session = Depends(session_scope)):
        state = db.scalar(select(GovernanceState).where(GovernanceState.id == 'policy').with_for_update())
        row = db.get(PolicyRevision, revision_id)
        if row is None:
            raise HTTPException(404, 'Policy draft not found')
        if row.status != 'approved' or not row.reviewer or row.reviewer == row.author:
            raise HTTPException(409, 'Independent approval is required before activation')
        if row.base_version != state.data['version']:
            raise HTTPException(409, 'Draft is based on an outdated policy; create a new draft')
        claimed = db.execute(update(GovernanceState).where(GovernanceState.id == 'policy', GovernanceState.version == state.version)
                             .values(data=row.policy, version=state.version + 1).execution_options(synchronize_session=False))
        if claimed.rowcount != 1:
            db.rollback()
            raise HTTPException(409, 'Policy changed concurrently; refresh')
        row.status = 'activated'
        audit(db, 'policy', revision_id, actor, 'activated', previous_version=row.base_version, reason=payload.reason)
        db.commit()
        return active_policy(db)

    def case_record(row, db, include_notes=False):
        scan = db.get(Scan, row.scan_id)
        result = {'id': row.id, 'scan_id': row.scan_id, 'title': row.title, 'assignee': row.assignee,
                  'status': row.status, 'resolution': row.resolution, 'revision': row.revision,
                  'severity': scan.severity, 'created_at': iso(row.created_at), 'updated_at': iso(row.updated_at)}
        if include_notes:
            result['notes'] = [{'id': n.id, 'author': n.author, 'body': n.body, 'created_at': iso(n.created_at)}
                               for n in db.scalars(select(CaseNote).where(CaseNote.case_id == row.id).order_by(CaseNote.created_at))]
        return result

    @app.get('/api/cases', dependencies=[Admin])
    def cases(db: Session = Depends(session_scope), limit: int = Query(200, ge=1, le=500)):
        return [case_record(r, db) for r in db.scalars(select(IncidentCase).order_by(IncidentCase.updated_at.desc()).limit(limit))]

    @app.post('/api/cases', status_code=201)
    def create_case(payload: CaseCreate, actor: str = Admin, db: Session = Depends(session_scope)):
        if db.get(Scan, payload.scan_id) is None:
            raise HTTPException(404, 'Scan not found')
        if payload.assignee not in directory.operators(db):
            raise HTTPException(422, 'Choose a configured administrator')
        row = IncidentCase(**payload.model_dump())
        db.add(row)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, 'Source scan changed during retention; refresh before creating a case') from None
        audit(db, 'case', row.id, actor, 'created', scan_id=row.scan_id, assignee=row.assignee)
        from alba_security.operations import attach_workflow
        attach_workflow(db, row, directory)
        db.commit()
        return case_record(row, db)

    @app.get('/api/cases/{case_id}', dependencies=[Admin])
    def case_detail(case_id: str, db: Session = Depends(session_scope)):
        row = db.get(IncidentCase, case_id)
        if row is None:
            raise HTTPException(404, 'Case not found')
        return case_record(row, db, True)

    @app.post('/api/cases/{case_id}/notes', status_code=201)
    def add_note(case_id: str, payload: NoteCreate, actor: str = Admin, db: Session = Depends(session_scope)):
        row = db.get(IncidentCase, case_id)
        if row is None:
            raise HTTPException(404, 'Case not found')
        note = CaseNote(case_id=case_id, author=actor, body=payload.body)
        db.add(note)
        row.updated_at = utc_now()
        audit(db, 'case', case_id, actor, 'note_added')
        db.commit()
        return case_record(row, db, True)

    @app.post('/api/cases/{case_id}/status')
    def change_case(case_id: str, payload: CaseChange, actor: str = Admin, db: Session = Depends(session_scope)):
        row = db.get(IncidentCase, case_id)
        if row is None:
            raise HTTPException(404, 'Case not found')
        if payload.assignee not in directory.operators(db):
            raise HTTPException(422, 'Choose a configured administrator')
        transitions = {'open': {'open', 'investigating'}, 'investigating': {'investigating', 'open', 'resolved'}, 'resolved': {'resolved', 'open'}}
        if payload.status not in transitions[row.status]:
            raise HTTPException(409, 'Investigate an open case before resolving it')
        previous = row.status
        change = db.execute(update(IncidentCase).where(IncidentCase.id == case_id, IncidentCase.revision == payload.expected_revision)
                            .values(status=payload.status, assignee=payload.assignee, revision=payload.expected_revision + 1,
                                    resolution=payload.reason if payload.status == 'resolved' else None, updated_at=utc_now()))
        if change.rowcount != 1:
            db.rollback()
            raise HTTPException(409, 'Case changed; refresh before updating')
        audit(db, 'case', case_id, actor, 'status_changed', previous_status=previous, status=payload.status,
              assignee=payload.assignee, reason=payload.reason)
        db.commit()
        db.refresh(row)
        return case_record(row, db, True)

    @app.get('/api/privacy', dependencies=[Admin])
    def privacy(db: Session = Depends(session_scope)):
        return {**privacy_settings(db), 'inventory': [
            {'data': 'Workflow rules and notifications', 'stored': 'Verified operators, deadlines and audited case references', 'purpose': 'Incident assignment, review and escalation'},
            {'data': 'Navigation observations', 'stored': 'Actor, linked device, hashed destination and outcome; no URL retained', 'purpose': 'Measure extension-reported blocking and approved visits'},
            {'data': 'Control assessments', 'stored': 'Evidence reference, reviewer, outcome and independent label', 'purpose': 'Evaluate security controls without changing scores'},
            {'data': 'URL scan', 'stored': 'SHA-256 fingerprint and optional hostname; no URL path/query', 'purpose': 'Correlate security findings'},
            {'data': 'File check', 'stored': 'SHA-256 digest; uploaded bytes discarded', 'purpose': 'Reputation lookup'},
            {'data': 'Device / extension', 'stored': 'References, display names and extension version', 'purpose': 'Associate investigations'},
            {'data': 'Case / audit', 'stored': 'Administrator identity, decisions and notes', 'purpose': 'Accountable response and change review'},
            {'data': 'Monthly report', 'stored': 'Aggregate counts and reviewed summary', 'purpose': 'Security reporting'},
            {'data': 'Website approval', 'stored': 'Explicitly requested URL scheme, host, port and path; requester, reviewer, reasons and expiry; no query or fragment', 'purpose': 'Controlled website access and decision audit'},
        ], 'ai_processing': 'By default the model receives fixed security categories and aggregate counts. Optional public-page or matching text-file excerpts require explicit consent, are bounded, and are not persisted as raw content. AI explanations follow scan deletion through their scan foreign key. Saved weekly/monthly report snapshots are retained separately for administrator review; deleting a scan does not rewrite a historical report snapshot.', 'retention_scope': 'Scan evidence without a linked case or an open/acknowledged alert. Cases, policy history, reports, website approval history and administrative audit records are held for investigation and review. Approval expiry ends access; it does not erase the decision history.',
            'note_guidance': 'Do not enter passwords, full browsing URLs, file paths or personal details in free-text fields.'}

    @app.post('/api/privacy')
    def change_privacy(payload: PrivacyChange, actor: str = Admin, db: Session = Depends(session_scope)):
        old = privacy_settings(db)
        values = payload.model_dump(exclude={'reason', 'expected_revision'})
        change = db.execute(update(GovernanceState).where(GovernanceState.id == 'privacy', GovernanceState.version == payload.expected_revision)
                            .values(data=values, version=payload.expected_revision + 1))
        if change.rowcount != 1:
            db.rollback()
            raise HTTPException(409, 'Privacy rules changed; refresh')
        audit(db, 'privacy', 'privacy', actor, 'rules_updated', before=old, after=values, reason=payload.reason)
        db.commit()
        return privacy(db)

    @app.get('/api/privacy/retention-preview', dependencies=[Admin])
    def preview_retention(db: Session = Depends(session_scope)):
        ids, cutoff, settings = retention_candidates(db)
        from alba_security.operations import NavigationEvidence
        return {'eligible_scans': len(ids), 'cutoff': iso(cutoff), 'revision': settings['revision'],
                'eligible_navigation_observations': db.query(NavigationEvidence).filter(NavigationEvidence.created_at < cutoff).count(),
                'protected_case_scans': db.query(IncidentCase.scan_id).distinct().count()}

    @app.post('/api/privacy/retention-apply')
    def apply_retention(payload: RetentionApply, actor: str = Admin, db: Session = Depends(session_scope)):
        state = db.scalar(select(GovernanceState).where(GovernanceState.id == 'privacy').with_for_update())
        if state.version != payload.expected_revision:
            raise HTTPException(409, 'Privacy rules changed; preview again')
        ids, cutoff, _ = retention_candidates(db)
        # Deleting children first respects both PostgreSQL and SQLite FKs.
        try:
            from alba_security.operations import NavigationEvidence
            removed_navigation = db.execute(delete(NavigationEvidence).where(NavigationEvidence.created_at < cutoff)).rowcount
            for offset in range(0, len(ids), 200):
                batch = ids[offset:offset + 200]
                for model in [SecurityEvent, Alert, Finding]:
                    db.execute(delete(model).where(model.scan_id.in_(batch)))
                db.execute(delete(Scan).where(Scan.id.in_(batch)))
            audit(db, 'privacy', 'retention', actor, 'retention_applied', removed_scans=len(ids), removed_navigation_observations=removed_navigation, cutoff=iso(cutoff))
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, 'New investigation evidence was linked during retention; preview again') from None
        return {'removed_scans': len(ids), 'cutoff': iso(cutoff)}

    @app.get('/api/evaluations', dependencies=[Admin])
    def evaluations(db: Session = Depends(session_scope)):
        return [{'id': r.id, 'dataset_version': r.dataset_version, 'policy_version': r.policy_version, 'actor': r.actor,
                 'results': r.results, 'created_at': iso(r.created_at)}
                for r in db.scalars(select(EvaluationRun).order_by(EvaluationRun.created_at.desc()).limit(100))]

    @app.post('/api/evaluations', status_code=201)
    def create_evaluation(payload: EvaluationCreate, actor: str = Admin, db: Session = Depends(session_scope)):
        current = active_policy(db)
        baseline = risk_policy()
        fixtures = [r.model_dump() for r in payload.scenarios]
        digest = hashlib.sha256(json.dumps(fixtures, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        dataset = db.get(EvaluationDataset, payload.dataset_version)
        if dataset is None:
            dataset = EvaluationDataset(version=payload.dataset_version, digest=digest, fixtures=fixtures)
            db.add(dataset)
            try:
                db.flush()
            except IntegrityError:
                db.rollback()
                dataset = db.get(EvaluationDataset, payload.dataset_version)
                if dataset is None:
                    raise
        if dataset.digest != digest:
            raise HTTPException(409, 'Dataset contents changed; use a new dataset version')
        current_result = evaluate(payload.scenarios, current)
        baseline_result = evaluate(payload.scenarios, baseline)
        row = EvaluationRun(dataset_version=payload.dataset_version, policy_version=current['version'], actor=actor,
                            results={'current': current_result, 'baseline': baseline_result,
                                     'recommendations': scoring_recommendations(payload.scenarios, current_result, baseline_result),
                                     'baseline_version': baseline['version'],
                                     'fixtures': fixtures, 'dataset_digest': digest})
        db.add(row)
        db.flush()
        audit(db, 'evaluation', row.id, actor, 'run_completed', dataset_version=payload.dataset_version, policy_version=current['version'])
        db.commit()
        return {'id': row.id, 'dataset_version': row.dataset_version, 'policy_version': row.policy_version, 'results': row.results}

    def usability_record(row):
        return {'id': row.id, 'task': row.task, 'category': row.category, 'outcome': row.outcome, 'observation': row.observation,
                'status': row.status, 'revision': row.revision, 'verification': row.verification,
                'actor': row.actor, 'created_at': iso(row.created_at)}

    @app.get('/api/usability', dependencies=[Admin])
    def usability(db: Session = Depends(session_scope)):
        return [usability_record(r) for r in db.scalars(select(UsabilityRecord).order_by(UsabilityRecord.created_at.desc()).limit(200))]

    @app.post('/api/usability', status_code=201)
    def create_usability(payload: UsabilityCreate, actor: str = Admin, db: Session = Depends(session_scope)):
        row = UsabilityRecord(**payload.model_dump(), actor=actor, status='verified' if payload.outcome == 'passed' else 'open')
        db.add(row)
        db.flush()
        audit(db, 'usability', row.id, actor, 'walkthrough_recorded', outcome=payload.outcome, category=payload.category)
        db.commit()
        return usability_record(row)

    @app.post('/api/usability/{record_id}/status')
    def update_usability(record_id: str, payload: UsabilityChange, actor: str = Admin, db: Session = Depends(session_scope)):
        row = db.get(UsabilityRecord, record_id)
        if row is None:
            raise HTTPException(404, 'Walkthrough not found')
        allowed = {'open': {'open', 'fixed'}, 'fixed': {'open', 'verified'}, 'verified': {'open'}}
        if payload.status not in allowed[row.status]:
            raise HTTPException(409, 'Record a fix before verifying the retest')
        if payload.status == 'verified' and row.status != 'fixed':
            raise HTTPException(409, 'Record a fix before verifying the retest')
        changed = db.execute(update(UsabilityRecord).where(UsabilityRecord.id == record_id, UsabilityRecord.revision == payload.expected_revision)
                             .values(status=payload.status, verification=payload.verification, revision=payload.expected_revision + 1))
        if changed.rowcount != 1:
            db.rollback()
            raise HTTPException(409, 'Walkthrough changed; refresh')
        audit(db, 'usability', record_id, actor, 'status_changed', status=payload.status, verification=payload.verification)
        db.commit()
        db.refresh(row)
        return usability_record(row)
