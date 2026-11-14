"""Bounded provider evidence and incident rules; never a probability of safety."""
from datetime import datetime, timezone

COUNTS = ('malicious', 'suspicious', 'harmless', 'undetected')
CATEGORIES = {
    'phishing': ('Phishing finding', 'Verify the destination and review whether credentials were entered.'),
    'malicious_download': ('Malicious download', 'Do not execute the file; review the hash and affected device.'),
    'malicious_website': ('Malicious website', 'Stop interaction and review the provider findings before release.'),
    'malicious_ip': ('Malicious IP reputation', 'Investigate the destination and affected browser activity.'),
    'suspicious_reputation': ('Suspicious reputation', 'Review the provider evidence; a warning is not proof of compromise.'),
    'extension_risk': ('Extension security findings', 'Review permissions, code findings and extension controls.'),
    'domain_age': ('Recent domain registration', 'Review the age evidence with other findings; age alone does not prove a threat.'),
    'manual_review': ('Manual evidence review', 'Investigate the linked scan; unavailable evidence is not a safe result.'),
}

def provider_evidence(stats, *, cached=False, analysis_date=None, categories=()):
    if not isinstance(stats, dict) or any(type(v) is not int or not 0 <= v <= 2_147_483_647 for v in stats.values()):
        raise ValueError('Invalid provider engine counts')
    # A missing category is not a reported zero. Preserve missing evidence.
    counts = {name: stats.get(name) for name in COUNTS}
    usable = any((counts[name] or 0) > 0 for name in COUNTS)
    date = None
    if type(analysis_date) is int and 0 < analysis_date < 4_102_444_800:
        date = datetime.fromtimestamp(analysis_date, timezone.utc).isoformat()
    return {'provider':'VirusTotal', 'status':'available' if usable else 'unavailable',
            'counts':counts, 'cached':bool(cached), 'analysis_at':date,
            'categories':[v for v in ('phishing', 'malware', 'ransomware') if v in categories],
            'mapping':'extsecure-provider-evidence-v1',
            'explanation':'VirusTotal engine counts are evidence. ExtSecure calculates its own policy score; neither is a probability of safety.'}

def scan_provider_evidence(result, *, cached=False):
    stats = result.engine_stats or {name:getattr(result, name) for name in COUNTS}
    return provider_evidence(stats, cached=cached, analysis_date=result.analysis_date, categories=result.categories)

def unavailable_provider(reason='unavailable'):
    return {**provider_evidence({}),'reason':reason if reason in {'not_found','rate_limited','provider_auth_failed','lookup_failed','invalid_response','not_configured'} else 'unavailable'}

def provider_signals(kind, evidence):
    suffix = 'file_hash' if kind in {'hash', 'download'} else kind
    counts = evidence['counts']
    assessed = evidence['status']=='available'
    return [{'code':prefix+'_'+suffix,
             'status':'unknown' if not assessed else 'detected' if (counts[prefix] or 0)>0 else 'clear'}
            for prefix in ('malicious','suspicious')]

def incident_rule(scan, evidence=None):
    codes={s['code'] for s in scan.signals if s['status']=='detected'}
    evidence=evidence or {}
    if scan.target_kind=='url' and 'phishing' in evidence.get('categories', []) and codes & {'malicious_url','suspicious_url'}:
        category='phishing'
    elif codes & {'malicious_url','malicious_file_hash','malicious_ip'}:
        category = ('malicious_download' if scan.target_kind in {'download','hash'} else
                    'malicious_ip' if scan.target_kind=='ip' else 'malicious_website')
    elif any(code.startswith('suspicious_') for code in codes):category='suspicious_reputation'
    elif codes & {'sensitive_permission','broad_host_access','obfuscated_code','external_data_transfer'}:category='extension_risk'
    elif 'new_domain' in codes:category='domain_age'
    else:category='manual_review'
    title, guidance=CATEGORIES[category]
    return {'category':category,'category_label':title,'guidance':guidance,
            'source':'SecureScope / VirusTotal' if evidence.get('status')=='available' else 'ExtSecure scan evidence',
            'auto_eligible':bool(codes & {'malicious_url','malicious_file_hash','malicious_ip','suspicious_url','suspicious_file_hash','suspicious_ip'}) and scan.override_id is None}

def stored_provider(db, scan_id):
    from sqlalchemy import select
    from alba_security.models import SecurityEvent
    for event in db.scalars(select(SecurityEvent).where(SecurityEvent.scan_id==scan_id, SecurityEvent.event_type=='scan_completed')):
        if isinstance(event.details.get('provider_evidence'), dict):return event.details['provider_evidence']
    return None

def ensure_review_case(db, scan, directory, evidence=None):
    from sqlalchemy import select
    from alba_security.governance import IncidentCase, audit
    existing=db.scalar(select(IncidentCase).where(IncidentCase.scan_id==scan.id))
    if existing:return existing
    rule=incident_rule(scan, evidence)
    if not rule['auto_eligible']:return None
    people=directory.operators(db)
    owner=directory.username if directory.username in people or not people else sorted(people)[0]
    case=IncidentCase(scan_id=scan.id,title=rule['category_label']+' investigation',assignee=owner)
    db.add(case);db.flush()
    audit(db,'case',case.id,'system','created',scan_id=scan.id,assignee=owner,category=rule['category'],evidence_based=True)
    return case
