"""Administrator screens for ExtSecure investigation and governance."""
import json
import streamlit as st


def render(view, token, fetch, post):
    def get(path, kind=list):
        return fetch('/api/' + path, token, kind)

    def save(path, data):
        result = post('/api/' + path, token, data)
        if result is not None:
            st.session_state['governance_notice'] = 'Changes saved. The administrator audit trail was updated.'
            st.rerun()

    notice = st.session_state.pop('governance_notice', None)
    if notice:
        st.success(notice)
    st.header(view)
    st.caption('Review the evidence, record the decision, and keep the next action clear.')

    if view == 'Threat blocklist':
        rows = get('threat-blocks')
        if rows is None:
            return
        st.info('Active High/Critical blocks override approvals and whitelist entries. Investigate the linked case before a reviewed administrator release in the Chrome extension console.')
        st.dataframe([{key: row.get(key) for key in ('target_display','severity','active','case_id','case_status','updated_at')} for row in rows], hide_index=True, use_container_width=True)

    elif view == 'Incident cases':
        accounts = get('case-assignees')
        scans = get('scans')
        cases = get('cases')
        if accounts is None or scans is None or cases is None:
            return
        names = [r['username'] for r in accounts]
        source = st.session_state.pop('case_source_id', None)
        if source is not None:
            if not any(r['id'] == source for r in scans):
                evidence = get(f'scans/{source}', dict)
                if evidence is not None:
                    scans = [evidence, *scans]
            if any(r['id'] == source for r in scans):
                st.session_state['case_scan'] = source
        st.info('Cases keep their linked scan evidence on an investigation hold. Resolving a case does not change its risk score or resend alerts.')
        if scans and names:
            with st.expander('Open a case from a scan'):
                with st.form('case_create'):
                    options = {r['id']: r for r in scans}
                    scan_id = st.selectbox('Source scan', options, format_func=lambda k: f"{options[k]['severity']} · {options[k]['target_display']} · {k[:8]}", key='case_scan')
                    title = st.text_input('Case title', max_chars=160)
                    assignee = st.selectbox('Assigned administrator', names)
                    if st.form_submit_button('Create incident case', type='primary'):
                        save('cases', {'scan_id': scan_id, 'title': title, 'assignee': assignee})
        if not cases:
            st.info('No incident cases have been opened.')
            return
        st.dataframe([{k: r[k] for k in ['title', 'severity', 'assignee', 'status', 'updated_at']} for r in cases], hide_index=True, use_container_width=True)
        options = {r['id']: r for r in cases}
        chosen = st.selectbox('Case to investigate', options, format_func=lambda k: f"{options[k]['title']} · {options[k]['status']}")
        case = get(f'cases/{chosen}', dict)
        if case is None:
            return
        st.subheader(case['title'])
        st.caption(f"Severity: {case['severity']} · Assigned to {case['assignee']} · Revision {case['revision']}")
        if case.get('resolution'):
            st.write('Resolution: ' + case['resolution'])
        with st.expander('Original scan evidence'):
            evidence = get(f"scans/{case['scan_id']}", dict)
            if evidence is not None:
                st.write(evidence.get('suggested_action'))
                st.caption(f"Policy {evidence.get('risk_policy_version')} · Assessment {evidence.get('completeness')}")
                st.dataframe(evidence.get('findings', []), hide_index=True, use_container_width=True)
        st.subheader('Investigation notes')
        st.caption('Use concise evidence references. Avoid private URLs, passwords, file paths, or personal details.')
        for note in case.get('notes', []):
            st.caption(f"{note['author']} · {note['created_at']}")
            st.text(note['body'])
        with st.form('case_note'):
            body = st.text_area('New investigation note', max_chars=4000)
            if st.form_submit_button('Add note'):
                save(f'cases/{chosen}/notes', {'body': body})
        allowed = {'open': ['open', 'investigating'], 'investigating': ['investigating', 'resolved', 'open'], 'resolved': ['resolved', 'open']}
        with st.form('case_update'):
            status = st.selectbox('Case status', allowed[case['status']])
            assignee = st.selectbox('Assign case to', names, index=names.index(case['assignee']) if case['assignee'] in names else 0)
            reason = st.text_area('Decision or resolution reason', max_chars=2000)
            if st.form_submit_button('Update case'):
                save(f'cases/{chosen}/status', {'status': status, 'assignee': assignee, 'reason': reason, 'expected_revision': case['revision']})

    elif view == 'Privacy governance':
        rules = get('privacy', dict)
        if rules is None:
            return
        st.subheader('Data inventory')
        st.dataframe(rules['inventory'], hide_index=True, use_container_width=True)
        st.write(rules['retention_scope'])
        st.caption(rules['note_guidance'])
        with st.form('privacy_rules'):
            purpose = st.text_area('Collection purpose', value=rules['collection_purpose'], max_chars=1000)
            days = st.number_input('Scan retention period in days', min_value=7, max_value=3650, value=rules['retention_days'])
            hostnames = st.checkbox('Retain and display hostnames in URL scans', value=rules['show_hostnames'])
            st.caption('Disabling hostnames masks earlier scan displays and omits hostnames from new URL scan records. Existing exception targets remain available for administration.')
            reason = st.text_area('Reason for privacy-rule change', max_chars=2000)
            if st.form_submit_button('Save privacy rules'):
                save('privacy', {'expected_revision': rules['revision'], 'retention_days': days, 'show_hostnames': hostnames, 'collection_purpose': purpose, 'reason': reason})
        st.subheader('Retention review')
        preview = get('privacy/retention-preview', dict)
        if preview is not None:
            metrics = st.columns(2)
            metrics[0].metric('Eligible scans', preview['eligible_scans'])
            metrics[1].metric('Case evidence on hold', preview['protected_case_scans'])
            st.caption('Cutoff: ' + preview['cutoff'] + '. Stored monthly reports are snapshots; live statistics change after deletion.')
            confirmed = st.checkbox('Delete eligible scan evidence after reviewing this preview', key='retention_confirm')
            if st.button('Apply scan retention', disabled=not confirmed or preview['eligible_scans'] == 0):
                save('privacy/retention-apply', {'expected_revision': preview['revision'], 'confirm': True})

    elif view == 'Detection evaluation':
        st.info('Use labelled test scenarios to check scoring behavior. High/Critical count as a threat decision. Unknown results are reported separately. These tests do not measure real-world malware detection accuracy.')
        sample = [
            {'name': 'Confirmed malicious URL', 'expected': 'threat', 'signals': [{'code': 'malicious_url', 'status': 'detected'}]},
            {'name': 'Clear URL check', 'expected': 'benign', 'signals': [{'code': 'malicious_url', 'status': 'clear'}]},
            {'name': 'Unavailable lookup', 'expected': 'unknown', 'signals': [{'code': 'malicious_url', 'status': 'unknown'}]},
        ]
        with st.form('evaluation_run'):
            version = st.text_input('Dataset version', value='synthetic-example-v1', max_chars=80)
            fixtures = st.text_area('Labelled scenarios as JSON', value=json.dumps(sample, indent=2), height=280)
            st.caption('Replace the synthetic examples with reviewed fixtures. Keep private identifiers out of scenario names and evidence.')
            if st.form_submit_button('Compare active policy with baseline'):
                try:
                    rows = json.loads(fixtures)
                except ValueError:
                    st.error('Enter valid JSON before running the evaluation.')
                else:
                    save('evaluations', {'dataset_version': version, 'scenarios': rows})
        runs = get('evaluations')
        if not runs:
            st.info('No evaluation runs have been recorded.')
            return
        options = {r['id']: r for r in runs}
        selected = st.selectbox('Evaluation run', options, format_func=lambda k: f"{options[k]['dataset_version']} · {options[k]['created_at']}")
        row = options[selected]
        st.caption('Active scoring version in this run: ' + row['policy_version'])
        for label in ['current', 'baseline']:
            result = row['results'][label]
            st.subheader(label.title() + ' results')
            columns = st.columns(4)
            for column, name in zip(columns, ['true_positives', 'false_positives', 'false_negatives', 'unknown_outcomes']):
                column.metric(name.replace('_', ' ').title(), result[name])
            st.caption(f"Precision: {result['precision'] if result['precision'] is not None else 'Not available'} · Recall: {result['recall'] if result['recall'] is not None else 'Not available'} · Coverage: {result['coverage']:.0%}")
            st.dataframe(result['scenarios'], hide_index=True, use_container_width=True)
        st.subheader('Scoring review recommendations')
        st.caption('Suggestions use the labelled scenarios in this run. They do not change the active policy. Recommendations are reviewed by an administrator.')
        recommendations = row['results'].get('recommendations', [])
        if not recommendations:
            st.info('This older run has no stored recommendations. Run its unchanged dataset again to generate review suggestions.')
        for recommendation in recommendations:
            with st.expander(recommendation['category'].replace('_', ' ').title(), expanded=True):
                st.write(recommendation['action'])
                if recommendation['scenarios']:
                    st.write('Affected scenarios: ' + ', '.join(recommendation['scenarios']))
                if recommendation['signal_codes']:
                    st.write('Detected signals to review: ' + ', '.join(recommendation['signal_codes']))
        st.download_button('Download evaluation evidence', json.dumps(row, indent=2), file_name='extsecure-evaluation.json', mime='application/json')

    elif view == 'Usability and accessibility':
        st.write('Record an actual walkthrough, identify a problem, document its fix, then verify the retest. A failed or blocked task remains visible until the fix has been checked.')
        with st.expander('Walkthrough checklist', expanded=True):
            st.markdown('- Sign in using the keyboard and complete both authentication steps.\n- Read a risk result without relying on colour.\n- Explain the difference between Low and Unknown.\n- Open an alert, find its evidence, and create an incident case.\n- Check focus visibility, labels, contrast, and layout at enlarged zoom.')
        with st.form('usability_record'):
            task = st.text_input('Task tested', max_chars=200)
            category = st.selectbox('Test category', ['keyboard', 'contrast', 'screen_reader', 'comprehension', 'workflow'])
            outcome = st.selectbox('Observed outcome', ['failed', 'blocked', 'passed'])
            observation = st.text_area('Observation and evidence', max_chars=2000)
            if st.form_submit_button('Record walkthrough'):
                save('usability', {'task': task, 'category': category, 'outcome': outcome, 'observation': observation})
        rows = get('usability')
        if rows:
            st.dataframe(rows, hide_index=True, use_container_width=True)
            options = {r['id']: r for r in rows}
            selected = st.selectbox('Walkthrough to update', options, format_func=lambda k: f"{options[k]['task']} · {options[k]['status']}")
            row = options[selected]
            with st.form('usability_update'):
                statuses = ['fixed', 'open'] if row['status'] == 'open' else ['verified', 'open'] if row['status'] == 'fixed' else ['open']
                status = st.selectbox('Fix or retest status', statuses)
                verification = st.text_area('Fix details or retest evidence', max_chars=2000)
                if st.form_submit_button('Save walkthrough update'):
                    save(f'usability/{selected}/status', {'expected_revision': row['revision'], 'status': status, 'verification': verification})
        elif rows is not None:
            st.info('No walkthroughs have been recorded yet.')

    elif view == 'Security guidance':
        st.subheader('Start with the evidence')
        st.write('Open an alert or scan to see the confirmed findings, unavailable checks, scoring version, and suggested next action. The score is a review priority, not a probability that a device has been compromised.')
        policy = get('risk-policy', dict)
        if policy is not None:
            st.dataframe(policy['severity_bands'], hide_index=True, use_container_width=True)
            st.info(policy['unknown_policy'])
        for title, content in [
            ('Review a threat', 'Avoid opening the flagged destination or file. Inspect the scan evidence, open a case, assign an administrator, and record investigation notes. Resolve only after documenting the evidence and decision.'),
            ('Check a downloaded file', 'Use a SHA-256 hash when possible. Uploading a file sends its bytes to the backend for hashing; only its hash is sent to the reputation provider. Unknown requires follow-up and is not a clean verdict.'),
            ('Use an exception responsibly', 'An exception suppresses external notifications for its exact matching target. It does not erase findings, lower a score, prove a destination is safe, or cover subdomains automatically. Include a reason and expiry.'),
            ('Prepare a monthly report', 'Review the aggregate totals and generated narrative before sending. The report uses the saved statistics, and SMTP acceptance does not confirm delivery to an inbox.'),
            ('Protect browsing data', 'Keep private URLs, passwords and local file paths out of notes. Review collection and retention rules. Linked cases and pending alerts protect their source scan evidence from the retention operation.'),
        ]:
            with st.expander(title):
                st.write(content)
        st.caption('Administrator guide · ExtSecure 0.3 · Backend and dashboard workflows')

    if view != 'Security guidance':
        with st.expander('Administrator decision trail'):
            rows = get('governance/audit')
            if rows:
                st.dataframe(rows, hide_index=True, use_container_width=True)
            elif rows is not None:
                st.info('No governance actions have been recorded.')
