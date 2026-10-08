import {escapeHtml as esc} from './core.js';

export function workflowReadiness(rules,people,runner={}) {
  const operators=new Set(people.map(p=>p.username));
  const administrators=new Set(people.filter(p=>['administrator','head_administrator'].includes(p.role)).map(p=>p.username));
  const enabled=rules.filter(r=>r.enabled);
  const eligible=enabled.filter(r=>operators.has(r.assignee)&&operators.has(r.reviewer)&&administrators.has(r.escalate_to));
  const automatic=eligible.filter(r=>r.auto_create).length;
  const state=runner.running===false?'stopped':runner.status==='failed'?'failed':runner.status!=='ready'?'starting':!enabled.length?'disabled':!eligible.length?'unavailable':'ready';
  return {state,enabled:enabled.length,eligible:eligible.length,automatic,invalid:enabled.length-eligible.length};
}

export function workflowNoticeLabel(phase) {
  return {assigned:'Incident assigned',review_requested:'Review requested',escalated:'Incident escalated'}[phase]??phase;
}

export function workflowBody(data,revision) {
  const body={name:data.name,enabled:data.enabled==='on',priority:Number(data.priority),
    minimum_severity:data.minimum_severity,target_kind:data.target_kind,auto_create:data.auto_create==='on',
    assignee:data.assignee,notify_reviewer:data.notify_reviewer==='on',reviewer:data.reviewer,
    escalate_after_hours:Number(data.escalate_after_hours),escalate_to:data.escalate_to,reason:data.reason};
  if(revision!==undefined)body.expected_revision=revision;
  return body;
}

export function controlReviewBody(data) {
  const [reference_type,reference_id,...extra]=(data.reference??'').split(':');
  if(extra.length||!['scan','access_request','alert'].includes(reference_type)||!reference_id)
    throw new Error('Choose recorded evidence for this review.');
  return {control:data.control,reference_type,reference_id,outcome:data.outcome,ground_truth:data.ground_truth,evidence:data.evidence};
}

export function controlReferences(records,control) {
  const kinds={blocking:['scan','access_request'],approvals:['access_request'],exceptions:['scan'],alerts:['alert']}[control]??[];
  return records.filter(r=>kinds.includes(r.type)&&(control!=='exceptions'||r.override)).map(r=>[`${r.type}:${r.id}`,r.label]);
}

export function updateControlReference(form,records) {
  const input=form?.elements?.reference,control=form?.elements?.control?.value;
  if(!input)return;
  const choices=controlReferences(records,control),previous=input.value;
  input.innerHTML=choices.map(([value,label])=>`<option value="${esc(value)}">${esc(label)}</option>`).join('');
  if(choices.some(([value])=>value===previous))input.value=previous;
  input.required=true;
  const button=form.querySelector('button[type="submit"]');if(button)button.disabled=!choices.length;
}

export async function workflowView(c) {
  const {api,can,table,form,field,select,check,reason,notice,details,date,btn}=c;
  const manage=can('workflow');
  const [notices,rules,people,operations]=await Promise.all([api('workflow/notifications'),manage?api('workflow/rules'):null,manage?api('case-assignees'):[],manage?api('operations/status'):null]);
  const rows=rules?.rules??[],names=people.map(p=>p.username),senior=people.filter(p=>['administrator','head_administrator'].includes(p.role)).map(p=>p.username),row=rows.find(r=>r.id===c.selected)??rows[0];
  const readiness=manage?workflowReadiness(rows,people,operations?.workflow??rules?.runner):null;
  const messages={ready:'Automation is ready. New matching scans will be assigned automatically.',disabled:'Automation is not enabled. Create and enable a rule to start assignment, review notifications and escalation.',unavailable:'Enabled rules reference unavailable accounts. Edit the investigator, reviewer and escalation recipient before automation can run.',failed:'The last workflow check failed. Check the API service and run a workflow check again.',starting:'The workflow runner is starting. Refresh shortly to check its status.',stopped:'The workflow runner is stopped. Restart the ExtSecure API to resume scheduled checks.'};
  const setup=manage?`<section class="panel stack"><h2>Workflow status</h2>${notice(readiness.state==='ready'&&!readiness.automatic?'Escalation is ready for linked cases. Enable automatic case creation in a rule to assign new scans.':messages[readiness.state],readiness.state==='ready'?'info':'warning')}<p class="meta">${readiness.enabled} <span>enabled rules</span> · ${readiness.automatic} <span>automatic case rules</span> · ${notices.filter(n=>!n.acknowledged_at).length} <span>unread notifications</span></p>${readiness.invalid?notice('Some enabled rules reference unavailable accounts and cannot create automatic cases. Review their recipients.','warning'):''}</section>`:'';
  const inputs=(r={})=>field('Rule name','name','text',r.name??'','required minlength="4" maxlength="120"')+
    check('Enable this workflow rule','enabled',r.enabled??false)+field('Priority (lower runs first)','priority','number',r.priority??50,'required min="1" max="100"')+
    select('Minimum risk level','minimum_severity',['Low','Medium','High','Critical'],r.minimum_severity??'High')+
    select('Scan type','target_kind',[['any','All scan types'],['url','Website'],['file','File']],r.target_kind??'any')+
    check('Create incident cases automatically for new matching scans','auto_create',r.auto_create??true)+
    select('Assign new cases to','assignee',names,r.assignee??names[0])+
    check('Notify the reviewer in the extension','notify_reviewer',r.notify_reviewer??true)+select('Reviewer','reviewer',names,r.reviewer??names[0])+
    field('Escalate unresolved cases after (hours)','escalate_after_hours','number',r.escalate_after_hours??24,'required min="1" max="720"')+
    select('Escalate to administrator','escalate_to',senior,r.escalate_to??senior[0])+reason();
  c.cache({rows,row,notices});
  const inboxColumns=[['Case',r=>esc(r.case_id)],['Action',r=>esc(workflowNoticeLabel(r.phase))],['Reviewer','recipient'],['Created',r=>esc(date(r.created_at))],
    ['Status',r=>r.acknowledged_at?'Acknowledged':btn('Acknowledge','workflow-ack','small',`data-id="${esc(r.id)}"`)],
    ['Investigate',r=>btn('Open case','workflow-case','small',`data-id="${esc(r.case_id)}"`)]];
  return setup+`<section class="panel stack"><h2>Review notifications</h2><p class="meta">Acknowledge to mark a notification as read. Open its case to investigate or record resolution.</p>${btn('Refresh notifications','refresh','small')}${notices.length?table(notices,inboxColumns):notice('No workflow notifications yet. Notifications appear when a rule assigns a new case, requests a review or escalates an unresolved case.')}</section>`+
    (manage?`<section class="panel stack"><h2>Automation rules</h2>${details('How automation works','<p>Assignment, review and escalation notifications stay in the extension. Acknowledging a notification does not resolve its incident.</p><p>The first enabled matching rule assigns each new case. Exceptions and Unknown results do not create automatic cases. Existing manually assigned cases keep their investigator until escalation. Notes do not reset the deadline; reopening starts a new deadline.</p><p>Rules apply to new scans after they are enabled. Old scans are not turned into cases automatically. A 24-hour escalation needs an unresolved case to reach its deadline; it is not immediate.</p>')}
    <p class="meta">Runner: ${esc(rules.runner.status)} · Last check: ${esc(date(rules.runner.last_run))} · Every 60 seconds while the API runs</p>
    ${table(rows,[['Rule','name'],['Priority','priority'],['Minimum risk','minimum_severity'],['Investigator','assignee'],['Reviewer','reviewer'],['Escalate after',r=>esc(r.escalate_after_hours)+' h'],['Escalate to','escalate_to'],['Enabled',r=>r.enabled?'Enabled':'Disabled']])}
    ${names.length?details('Create a workflow rule',form('workflow-create',inputs(),'Create workflow rule')):notice('Approve an investigator account before creating a workflow rule.','warning')}
    ${row?details('Edit a workflow rule',c.selectRows('Rule',rows,row.id)+form('workflow-update',inputs(row),'Save workflow rule')):''}
    ${details('Check unresolved cases now',form('workflow-run',reason(),'Run workflow check'))}</section>`:'');
}

export async function effectivenessView(c,days=30) {
  const {api,can,table,form,select,textarea,notice,details,metrics,date}=c;
  const [data,reviews,scans,requests,alerts]=await Promise.all([api('controls/effectiveness?days='+days),api('controls/reviews'),
    can('controls')?api('scans'):[],can('controls')?api('access/requests'):[],can('controls')?api('alerts'):[]]);
  const referenceRecords=[...scans.map(r=>({type:'scan',id:r.id,override:!!r.override_id,label:`Scan · ${r.severity} · ${r.target_display}`})),
    ...requests.map(r=>({type:'access_request',id:r.id,label:`Access request · ${r.requester} · ${r.status}`})),
    ...alerts.map(r=>({type:'alert',id:r.id,label:`Alert · ${r.severity} · ${r.status}`}))];
  const references=controlReferences(referenceRecords,'blocking');
  const time=value=>value===null?'No response samples':value<60?`${Math.round(value)} s`:`${Math.round(value/60)} min`;
  c.cache({data,reviews,referenceRecords});
  return `<section class="panel stack"><h2>Security control effectiveness</h2>${select('Review period','control_days',[['7','Last 7 days'],['30','Last 30 days'],['90','Last 90 days'],['365','Last 365 days']],String(days),'data-control-days')}
    <p class="meta">${esc(date(data.start))} → ${esc(date(data.end))}</p>
    ${metrics([['Blocked navigation reports',data.blocking.blocked_reports,'Reported by signed-in extensions','lock'],['Unresolved incidents',data.incidents.unresolved,'Created in this review period','case'],['Repeated detections',data.incidents.repeated_detections,'Same target and device','alert']])}
    ${table(data.controls,[['Control','control'],['Reviewed','reviewed'],['Effective','effective'],['Missed','missed'],['Unnecessary','unnecessary'],['Inconclusive','inconclusive'],['Effectiveness',r=>r.effectiveness_percent===null?'Not assessed':esc(r.effectiveness_percent)+'%']])}
    ${table([{metric:'Approval response',...data.approvals.response_time},{metric:'Alert response',...data.alerts.response_time},{metric:'Incident resolution',...data.incidents.resolution_time}],
      [['Response time','metric'],['Samples','samples'],['Median',r=>esc(time(r.median_seconds))],['95th percentile',r=>esc(time(r.p95_seconds))]])}
    ${table([{control:'Blocking',activity:`${data.blocking.blocked_reports} blocked / ${data.blocking.opened_reports} opened reports`},
      {control:'Approvals',activity:`${data.approvals.approved} approved / ${data.approvals.rejected} rejected / ${data.approvals.pending} pending`},
      {control:'Exceptions',activity:`${data.exceptions.suppressed_scans} excepted scans / ${data.exceptions.suppressed_alerts} suppressed alerts / ${data.exceptions.whitelist_visits} whitelist visits`},
      {control:'Alerts',activity:`${data.alerts.created} created / ${data.alerts.open} open / ${data.alerts.delivery_sent} deliveries sent / ${data.alerts.delivery_failed} failed`}],[['Control','control'],['Recorded activity','activity']])}
    ${metrics([['Missed warnings',data.detection.missed_warnings,'Reviewer-labelled threats below High','search'],['Unnecessary warnings',data.detection.unnecessary_warnings,'Reviewer-labelled benign High/Critical scans','alert'],['Labelled scans',data.detection.labelled_scans,`${data.detection.unknown_scans} Unknown results remain unassessed`,'chart']])}
    ${data.notes.map(note=>`<p class="meta">${esc(note)}</p>`).join('')}</section>
    <section class="panel stack"><h2>Evidence reviews</h2>${notice('Record a verified outcome and the evidence supporting it. Keep private URLs, personal details and credentials out of notes. A review never changes a score or an approval.')}
    ${can('controls')&&references.length?details('Record a control assessment',form('control-review',
      select('Control','control',['blocking','approvals','exceptions','alerts'],'blocking','data-control-review')+select('Recorded evidence','reference',references,'','required')+
      select('Observed outcome','outcome',['effective','missed','unnecessary','inconclusive'],'inconclusive')+
      select('Independent threat label','ground_truth',[['unknown','Not independently verified'],['threat','Verified threat'],['benign','Verified benign']],'unknown')+
      textarea('Evidence and reasoning','evidence','','required minlength="20" maxlength="2000"'),'Record assessment')):''}
    ${table(reviews,[['Control','control'],['Outcome',r=>`<div>${esc(r.outcome)}</div><div class="meta">${esc(r.ground_truth)}</div>`],['Reference',r=>`<span title="${esc(r.reference_id)}" data-no-translate>${esc(r.reference_type)} · ${esc(r.reference_id.slice(0,8))}…</span>`],['Evidence','evidence'],['Reviewed by','actor'],['Created',r=>esc(date(r.created_at))]])}</section>`;
}
