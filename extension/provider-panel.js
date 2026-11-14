import {escapeHtml as esc} from './core.js';

export function providerPanel(result, compact=false) {
 const evidence=result?.provider_evidence;
 if(!evidence||evidence.provider!=='VirusTotal')return '<p class="meta">VirusTotal engine evidence was not retained for this scan. No provider score is inferred.</p>';
 const count=name=>Number.isSafeInteger(evidence.counts?.[name])&&evidence.counts[name]>=0?String(evidence.counts[name]):'Unavailable';
 const labels={malicious:'Malicious',suspicious:'Suspicious',harmless:'Harmless',undetected:'Undetected'};
 return `<section class="stack provider-evidence" aria-label="VirusTotal reputation evidence"><h3>VirusTotal reputation evidence</h3><div class="risk-grid">${Object.entries(labels).map(([key,label])=>`<div class="risk-pill"><span>${label}</span><strong data-no-translate>${count(key)}</strong></div>`).join('')}</div><p class="meta">${evidence.status==='available'?'Provider report available.':'Provider report unavailable or incomplete. Unknown is not safe.'} ${evidence.cached?'Cached report.':''}</p>${!compact&&evidence.analysis_at?`<p class="meta">Provider analysis time: <bdi data-no-translate>${esc(evidence.analysis_at)}</bdi></p>`:''}<p class="meta">These are engine counts, not a VirusTotal score out of 100. ExtSecure calculates its policy score separately. Undetected does not mean harmless.</p></section>`;
}

export const incidentRules=[
 ['Phishing finding','A provider explicitly labels a detected website as phishing.'],
 ['Malicious website','At least one provider engine reports a malicious destination.'],
 ['Malicious download','A SHA-256 reputation report contains a malicious detection.'],
 ['Malicious IP reputation','The linked scan contains malicious IP evidence.'],
 ['Suspicious reputation','A provider reports suspicious evidence requiring review.'],
 ['Extension security findings','An investigator reviews permissions, code or transfer findings.'],
 ['Recent domain registration','Domain age is reviewed with other evidence; age alone is not proof of danger.'],
 ['Manual evidence review','An investigator creates a scan-linked case for another concern.']
];

export function incidentRulesPanel() {
 return `<details class="panel"><summary>Incident categories and creation rules</summary><p class="meta">Confirmed malicious or suspicious scan findings create one investigation per scan. Unknown and exception-only results do not automatically create cases. High and Critical threats remain blocked. Other categories support manual review. Categories follow evidence, not a prediction of infection.</p><dl>${incidentRules.map(([name,description])=>`<dt><strong>${esc(name)}</strong></dt><dd>${esc(description)}</dd>`).join('')}</dl></details>`;
}
