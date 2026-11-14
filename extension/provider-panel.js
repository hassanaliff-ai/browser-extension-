import {escapeHtml as esc} from './core.js';

export function providerSummary(result={}) {
 const evidence=result.provider_evidence,counts=evidence?.counts;
 if(evidence?.provider!=='VirusTotal'||evidence.status!=='available')return {label:'Unknown',tone:'unknown',message:'No usable VirusTotal report is available. Unknown is not a safe result.'};
 if(Number.isSafeInteger(counts?.malicious)&&counts.malicious>0)return {label:'Malicious detections',tone:'critical',message:counts.malicious+' engines reported malicious results. Do not open this destination or file.'};
 if(Number.isSafeInteger(counts?.suspicious)&&counts.suspicious>0)return {label:'Suspicious detections',tone:'medium',message:counts.suspicious+' engines reported suspicious results. Review before proceeding.'};
 if(counts?.malicious===0&&counts?.suspicious===0)return {label:'No detections reported',tone:'low',message:'VirusTotal reported no malicious or suspicious detections in this report. This does not guarantee safety.'};
 return {label:'Unknown',tone:'unknown',message:'VirusTotal returned an incomplete report. Unknown is not a safe result.'};
}

export function providerPanel(result, compact=false) {
 const evidence=result?.provider_evidence;
 if(!evidence||evidence.provider!=='VirusTotal')return '<p class="meta">The VirusTotal report was not retained for this saved scan. Run a new check to retrieve the report.</p>';
 const count=name=>Number.isSafeInteger(evidence.counts?.[name])&&evidence.counts[name]>=0?String(evidence.counts[name]):'Unavailable';
 const labels={malicious:'Malicious',suspicious:'Suspicious',harmless:'Harmless',undetected:'Undetected'};
 return `<section class="stack provider-evidence" aria-label="VirusTotal reputation evidence"><h3>VirusTotal report</h3><div class="risk-grid">${Object.entries(labels).map(([key,label])=>`<div class="risk-pill"><span>${label}</span><strong data-no-translate>${count(key)}</strong></div>`).join('')}</div><p class="meta">${evidence.status==='available'?'Provider report available.':'Provider report unavailable or incomplete. Unknown is not safe.'} ${evidence.cached?'Cached report.':''}</p>${!compact&&evidence.analysis_at?`<p class="meta">Provider analysis time: <bdi data-no-translate>${esc(evidence.analysis_at)}</bdi></p>`:''}<p class="meta">Results returned by VirusTotal. Undetected does not mean harmless.</p></section>`;
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
