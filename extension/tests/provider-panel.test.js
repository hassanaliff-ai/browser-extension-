import test from 'node:test';
import assert from 'node:assert/strict';
import {providerPanel,providerSummary,incidentRulesPanel,incidentRules} from '../provider-panel.js';
import {scanEvidenceExport} from '../evidence-export.js';
test('Detector shows VirusTotal counts with no separate numerical score',()=>{
 const result={score:80,provider_evidence:{provider:'VirusTotal',status:'available',counts:{malicious:1,suspicious:2,harmless:60,undetected:4},cached:true,analysis_at:'<script>bad</script>'}};
 for(const compact of [true,false]){const html=providerPanel(result,compact);assert.match(html,/Malicious/);assert.match(html,/Suspicious/);assert.match(html,/Harmless/);assert.match(html,/Undetected/);assert.doesNotMatch(html,/score|100/);assert.match(html,/Cached report/);assert(!html.includes('<script>'));}
});
test('Detector verdict follows provider counts rather than the policy score',()=>{
 const report=counts=>({score:100,severity:'Critical',provider_evidence:{provider:'VirusTotal',status:'available',counts}});
 assert.equal(providerSummary(report({malicious:0,suspicious:0})).label,'No detections reported');
 assert.equal(providerSummary(report({malicious:1,suspicious:0})).label,'Malicious detections');
 assert.equal(providerSummary(report({malicious:0,suspicious:1})).label,'Suspicious detections');
 assert.equal(providerSummary({score:0,severity:'Low'}).label,'Unknown');
});
test('The same AMTSO page report displays its original 12 of 93 engine count',()=>{
 const html=providerPanel({provider_evidence:{provider:'VirusTotal',status:'available',engine_total:93,counts:{malicious:12,suspicious:0,harmless:48,undetected:33},analysis_at:'2026-11-11T05:24:43+00:00',report_id:'f19761934518c3993f38ec9968a19b8d4d48f3ae7b1d9d3c4c6eb2b6e578607f'}},true);
 assert.match(html,/12 \/ 93/);assert.match(html,/2026-11-11T05:24:43/);
 assert.doesNotMatch(html,/class="score"|0-100/);
});
test('Missing or invalid engine counts are never invented as zero',()=>{
 const html=providerPanel({provider_evidence:{provider:'VirusTotal',status:'unavailable',counts:{malicious:null,suspicious:'4',harmless:-1,undetected:true}}});
 assert.equal((html.match(/<strong data-no-translate>Unavailable/g)??[]).length,4);
 assert.match(providerPanel({}),/not retained/);
});
test('Incident rule catalog distinguishes automatic evidence from manual investigation',()=>{
 assert.equal(incidentRules.length,8);const html=incidentRulesPanel();
 assert.match(html,/Unknown and exception-only results do not automatically create cases/);
 assert.match(html,/one investigation per scan/);assert.match(html,/High and Critical threats remain blocked/);
});
test('Evidence export preserves counts but excludes raw reports and secrets',()=>{
 const exported=scanEvidenceExport({provider_evidence:{provider:'VirusTotal',status:'available',counts:{malicious:3,suspicious:0,harmless:null,undetected:8,secret:'PRIVATE'},api_key:'PRIVATE',raw_report:'PRIVATE',analysis_at:'<script>',cached:true,mapping:'extsecure-provider-evidence-v1'}});
 assert.deepEqual(exported.provider_evidence.counts,{malicious:3,suspicious:0,harmless:null,undetected:8});
 assert.equal(exported.provider_evidence.analysis_at,null);assert(!JSON.stringify(exported).includes('PRIVATE'));
});
