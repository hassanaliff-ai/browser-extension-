import test from 'node:test';
import assert from 'node:assert/strict';
import {providerPanel,incidentRulesPanel,incidentRules} from '../provider-panel.js';
import {scanEvidenceExport} from '../evidence-export.js';
test('Provider counts remain separate from the ExtSecure score in popup and console',()=>{
 const result={score:80,provider_evidence:{provider:'VirusTotal',status:'available',counts:{malicious:1,suspicious:2,harmless:60,undetected:4},cached:true,analysis_at:'<script>bad</script>'}};
 for(const compact of [true,false]){const html=providerPanel(result,compact);assert.match(html,/Malicious/);assert.match(html,/Suspicious/);assert.match(html,/Harmless/);assert.match(html,/Undetected/);assert.match(html,/not a VirusTotal score out of 100/);assert.match(html,/Cached report/);assert(!html.includes('<script>'));}
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
