import test from 'node:test';
import assert from 'node:assert/strict';
import {safeApiPath} from '../core.js';
globalThis.location={protocol:'https:',hostname:'example.com',port:''};
const {previousPeriod,explanationForm,runExplanation,runPeriodReport,automaticReportStatus}=await import('../intelligence-ui.js');
test('AI API routes are narrow and cannot call arbitrary model endpoints',()=>{
 assert.equal(safeApiPath('/api/intelligence/scans/test-id/explain','POST'),true);
 assert.equal(safeApiPath('/api/intelligence/reports?limit=100','GET'),true);
 for(const path of ['/api/intelligence/scans/../../admin/explain','/api/intelligence/provider','/api/intelligence/reports/delete','/api/intelligence/reports?url=https://evil.test'])assert.equal(safeApiPath(path,'POST'),false);
});
test('Optional content sharing is opt-in and scan references are escaped',()=>{
 const markup=explanationForm({id:'"/><script>alert(1)</script>'});
 assert.equal(markup.includes('<script>'),false);assert.match(markup,/&lt;script&gt;/);
 assert.match(markup,/name="consent_content">/);assert.equal(markup.includes('name="consent_content" checked'),false);
});
test('Default weekly and monthly selections use completed UTC periods at rollover',()=>{
 const NativeDate=Date;
 globalThis.Date=class extends NativeDate{constructor(...args){super(...(args.length?args:['2027-01-01T00:30:00Z']));}};
 try{assert.equal(previousPeriod('weekly'),'2026-12-21');assert.equal(previousPeriod('monthly'),'2026-12');}finally{globalThis.Date=NativeDate;}
});

test('Optional file content is never read before explicit content-sharing consent',async()=>{
 const OriginalFormData=globalThis.FormData;let read=false;
 const file={size:10,arrayBuffer:async()=>{read=true;return new ArrayBuffer(10);}};
 globalThis.FormData=class{get(key){return key==='context_file'?file:'';}has(){return false;}};
 try{await assert.rejects(runExplanation({}),/Confirm optional content sharing/);assert.equal(read,false);}
 finally{globalThis.FormData=OriginalFormData;}
});
test('Invalid weekly period is rejected before any AI generation call',async()=>{
 const OriginalFormData=globalThis.FormData;
 globalThis.FormData=class{get(key){return key==='kind'?'weekly':'2026-09-29';}};
 try{await assert.rejects(runPeriodReport({}),/completed week beginning on Monday/);}
 finally{globalThis.FormData=OriginalFormData;}
});


test('The report screen distinguishes a failed run from an earlier successful run',()=>{
 const html=automaticReportStatus({runs:{weekly:{},monthly:{last_success:{at:'2026-11-01T06:00:00Z'},last_attempt:{status:'failed',stage:'local_ai',at:'2026-11-02T06:10:00Z'},next_scheduled_at:'2026-12-01T06:00:00Z',next_recovery_at:'2026-11-03T06:10:00Z'}}});
 assert.match(html,/Last successful run/);assert.match(html,/1 Nov 2026/);
 assert.match(html,/Local AI was unavailable/);assert.match(html,/Next recovery check/);
 assert.match(html,/No automatic attempts recorded/);
 assert.match(automaticReportStatus({enabled:true}),/history is unavailable/);
});
