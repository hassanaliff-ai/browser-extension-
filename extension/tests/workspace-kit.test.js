import test from 'node:test';
import assert from 'node:assert/strict';
import {connectionBadge,filterRecords,requestedRole,updateAccountReview,resetDestinationReview,validateReportPeriod,safeActiveTab} from '../workspace-kit.js';

test('Weekly reports require a real, completed Monday-based UTC week',()=>{
 const now=new Date('2026-10-07T13:00:00Z');
 assert.equal(validateReportPeriod('weekly','2026-09-28',now),'2026-09-28');
 for(const value of ['2026-10-05','2026-09-29','2026-02-30','2026-13-01','anything','2026-09'])assert.throws(()=>validateReportPeriod('weekly',value,now));
 assert.equal(validateReportPeriod('weekly','2026-09-28',new Date('2026-10-05T00:00:00Z')),'2026-09-28');
});
test('Monthly reports reject incomplete periods and malformed selections',()=>{
 const now=new Date('2026-10-07T13:00:00Z');
 assert.equal(validateReportPeriod('monthly','2026-09',now),'2026-09');
 for(const value of ['2026-10','2026-11','2026-00','2026-09-01'])assert.throws(()=>validateReportPeriod('monthly',value,now));
 assert.throws(()=>validateReportPeriod('yearly','2026',now));
});
test('Account review defaults to the requested role only inside reviewer authority',()=>{
 assert.equal(requestedRole({approvable_roles:['normal_user','manager']},{role:'manager'}),'manager');
 assert.equal(requestedRole({approvable_roles:['normal_user']},{role:'administrator'}),'');
});
test('Changing the person under review resets identity consent and the old reason',()=>{
 const fields={username:{value:'second'},role:{value:'normal_user'},confirmed:{checked:true},reason:{value:'First account identity reviewed'}};
 const form={dataset:{form:'account-review'},querySelector:selector=>fields[selector.match(/name="(.*?)"/)[1]]};
 updateAccountReview(form,{approvable_roles:['normal_user','manager']},[{username:'second',role:'manager'}]);
 assert.equal(fields.role.value,'manager');assert.equal(fields.confirmed.checked,false);assert.equal(fields.reason.value,'');
});
test('Changing a destination clears confirmation and reason for the previous destination',()=>{
 const confirmed={checked:true},reason={value:'Verified original site'};
 resetDestinationReview({dataset:{form:'access-review'},querySelector:s=>s.includes('confirmed')?confirmed:reason});
 assert.equal(confirmed.checked,false);assert.equal(reason.value,'');
});
test('Search exposes a count and a reversible empty state without changing evidence',()=>{
 const rows=[{textContent:'Critical Example.COM',hidden:false},{textContent:'Low Document',hidden:false}];
 const container={querySelectorAll:()=>rows};
 assert.deepEqual(filterRecords(container,'  example.com '),{visible:1,total:2});assert.equal(rows[1].hidden,true);
 assert.deepEqual(filterRecords(container,'nothing'),{visible:0,total:2});
 assert.deepEqual(filterRecords(container,''),{visible:2,total:2});assert(rows.every(row=>!row.hidden));
 assert.equal(rows[0].textContent,'Critical Example.COM');
});
test('Connection states use explicit text and do not inject arbitrary markup',()=>{
 for(const [state,text] of [['ready','API connected'],['offline','API unavailable'],['checking','Checking API…']])assert(connectionBadge(state).includes(text));
 assert.doesNotMatch(connectionBadge('\"><script>alert(1)</script>'),/<script>/);
 assert.match(connectionBadge(),/aria-label="Check API connection"/);
});
test('Only an HTTP or HTTPS page can enable the popup scan action',()=>{
 assert.equal(safeActiveTab({url:'https://example.com/a?x=1'}).host,'example.com');
 for(const url of ['chrome://extensions','chrome://newtab','file:///C:/file.txt','https://user:secret@example.com','not a URL'])assert.deepEqual(safeActiveTab({url}),{url:'',host:''});
});
