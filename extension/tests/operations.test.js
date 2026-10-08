import test from 'node:test';
import assert from 'node:assert/strict';
import {safeApiPath,roleCanWrite} from '../core.js';
import {reportNavigation} from '../access.js';
import {workflowBody,controlReviewBody,controlReferences,updateControlReference} from '../operations-ui.js';

test('Operations API grants are narrow and reject unsupported paths and methods',()=>{
 for(const path of ['/api/operations/status','/api/workflow/rules','/api/workflow/notifications','/api/controls/reviews','/api/controls/effectiveness?days=30'])assert(safeApiPath(path));
 for(const path of ['/api/workflow/run','/api/controls/reviews','/api/controls/navigation',`/api/workflow/rules/${'a'.repeat(8)}-${'b'.repeat(27)}/update`,`/api/workflow/notifications/${'c'.repeat(64)}/acknowledge`])assert(safeApiPath(path,'POST'));
 for(const path of ['/api/workflow/rules/../admin/me','/api/workflow/rules?token=secret','/api/controls/effectiveness?days=30&token=secret'])assert(!safeApiPath(path));
 assert(!safeApiPath('/api/workflow/run','DELETE'));
 assert(!safeApiPath('/api/operations/status','POST'));
 assert(!roleCanWrite({role:'manager'},'workflow'));
 assert(roleCanWrite({role:'administrator'},'workflow'));
});

test('Rule forms use explicit booleans and revision checks for edits',()=>{
 const fields={name:'Priority incident',priority:'20',minimum_severity:'High',target_kind:'url',assignee:'manager',reviewer:'administrator',escalate_after_hours:'24',escalate_to:'head',reason:'Review and assign incident handling',auto_create:'on'};
 const body=workflowBody(fields,7);
 assert.equal(body.enabled,false);assert.equal(body.auto_create,true);assert.equal(body.notify_reviewer,false);
 assert.equal(body.escalate_after_hours,24);assert.equal(body.expected_revision,7);
 assert.equal(workflowBody({...fields,enabled:'on',notify_reviewer:'on'}).notify_reviewer,true);
});

test('Evidence choices belong to the selected control and exceptions require an applied override',()=>{
 const records=[{type:'scan',id:'s1',label:'Scan',override:false},{type:'scan',id:'s2',label:'Exception scan',override:true},
  {type:'alert',id:'a1',label:'Alert'},{type:'access_request',id:'r1',label:'Access'}];
 assert.deepEqual(controlReferences(records,'approvals'),[['access_request:r1','Access']]);
 assert.deepEqual(controlReferences(records,'exceptions'),[['scan:s2','Exception scan']]);
 assert.equal(controlReferences(records,'blocking').length,3);
 assert.deepEqual(controlReferences(records,'alerts'),[['alert:a1','Alert']]);
 assert.deepEqual(controlReferences(records,'unknown'),[]);
});

test('Changing a control disables submission when no relevant evidence exists',()=>{
 const button={},input={value:'scan:previous'},form={elements:{reference:input,control:{value:'exceptions'}},querySelector:()=>button};
 updateControlReference(form,[]);assert.equal(input.innerHTML,'');assert(button.disabled);assert(input.required);
 form.elements.control.value='blocking';updateControlReference(form,[{type:'scan',id:'s1',label:'<unsafe>'}]);
 assert.equal(button.disabled,false);assert(input.innerHTML.includes('&lt;unsafe&gt;'));
});

test('Review forms require a recorded reference and preserve the assessment evidence',()=>{
 assert.throws(()=>controlReviewBody({reference:'scan:id:extra'}),/recorded evidence/);
 assert.throws(()=>controlReviewBody({reference:''}),/recorded evidence/);
 assert.deepEqual(controlReviewBody({reference:'scan:example',control:'blocking',outcome:'inconclusive',ground_truth:'unknown',evidence:'Needs independent validation.'}),
  {reference_type:'scan',reference_id:'example',control:'blocking',outcome:'inconclusive',ground_truth:'unknown',evidence:'Needs independent validation.'});
});

test('Navigation evidence strips private parameters and reuses the event key across retries',async()=>{
 const calls=[],request=async(...args)=>calls.push(args),session=async()=>({token:'synthetic',profile:{username:'sample'}});
 const context={tabId:12,capturedAt:1000,original:'https://example.com/path?password=PRIVATE#secret'};
 await reportNavigation(request,session,context,'blocked');await reportNavigation(request,session,context,'blocked');
 assert.equal(calls[0][2].target,'https://example.com/path');assert.equal(calls[0][2].event_id,calls[1][2].event_id);
 assert.match(calls[0][2].event_id,/^[a-f0-9]{64}$/);
});

test('A telemetry outage and signed-out navigation never weaken the gate or expose a target',async()=>{
 let calls=0;
 const request=async()=>{calls++;throw new Error('Offline');},context={tabId:1,capturedAt:1,original:'https://example.com/'};
 await reportNavigation(request,async()=>({}),context,'blocked');assert.equal(calls,0);
 await reportNavigation(request,async()=>({token:'test',profile:{username:'sample'}}),context,'blocked');assert.equal(calls,1);
});
