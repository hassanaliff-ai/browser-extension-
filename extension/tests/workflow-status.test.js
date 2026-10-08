import test from 'node:test';
import assert from 'node:assert/strict';
import {workflowReadiness,workflowNoticeLabel} from '../operations-ui.js';
const people=[{username:'head',role:'head_administrator'},{username:'manager',role:'manager'}];
const rule={enabled:true,auto_create:true,assignee:'manager',reviewer:'head',escalate_to:'head'};
const runner={running:true,status:'ready'};
test('An empty or disabled setup explains why all automation is inactive',()=>{
 assert.deepEqual(workflowReadiness([],people,runner),{state:'disabled',enabled:0,eligible:0,automatic:0,invalid:0});
 assert.equal(workflowReadiness([{...rule,enabled:false}],people,runner).state,'disabled');
});
test('An enabled valid rule reports readiness for new cases',()=>{
 assert.deepEqual(workflowReadiness([rule],people,runner),{state:'ready',enabled:1,eligible:1,automatic:1,invalid:0});
});
test('Revoked investigators and reviewers cannot be reported as a working automatic rule',()=>{
 for(const key of ['assignee','reviewer'])assert.equal(workflowReadiness([{...rule,[key]:'revoked'}],people,runner).state,'unavailable');
});
test('A manager is not a valid escalation administrator',()=>{
 assert.equal(workflowReadiness([{...rule,escalate_to:'manager'}],people,runner).state,'unavailable');
});
test('A mixed set reports working rules while exposing unavailable recipients',()=>{
 assert.deepEqual(workflowReadiness([rule,{...rule,reviewer:'revoked'}],people,runner),{state:'ready',enabled:2,eligible:1,automatic:1,invalid:1});
});
test('A manual-case rule never claims automatic assignment is enabled',()=>{
 const state=workflowReadiness([{...rule,auto_create:false}],people,runner);
 assert.equal(state.state,'ready');assert.equal(state.automatic,0);
});
test('A stopped or failed runner is not shown as ready even with a valid rule',()=>{
 assert.equal(workflowReadiness([rule],people,{running:false,status:'ready'}).state,'stopped');
 assert.equal(workflowReadiness([rule],people,{running:true,status:'failed'}).state,'failed');
 assert.equal(workflowReadiness([rule],people,{running:true,status:'waiting'}).state,'starting');
});
test('Notification actions have readable labels and preserve unknown phases',()=>{
 assert.equal(workflowNoticeLabel('assigned'),'Incident assigned');assert.equal(workflowNoticeLabel('review_requested'),'Review requested');
 assert.equal(workflowNoticeLabel('escalated'),'Incident escalated');assert.equal(workflowNoticeLabel('custom_phase'),'custom_phase');
});
