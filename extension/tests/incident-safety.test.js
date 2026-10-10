import test from 'node:test';
import assert from 'node:assert/strict';
import {incidentActionBody, incidentSafetyPanel} from '../incident-safety.js';
import {safeApiPath, roleCanWrite} from '../core.js';

const row = {id:'case-1', revision:3, device_protection:{registered:true, blocked:false, revision:7}, safety_plan:{actions:[{code:'user_notified',description:'Notify user',completed:false}]}};
test('Incident removal requires explicit confirmation and carries the reviewed revision', () => {
  assert.throws(() => incidentActionBody('case-remove',{confirmed:'false'},row),/Confirm/);
  assert.deepEqual(incidentActionBody('case-remove',{confirmed:'on',reason:'Duplicate investigation'},row),{confirmed:true,expected_revision:3,reason:'Duplicate investigation'});
});
test('Device protection requires both case and registered-device revisions', () => {
  assert.equal(incidentActionBody('case-block-device',{confirmed:true},row).expected_device_revision,7);
  assert.throws(() => incidentActionBody('case-block-device',{confirmed:true},{...row,device_protection:{registered:false}}),/registered device/);
});
test('Only offered safety actions are submitted; an empty confirmation is rejected', () => {
  assert.throws(() => incidentActionBody('case-safety',{},row),/at least one/);
  assert.deepEqual(incidentActionBody('case-safety',{safety_user_notified:'on',safety_fake:'on'},row).checks,['user_notified']);
});
test('Sensitive incident controls are absent for managers while safety review remains available', () => {
  const c={notice:t=>t,details:(t,x)=>t+x,form:(action,x)=>action+x,check:t=>t,reason:()=>'',can:a=>roleCanWrite({role:'manager'},a)};
  const html=incidentSafetyPanel(row,c);
  assert.match(html,/case-safety/);assert.doesNotMatch(html,/case-remove|case-block-device/);
  assert(safeApiPath('/api/cases/case-1/remove','POST'));assert(safeApiPath('/api/cases/case-1/safety','POST'));assert(safeApiPath('/api/cases/case-1/block-device','POST'));
  assert(!safeApiPath('/api/cases/case-1/remove','DELETE'));
});
