import test from 'node:test';
import assert from 'node:assert/strict';
import {actionTone,actionDisclosure,handleActionPanelClick,dismissActionPanel,setActionPanelBusy} from '../action-panels.js';
test('Inventory removal and restore have distinct action treatments',()=>{
 assert.equal(actionTone('inventory-remove','<input name="restore" value="no">'),'danger');
 assert.equal(actionTone('inventory-remove','<input name="restore" value="yes">'),'restore');
 assert.equal(actionTone('case-remove'),'danger');
 assert.equal(actionTone('device-connect'),'add');
 assert.equal(actionTone('extension-control'),'manage');
});
test('Form disclosures gain a review trigger without changing their fields',()=>{
 const form='<form data-form="inventory-remove"><input name="record_id" value="test"><input name="confirmed" required></form>';
 const html=actionDisclosure('Remove',form);
 assert.match(html,/data-action-panel/);assert.match(html,/data-action-tone="danger"/);assert(html.includes(form));assert.match(html,/aria-hidden="true"/);
});
test('Read-only details stay native and unsafe titles are escaped',()=>{
 assert.match(actionDisclosure('Read evidence','<p>Details</p>'),/modern-disclosure/);
 assert.doesNotMatch(actionDisclosure('<img src=x onerror=evil()>','<form data-form="device-connect"></form>'),/<img/);
});
test('Unrelated UI clicks and calls without an open dialog are harmless',()=>{
 assert.equal(handleActionPanelClick({target:{closest:()=>null}}),false);
 assert.doesNotThrow(()=>dismissActionPanel());assert.doesNotThrow(()=>setActionPanelBusy(true));
});

import {validationMessage} from '../form-validation.js';
test('Inline validation distinguishes confirmation and required choice without echoing field values',()=>{
 assert.match(validationMessage({type:'checkbox',value:'PRIVATE',validity:{valueMissing:true}}),/Confirm/);
 assert.match(validationMessage({type:'radio',value:'PRIVATE',validity:{valueMissing:true}}),/Choose/);
 assert.doesNotMatch(validationMessage({type:'text',value:'PRIVATE',validity:{tooShort:true}}),/PRIVATE/);
});
