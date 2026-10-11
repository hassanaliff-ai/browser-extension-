import test from 'node:test';
import assert from 'node:assert/strict';
import {applyExtensionControls} from '../extension-controls.js';
import {installedExtensions} from '../inventory.js';
const id='b'.repeat(32),selfId='a'.repeat(32);
const command=(desired,status='pending')=>({chrome_id:id,extension_id:'test-row',revision:1,desired,status});
function environment(enabled=true){
 const state={enabled,installed:true},receipts=[],calls=[];
 const management={get:async()=>{if(!state.installed)throw new Error('missing');return {id,type:'extension',enabled:state.enabled,mayDisable:true,mayEnable:true};},setEnabled:async(id,value)=>{calls.push(value);state.enabled=value;},uninstall:async(id,options)=>{assert.equal(options.showConfirmDialog,true);calls.push('uninstall');state.installed=false;}};
 return {state,calls,receipts,options:{management,selfId,receipt:async(id,body)=>receipts.push(body)}};
}
test('Installed snapshots include disabled extensions without permissions or descriptions',()=>{
 const items=installedExtensions([{id,name:'Disabled',version:'1',type:'extension',enabled:false,permissions:['tabs'],description:'private',mayDisable:false}]);
 assert.deepEqual(items,[{id,name:'Disabled',version:'1',enabled:false,may_disable:false,may_enable:true}]);
});
test('Turn off and block apply real management state and acknowledge only after verification',async()=>{
 for(const desired of ['disabled','blocked']){const env=environment();await applyExtensionControls([command(desired)],env.options);assert.deepEqual(env.calls,[false]);assert.equal(env.receipts[0].status,'applied');}
});
test('Turn on and removal wait for a deliberate user action',async()=>{
 for(const desired of ['enabled','removed']){const env=environment(false);await applyExtensionControls([command(desired)],env.options);assert.equal(env.calls.length,0);await applyExtensionControls([command(desired)],{...env.options,interactive:true});assert.equal(env.receipts[0].status,'applied');}
});
test('Persistent blocks re-disable a manually re-enabled extension without duplicate work when already disabled',async()=>{
 const env=environment(false);await applyExtensionControls([command('blocked','applied')],env.options);assert.equal(env.receipts.length,0);env.state.enabled=true;await applyExtensionControls([command('blocked','applied')],env.options);assert.equal(env.state.enabled,false);
});
test('Self and invalid extension IDs never reach management actions',async()=>{
 const env=environment();await applyExtensionControls([{...command('removed'),chrome_id:selfId},{...command('disabled'),chrome_id:'bad'}],{...env.options,interactive:true});assert.equal(env.calls.length,0);
});
test('Chrome restrictions and cancelled uninstall confirmations are visible failures',async()=>{
 const env=environment();env.options.management.get=async()=>({type:'extension',enabled:true,mayDisable:false});await applyExtensionControls([command('blocked')],env.options);assert.equal(env.receipts[0].error,'chrome_restricted');
 const cancel=environment();cancel.options.management.uninstall=async()=>{throw new Error('User cancelled');};await applyExtensionControls([command('removed')],{...cancel.options,interactive:true});assert.equal(cancel.receipts[0].error,'confirmation_cancelled');
});
test('Already uninstalled extension acknowledges removal without another native dialog',async()=>{
 const env=environment();env.state.installed=false;await applyExtensionControls([command('removed')],{...env.options,interactive:true});assert.equal(env.calls.length,0);assert.equal(env.receipts[0].status,'applied');
});
