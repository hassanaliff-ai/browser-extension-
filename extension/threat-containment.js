import {privateTarget} from './core.js';
export const THREAT_RULE_BASE=50000;
const KEY='threatContainment';
let queue=Promise.resolve();
export function threatHost(value){return new URL(privateTarget(value,true)).hostname.toLowerCase().replace(/\.$/,'');}
export function threatRule(host,id){
 if(!Number.isInteger(id)||id<THREAT_RULE_BASE||id>=100000)throw new Error('Invalid threat rule ID.');
 const normalized=threatHost('https://'+host+'/');
 if(normalized!==host)throw new Error('Invalid threat hostname.');
 const escaped=host.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
 return {id,priority:10000,action:{type:'redirect',redirect:{extensionPath:'/blocked.html'}},condition:{regexFilter:'^https?://'+escaped+'(?::[0-9]+)?(?:/|$)',isUrlFilterCaseSensitive:false,resourceTypes:['main_frame']}};
}
async function saveRules(rows){
 const old=await chrome.declarativeNetRequest.getDynamicRules();
 const addRules=rows.filter(r=>r.active&&r.host).flatMap((r,i)=>{
  const navigation=threatRule(r.host,THREAT_RULE_BASE+i*2);
  return [navigation,{...navigation,id:navigation.id+1,action:{type:'block'},condition:{...navigation.condition,resourceTypes:['sub_frame','script','stylesheet','image','font','object','xmlhttprequest','ping','media','websocket','other']}}];
 });
 if(addRules.length>4000)throw new Error('Threat rule capacity reached. The destination remains denied by the approval gate.');
 // Persist before installation; a worker restart can restore the same block.
 await chrome.storage.local.set({[KEY]:rows});
 await chrome.declarativeNetRequest.updateDynamicRules({removeRuleIds:old.filter(r=>r.id>=THREAT_RULE_BASE&&r.id<100000).map(r=>r.id),addRules});
}
function serial(task){const next=queue.catch(()=>{}).then(task);queue=next;return next;}
export async function containThreat(result,target,clearGrants){
 if(!result?.containment?.active&&!['High','Critical'].includes(result?.severity))return {blocked:false};
 const host=result.target_kind==='url'||target?threatHost(target):null;
 const block=result.containment;
 if(!block?.id)throw new Error('High-risk threat detected. Backend containment is unavailable; do not open this destination or file.');
 await clearGrants({preserveBlocked:true});
 await serial(async()=>{
  const saved=(await chrome.storage.local.get(KEY))[KEY]??[];
  const entry={id:block.id,kind:block.kind,fingerprint:block.fingerprint,active:true,host,severity:block.severity,scan_id:block.scan_id};
  await saveRules([...saved.filter(r=>r.id!==entry.id),entry]);
 });
 if(host){
  const tabs=await chrome.tabs.query({});
  for(const tab of tabs){try{if(Number.isInteger(tab.id)&&threatHost(tab.url)===host){
   await chrome.storage.session.set({['blocked:'+tab.id]:{url:privateTarget(tab.url,true),captured_at:Date.now()}});
   await chrome.tabs.update(tab.id,{url:chrome.runtime.getURL('blocked.html')});
  }}catch(error){if(error?.message?.includes('Invalid')||!/^https?:/.test(tab.url??''))continue;throw error;}}
 }
 return {blocked:true,scope:host?'hostname':'file_hash'};
}
export async function reconcileThreatHost(target,blocked){
 if(blocked)return;
 const host=threatHost(target);
 await serial(async()=>{const rows=(await chrome.storage.local.get(KEY))[KEY]??[];if(rows.some(r=>r.host===host))await saveRules(rows.filter(r=>r.host!==host));});
}
export async function restoreThreatRules(){return serial(async()=>saveRules((await chrome.storage.local.get(KEY))[KEY]??[]));}
