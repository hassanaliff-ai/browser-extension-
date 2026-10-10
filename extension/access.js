import {privateTarget} from './core.js';

export const ALLOW_BASE = 100000;
export function accessTarget(value) {
  const url = new URL(privateTarget(value, true));
  if (!url.hostname.startsWith('[')) url.hostname = url.hostname.replace(/\.$/, '');
  if (url.href.length > 2048) throw new Error('The URL is too long for an approval request.');
  return url.href;
}
export function visitRule(tabId, target) {
  if (!Number.isInteger(tabId) || tabId < 0 || tabId > 2000000000) throw new Error('Invalid browser tab.');
  const escaped = accessTarget(target).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return {id: ALLOW_BASE + tabId, priority: 100, action: {type:'allow'}, condition: {
    regexFilter: '^' + escaped + '(\\?[^#]*)?$', isUrlFilterCaseSensitive:true,
    resourceTypes:['main_frame'], tabIds:[tabId], requestMethods:['get']}};
}
export function navigationTarget(value){
  const original=new URL(value),approved=new URL(accessTarget(value));
  original.hostname=approved.hostname;
  return original.href;
}

// Static rules redirect before the request is sent, even while this worker sleeps.
// A temporary allow rule grants one GET navigation in one tab. It is removed on
// commit/error/closure and by a 30-second alarm if navigation never completes.
export function registerNavigationGate(request, loadSession, {reconcileThreatHost=async()=>{}}={}) {
  const pending = new Map();
  const navigationVersions = new Map();
  let generation = 0;
  let captureQueue = Promise.resolve();
  const clearTab = async tabId => {
    try { await chrome.declarativeNetRequest.updateSessionRules({removeRuleIds:[ALLOW_BASE+tabId]}); }
    finally { await chrome.storage.session.remove(['visit:'+tabId]); await chrome.alarms.clear('visit:'+tabId); }
  };
  const clear = async ({preserveBlocked=false}={}) => {
    generation++;
    pending.clear();
    await captureQueue;
    const rules = await chrome.declarativeNetRequest.getSessionRules();
    try { await chrome.declarativeNetRequest.updateSessionRules({removeRuleIds:rules.filter(r=>r.id>=ALLOW_BASE).map(r=>r.id)}); }
    finally {
      const stored = await chrome.storage.session.get(null);
      const keys=Object.keys(stored).filter(k=>k.startsWith('visit:')||(!preserveBlocked&&k.startsWith('blocked:')));
      await chrome.storage.session.remove(keys);
      await Promise.all(keys.map(key=>chrome.alarms.clear(key)));
    }
  };
  chrome.webNavigation.onBeforeNavigate.addListener(details => {
    if(details.frameId!==0)return;
    navigationVersions.set(details.tabId,(navigationVersions.get(details.tabId)??0)+1);
    if(!/^https?:\/\//i.test(details.url))return;
    const capturedGeneration=generation;
    // Original query parameters stay only in trusted, ephemeral browser memory.
    captureQueue = captureQueue.then(async()=>{
      if(capturedGeneration!==generation)return;
      await chrome.storage.session.set({['blocked:'+details.tabId]:{url:details.url,captured_at:Date.now()}});
      await chrome.alarms.create('blocked:'+details.tabId,{when:Date.now()+30*60*1000});
    }).catch(()=>{});
  });
  chrome.webNavigation.onCommitted.addListener(details=>{
    if(details.frameId!==0 || !/^https?:\/\//i.test(details.url))return;
    void (async()=>{
      await clearTab(details.tabId);await chrome.storage.session.remove('blocked:'+details.tabId);
    })().catch(()=>{});
  });
  chrome.webNavigation.onErrorOccurred.addListener(details=>{
    if(details.frameId===0)void clearTab(details.tabId).catch(()=>{});
  });
  chrome.tabs.onRemoved.addListener(tabId=>{
    navigationVersions.set(tabId,(navigationVersions.get(tabId)??0)+1);
    void captureQueue.then(()=>clearTab(tabId)).then(()=>chrome.storage.session.remove('blocked:'+tabId)).finally(()=>navigationVersions.delete(tabId)).catch(()=>{});
  });
  chrome.alarms.onAlarm.addListener(alarm=>{
    if(alarm.name.startsWith('visit:'))void clearTab(Number(alarm.name.slice(6))).catch(()=>{});
    if(alarm.name.startsWith('blocked:'))void chrome.storage.session.remove(alarm.name).catch(()=>{});
  });
  chrome.runtime.onStartup.addListener(()=>void clear().catch(()=>{}));
  chrome.runtime.onInstalled.addListener(()=>void clear().catch(()=>{}));

  async function context(sender) {
    if(sender.frameId!==0 || !Number.isInteger(sender.tab?.id) || !sender.url?.startsWith(chrome.runtime.getURL('blocked.html')))
      throw new Error('Open the blocked website tab to continue.');
    await captureQueue;
    const item=(await chrome.storage.session.get('blocked:'+sender.tab.id))['blocked:'+sender.tab.id];
    if(!item || !Number.isFinite(item.captured_at) || item.captured_at>Date.now() || Date.now()-item.captured_at>30*60*1000)throw new Error('The blocked destination expired. Try visiting the website again.');
    return {tabId:sender.tab.id,target:accessTarget(item.url),original:item.url,capturedAt:item.captured_at,navigationVersion:navigationVersions.get(sender.tab.id)??0};
  }
  async function open(sender) {
    const {tabId,target,original,navigationVersion}=await context(sender);
    if(pending.has(tabId))throw new Error('This website is already being opened.');
    const operation=Symbol('approved navigation'),openingGeneration=generation;
    pending.set(tabId,operation);
    const unchanged=()=>{
      if(openingGeneration!==generation || (navigationVersions.get(tabId)??0)!==navigationVersion)
        throw new Error('The browser tab or sign-in changed. Open the current blocked destination again.');
    };
    try {
      const openingSession=await loadSession();
      if(!openingSession.token)throw Object.assign(new Error('Sign in with your approved account first.'),{status:401});
      const check=await request('/api/access/check','POST',{target});
      if(check.threat_blocked)throw new Error('High-risk threat is blocked. Resolve its investigation before requesting release.');
      if(check.containment_checked===true)await reconcileThreatHost(target,false);
      unchanged();
      const rule=visitRule(tabId,target);
      const supported=await chrome.declarativeNetRequest.isRegexSupported({regex:rule.condition.regexFilter,isCaseSensitive:true});
      if(!supported.isSupported)throw new Error('Chrome cannot safely match this URL. It remains blocked.');
      unchanged();
      const grant=await request('/api/access/consume','POST',{target});
      if(!grant.allowed)throw new Error('This website has not been approved.');
      unchanged();
      await chrome.declarativeNetRequest.updateSessionRules({removeRuleIds:[rule.id],addRules:[rule]});
      await chrome.storage.session.set({['visit:'+tabId]:{target,expires_at:Date.now()+30000}});
      await chrome.alarms.create('visit:'+tabId,{when:Date.now()+30000});
      const latestSession=await loadSession();
      if(!latestSession.token||latestSession.token!==openingSession.token)throw new Error('Sign in again before opening this website.');
      unchanged();
      await chrome.tabs.update(tabId,{url:navigationTarget(original)});
      return {opened:true,kind:grant.kind};
    } catch(error) {
      await clearTab(tabId);
      throw error;
    } finally { if(pending.get(tabId)===operation)pending.delete(tabId); }
  }
  return {context,open,clear};
}
