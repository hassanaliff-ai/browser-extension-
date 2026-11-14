import {privateTarget} from './core.js';

export const ALLOW_BASE = 100000;
export function accessTarget(value) {
  const url = new URL(privateTarget(value, true));
  if (!url.hostname.startsWith('[')) url.hostname = url.hostname.replace(/\.$/, '');
  if (url.href.length > 2048) throw new Error('The URL is too long for an approval request.');
  return url.href;
}
export function visitRule(tabId, target, reusable=false) {
  if (!Number.isInteger(tabId) || tabId < 0 || tabId > 2000000000) throw new Error('Invalid browser tab.');
  const escaped = accessTarget(target).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return {id: ALLOW_BASE + tabId, priority: 100, action: {type:'allow'}, condition: {
    regexFilter: '^' + escaped + '(\\?[^#]*)?$', isUrlFilterCaseSensitive:true,
    resourceTypes:['main_frame'], tabIds:[tabId], requestMethods:reusable?['get','post']:['get']}};
}
export function visitLease(grant,session,now=Date.now()) {
  const approval=grant.kind==='whitelist'&&grant.permanent===true?Infinity:Date.parse(grant.expires_at);
  const expiry=Math.min(approval,Date.parse(session.expires_at),now+120000);
  if(!Number.isFinite(expiry)||expiry<=now)throw new Error('The website approval or sign-in has expired. Check approval again.');
  return expiry;
}
async function sessionStamp(session){return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(session.token)))).map(n=>n.toString(16).padStart(2,'0')).join('');}
export function navigationTarget(value){
  const original=new URL(value),approved=new URL(accessTarget(value));
  original.hostname=approved.hostname;
  return original.href;
}

// Static rules redirect before the request is sent, even while this worker sleeps.
// One-time approvals allow one GET. Reusable approvals retain an exact-URL,
// tab-scoped lease, revalidated every minute and bounded by session/grant expiry.
export function registerNavigationGate(request, loadSession, {reconcileThreatHost=async()=>{}}={}) {
  const pending = new Map();
  const navigationVersions = new Map();
  let generation = 0;
  let captureQueue = Promise.resolve();
  let ruleQueue=Promise.resolve();
  const mutate=task=>{const operation=ruleQueue.catch(()=>{}).then(task);ruleQueue=operation;return operation;};
  const clearTab = (tabId,nonce) => mutate(async()=>{
    if(nonce!==undefined&&(await currentVisit(tabId))?.nonce!==nonce)return;
    try { await chrome.declarativeNetRequest.updateSessionRules({removeRuleIds:[ALLOW_BASE+tabId]}); }
    finally { await chrome.storage.session.remove(['visit:'+tabId]); await chrome.alarms.clear('visit:'+tabId); }
  });
  const clear = async ({preserveBlocked=false}={}) => {
    generation++;
    pending.clear();
    await captureQueue;
    return mutate(async()=>{
    const rules = await chrome.declarativeNetRequest.getSessionRules();
    try { await chrome.declarativeNetRequest.updateSessionRules({removeRuleIds:rules.filter(r=>r.id>=ALLOW_BASE).map(r=>r.id)}); }
    finally {
      const stored = await chrome.storage.session.get(null);
      const keys=Object.keys(stored).filter(k=>k.startsWith('visit:')||k.startsWith('approval-attempt:')||(!preserveBlocked&&k.startsWith('blocked:')));
      await chrome.storage.session.remove(keys);
      await Promise.all(keys.map(key=>chrome.alarms.clear(key)));
    }
    });
  };
  const capture=(tabId,url,redirected=false)=>{
    const capturedGeneration=generation;
    captureQueue=captureQueue.then(async()=>{
      if(capturedGeneration!==generation)return;
      await chrome.storage.session.set({['blocked:'+tabId]:{url,captured_at:Date.now(),redirected}});
      await chrome.alarms.create('blocked:'+tabId,{when:Date.now()+30*60*1000});
    }).catch(()=>{});
  };
  // Server redirects do not necessarily emit another onBeforeNavigate. Remember
  // the actual destination so the blocked page cannot reopen the previous URL
  // in an endless redirect loop. Observe navigation metadata only, never bodies.
  chrome.webRequest?.onBeforeRedirect?.addListener(details=>{
    if(details.frameId===0&&details.tabId>=0&&/^https?:\/\//i.test(details.redirectUrl))capture(details.tabId,details.redirectUrl,true);
  },{urls:['http://*/*','https://*/*'],types:['main_frame']});

  const currentVisit=async tabId=>(await chrome.storage.session.get('visit:'+tabId))['visit:'+tabId];
  const clearCurrent=(tabId,entry)=>clearTab(tabId,entry.nonce);
  async function renewVisit(tabId) {
    const entry=await currentVisit(tabId);
    if(!entry?.reusable)return clearTab(tabId);
    const startGeneration=generation;
    try {
      const session=await loadSession();
      if(!session.token||await sessionStamp(session)!==entry.session_stamp)throw new Error('Sign-in changed');
      if(Date.now()>=entry.expires_at)await mutate(async()=>{
        if((await currentVisit(tabId))?.nonce===entry.nonce)await chrome.declarativeNetRequest.updateSessionRules({removeRuleIds:[ALLOW_BASE+tabId]});
      });
      const grant=await request('/api/access/check','POST',{target:entry.target});
      if(!grant.allowed||grant.threat_blocked||!['temporary','whitelist'].includes(grant.kind))throw new Error('Approval unavailable');
      const expires=visitLease(grant,session);
      if(startGeneration!==generation||(await currentVisit(tabId))?.nonce!==entry.nonce)return;
      const latest=await loadSession();
      if(!latest.token||await sessionStamp(latest)!==entry.session_stamp)throw new Error('Sign-in changed');
      await mutate(async()=>{
      const current=(await chrome.storage.session.get('session')).session;
      if(startGeneration!==generation||(await currentVisit(tabId))?.nonce!==entry.nonce||current?.token!==latest.token)return;
      await chrome.declarativeNetRequest.updateSessionRules({removeRuleIds:[ALLOW_BASE+tabId],addRules:[visitRule(tabId,entry.target,true)]});
      await chrome.storage.session.set({['visit:'+tabId]:{...entry,expires_at:expires}});
      await chrome.alarms.create('visit:'+tabId,{when:Math.min(Date.now()+60000,expires)});
      });
    }catch{await clearCurrent(tabId,entry);}
  }
  chrome.webNavigation.onBeforeNavigate.addListener(details => {
    if(details.frameId!==0)return;
    navigationVersions.set(details.tabId,(navigationVersions.get(details.tabId)??0)+1);
    if(!/^https?:\/\//i.test(details.url))return;
    // Original query parameters stay only in trusted, ephemeral browser memory.
    capture(details.tabId,details.url);
  });
  chrome.webNavigation.onCommitted.addListener(details=>{
    if(details.frameId!==0 || !/^https?:\/\//i.test(details.url))return;
    void (async()=>{
      const entry=await currentVisit(details.tabId);
      if(!entry?.reusable||entry.expires_at<=Date.now())await clearTab(details.tabId);
      await captureQueue;
      const blocked=(await chrome.storage.session.get('blocked:'+details.tabId))['blocked:'+details.tabId];
      if(blocked&&accessTarget(blocked.url)===accessTarget(details.url))await chrome.storage.session.remove('blocked:'+details.tabId);
      await chrome.storage.session.remove('approval-attempt:'+details.tabId);
    })().catch(()=>{});
  });
  chrome.webNavigation.onErrorOccurred.addListener(details=>{
    if(details.frameId===0)void (async()=>{if(!(await currentVisit(details.tabId))?.reusable)await clearTab(details.tabId);})().catch(()=>{});
  });
  chrome.tabs.onRemoved.addListener(tabId=>{
    navigationVersions.set(tabId,(navigationVersions.get(tabId)??0)+1);
    void captureQueue.then(()=>clearTab(tabId)).then(()=>chrome.storage.session.remove(['blocked:'+tabId,'approval-attempt:'+tabId])).finally(()=>navigationVersions.delete(tabId)).catch(()=>{});
  });
  chrome.alarms.onAlarm.addListener(alarm=>{
    if(alarm.name.startsWith('visit:'))void renewVisit(Number(alarm.name.slice(6))).catch(()=>{});
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
    return {tabId:sender.tab.id,target:accessTarget(item.url),original:item.url,redirected:item.redirected===true,capturedAt:item.captured_at,navigationVersion:navigationVersions.get(sender.tab.id)??0};
  }
  async function open(sender,{automatic=false}={}) {
    const {tabId,target,original,redirected,navigationVersion}=await context(sender);
    if(pending.has(tabId))throw new Error('This website is already being opened.');
    const operation=Symbol('approved navigation'),openingGeneration=generation;
    pending.set(tabId,operation);
    const unchanged=()=>{
      if(openingGeneration!==generation || (navigationVersions.get(tabId)??0)!==navigationVersion)
        throw new Error('The browser tab or sign-in changed. Open the current blocked destination again.');
    };
    try {
      const attemptsKey='approval-attempt:'+tabId;
      if(automatic&&redirected){
        const count=(await chrome.storage.session.get(attemptsKey))[attemptsKey]?.count??0;
        if(count>=8)throw new Error('Automatic reopening stopped because this website keeps redirecting. Review the destination, then open it manually.');
        await chrome.storage.session.set({[attemptsKey]:{count:count+1}});
      }else await chrome.storage.session.remove(attemptsKey);
      const openingSession=await loadSession();
      if(!openingSession.token)throw Object.assign(new Error('Sign in with your approved account first.'),{status:401});
      const check=await request('/api/access/check','POST',{target});
      if(check.threat_blocked)throw new Error('High-risk threat is blocked. Resolve its investigation before requesting release.');
      if(check.containment_checked===true)await reconcileThreatHost(target,false);
      unchanged();
      let rule=visitRule(tabId,target);
      const supported=await chrome.declarativeNetRequest.isRegexSupported({regex:rule.condition.regexFilter,isCaseSensitive:true});
      if(!supported.isSupported)throw new Error('Chrome cannot safely match this URL. It remains blocked.');
      unchanged();
      const grant=await request('/api/access/consume','POST',{target});
      if(!grant.allowed)throw new Error('This website has not been approved.');
      const reusable=['temporary','whitelist'].includes(grant.kind);
      const expires=reusable?visitLease(grant,openingSession):Math.min(Date.now()+30000,Date.parse(openingSession.expires_at));
      if(reusable)rule=visitRule(tabId,target,true);
      const stamp=reusable?await sessionStamp(openingSession):null;
      unchanged();
      await mutate(async()=>{
      unchanged();
      const current=(await chrome.storage.session.get('session')).session;
      if(current?.token!==openingSession.token)throw new Error('Sign-in changed');
      await chrome.declarativeNetRequest.updateSessionRules({removeRuleIds:[rule.id],addRules:[rule]});
      await chrome.storage.session.set({['visit:'+tabId]:{target,expires_at:expires,reusable,session_stamp:stamp,nonce:crypto.randomUUID()}});
      await chrome.alarms.create('visit:'+tabId,{when:reusable?Math.min(Date.now()+60000,expires):expires});
      });
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
