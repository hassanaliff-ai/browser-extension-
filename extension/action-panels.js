// Native review dialogs keep the original forms and backend safety checks intact.
import {escapeHtml as esc} from './core.js';
import {translate} from './locale.js';
const glyphs={add:'M12 5v14M5 12h14',danger:'M3 6h18M9 6V4h6v2M6 6l1 14h10l1-14M10 10v6M14 10v6',manage:'M4 7h16M7 4v6M4 17h16M17 14v6',restore:'M3 10a9 9 0 1 1 2 8M3 4v6h6'};
const icon=kind=>`<svg class="action-glyph" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="${glyphs[kind]??glyphs.manage}"/></svg>`;
export function actionTone(action,content=''){
 if(action==='inventory-remove'&&/name="restore" value="yes"/.test(content))return 'restore';
 if(['inventory-remove','case-remove','account-access','override-deactivate'].includes(action))return 'danger';
 if(/^(device-add|device-connect|device-pair|override-create|suggestion-submit|usability-create)$/.test(action))return 'add';
 return 'manage';
}
export function actionDisclosure(title,content){
 if(!/<form\b/.test(content))return `<details class="modern-disclosure"><summary>${esc(title)}</summary>${content}</details>`;
 const action=content.match(/data-form="([a-z-]+)"/)?.[1]??'';
 const tone=actionTone(action,content);
 return `<details class="action-entry" data-action-panel data-action-title="${esc(title)}" data-action-tone="${tone}"><summary>${icon(tone)}<span class="action-label">${esc(title)}</span><span class="action-entry-arrow" aria-hidden="true">↗</span></summary>${content}</details>`;
}
export function deviceAccessChoices(reviewer){
 return `<fieldset class="access-choices"><legend>Device access before adding</legend><div class="access-choice-grid"><label class="access-choice"><input type="radio" name="initial_access" value="trusted" required><span><strong>Trusted device</strong><span class="meta">${reviewer?'Allow ExtSecure activity on this device.':'Request administrator approval for this device.'}</span></span></label><label class="access-choice" data-choice="blocked"><input type="radio" name="initial_access" value="blocked" required><span><strong>Blocked device</strong><span class="meta">Add to inventory with ExtSecure access blocked.</span></span></label></div></fieldset>`;
}
let active,sequence=0;
export function setActionPanelBusy(value){
 if(!active)return;
 active.busy=!!value;
 active.dialog.setAttribute('aria-busy',String(!!value));
 active.dialog.querySelectorAll('[data-action-panel-close]').forEach(button=>button.disabled=!!value);
}
export function dismissActionPanel({restore=true,focus=true}={}){
 if(!active)return;
 const entry=active;active=null;
 entry.dialog.close();
 if(restore){
  entry.dialog.querySelectorAll('input[name=confirmed],input[name=initial_access]').forEach(input=>input.checked=false);
  for(const node of [...entry.body.childNodes])entry.host.append(node);
  entry.host.open=false;
 }
 entry.dialog.remove();
 if(focus&&entry.trigger.isConnected)entry.trigger.focus({preventScroll:true});
}
function openPanel(host,trigger,isBusy){
 if(active)return false;
 const dialog=document.createElement('dialog'),tone=host.dataset.actionTone??'manage';
 const id='action-review-'+ ++sequence;
 let title=host.dataset.actionTitle??trigger.textContent.trim();
 const form=host.querySelector('form');
 if(form?.dataset.form==='inventory-remove'){
  const kind=form.querySelector('[name=kind]')?.value;
  const restore=form.querySelector('[name=restore]')?.value==='yes';
  if(kind==='devices')title=restore?'Restore device':'Remove device';
  if(kind==='extensions')title=restore?'Restore extension':'Remove extension';
 }
 dialog.className='action-dialog';dialog.dataset.actionTone=tone;
 dialog.setAttribute('aria-labelledby',id);
 dialog.innerHTML=`<header class="action-dialog-header"><span class="action-dialog-icon">${icon(tone)}</span><div><p class="action-kicker">${esc(translate('Review change'))}</p><h2 id="${id}">${esc(translate(title))}</h2></div><button type="button" class="action-dialog-close" data-action-panel-close aria-label="${esc(translate('Close review'))}">×</button></header><div class="action-dialog-body"></div>`;
 const body=dialog.querySelector('.action-dialog-body');
 for(const node of [...host.childNodes])if(node!==trigger)body.append(node);
 for(const current of body.querySelectorAll('form')){
  const footer=current.querySelector('.form-actions');
  if(footer&&!footer.querySelector('[data-action-panel-close]')){
   const cancel=document.createElement('button');cancel.type='button';cancel.className='btn ghost dialog-cancel';cancel.dataset.actionPanelClose='';cancel.textContent=translate('Cancel');footer.prepend(cancel);
  }
 }
 host.open=true;host.append(dialog);
 active={dialog,body,host,trigger,busy:false};
 dialog.addEventListener('cancel',event=>{event.preventDefault();if(!active?.busy&&!isBusy())dismissActionPanel();});
 dialog.addEventListener('keydown',event=>{
  if(event.key!=='Tab'||event.ctrlKey||event.altKey||event.metaKey)return;
  const fields=[...dialog.querySelectorAll('button:not(:disabled),a[href],input:not(:disabled):not([type=hidden]),select:not(:disabled),textarea:not(:disabled),summary,[tabindex]:not([tabindex="-1"])')].filter(element=>element.getClientRects().length>0);
  const first=fields[0],last=fields.at(-1),current=document.activeElement;
  if(!first){event.preventDefault();dialog.querySelector('h2').focus();return;}
  if(event.shiftKey&&(current===first||current===dialog.querySelector('h2'))){event.preventDefault();last.focus();}
  else if(!event.shiftKey&&current===last){event.preventDefault();first.focus();}
 });
 dialog.showModal();
 // Start at the title: destructively acting or confirming is never the default focus.
 const heading=dialog.querySelector('h2');heading.tabIndex=-1;heading.focus({preventScroll:true});
 return true;
}
export function handleActionPanelClick(event,{isBusy=()=>false}={}){
 const close=event.target.closest?.('button[data-action-panel-close]');
 if(close?.hasAttribute?.('data-action-panel-close')){
  event.preventDefault();if(!isBusy()&&!active?.busy)dismissActionPanel();return true;
 }
 const trigger=event.target.closest?.('summary');
 const host=trigger?.parentElement;
 if(!host?.matches?.('details[data-action-panel]'))return false;
 // Nested optional actions remain inline inside the current review dialog.
 if(active?.dialog.contains(trigger))return false;
 event.preventDefault();
 if(!isBusy())openPanel(host,trigger,isBusy);
 return true;
}
