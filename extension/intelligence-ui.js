import {escapeHtml as esc} from './core.js';
import {send} from './transport.js';
import {getPreferences} from './locale.js';
import {validateReportPeriod} from './workspace-kit.js';
const api=(path,method='GET',body)=>send({type:'API',path:'/api/intelligence/'+path,method,body});
export function previousPeriod(kind){
 const now=new Date(),today=new Date(Date.UTC(now.getUTCFullYear(),now.getUTCMonth(),now.getUTCDate()));
 if(kind==='monthly'){today.setUTCDate(1);today.setUTCMonth(today.getUTCMonth()-1);return today.toISOString().slice(0,7);}
 today.setUTCDate(today.getUTCDate()-((today.getUTCDay()+6)%7)-7);return today.toISOString().slice(0,10);
}
export function explanationForm(result){return `<section class="panel stack"><h2>AI risk explanation</h2><p class="help-copy">The model explains recorded evidence and suggests actions. It does not decide risk or prove a file is safe.</p><form class="form" data-form="ai-explain"><input type="hidden" name="scan_id" value="${esc(result.id)}"><details><summary>Optional content for the explanation</summary><div class="stack"><label class="check"><input type="checkbox" name="consent_content">Optionally share bounded page or text-file content with the backend and configured AI provider.</label><label class="field"><span>Exact scanned public HTTPS URL (optional)</span><input name="page_url" type="url" placeholder="https://example.com/" autocomplete="off"></label><label class="field"><span>Matching UTF-8 text file (optional, maximum 256 KiB)</span><input name="context_file" type="file" accept=".txt,.md,.json,.js,.html,.csv"></label></div></details><p class="meta">Without optional content, only stored reputation evidence is explained. Binary files use hash evidence. No content is executed. Query strings and fragments are excluded.</p><div class="notice error form-error" role="alert" tabindex="-1" hidden></div><button class="btn primary" type="submit">Explain evidence and recommendations</button></form><div class="ai-explanation-result report-output" aria-live="polite"></div></section>`;}
export async function runExplanation(form){
 const data=new FormData(form),file=data.get('context_file'),page=String(data.get('page_url')||'').trim();
 if((page||file?.size)&&!data.has('consent_content'))throw new Error('Confirm optional content sharing before submitting a page or text file.');
 const body={language:getPreferences().language,consent_content:data.has('consent_content')};
 if(page)body.page_url=page;
 if(file?.size){
  if(file.size>256*1024)throw new Error('Only text files up to 256 KiB can be read. Use hash evidence for larger or binary files.');
  const bytes=new Uint8Array(await file.arrayBuffer());
  let binary='';for(let i=0;i<bytes.length;i+=4096)binary+=String.fromCharCode(...bytes.subarray(i,i+4096));
  body.file_base64=btoa(binary);bytes.fill(0);binary='';
  body.content_type=/\.html$/i.test(file.name)?'text/html':/\.json$/i.test(file.name)?'application/json':'text/plain';
 }
 if((page||body.file_base64)&&!body.consent_content)throw new Error('Confirm optional content sharing first.');
 const result=await api('scans/'+encodeURIComponent(data.get('scan_id'))+'/explain','POST',body);
 form.parentElement.querySelector('.ai-explanation-result').innerHTML=`<div class="notice warning">AI-assisted draft · Review against the original evidence. Original severity is unchanged.</div><p data-no-translate>${esc(result.summary)}</p><h3>Recommended actions</h3><ul>${result.recommendations.map(text=>`<li data-no-translate>${esc(text)}</li>`).join('')}</ul><p class="meta">${esc(result.context_scope)} · ${esc(result.model)}</p>`;
 form.querySelector('[name="context_file"]').value='';
}
export async function intelligenceReports(canGenerate=false){
 const rows=await api('reports');
 return `<div class="report-workspace"><section class="panel stack"><h2>Weekly and monthly AI reports</h2><p class="help-copy">Completed UTC periods only. Weekly periods begin on Monday.</p>${canGenerate?`<form class="form inline-form" data-form="ai-report"><label class="field"><span>Report frequency</span><select name="kind"><option value="weekly">Weekly</option><option value="monthly">Monthly</option></select></label><label class="field"><span>Period start</span><input name="ai_period" type="date" required value="${previousPeriod('weekly')}"></label><div class="notice error form-error" role="alert" tabindex="-1" hidden></div><div class="form-submit"><button class="btn primary" type="submit">Generate period report</button></div></form>`:'<p>Administrators generate reports. Managers can review saved reports.</p>'}<p class="meta">Each saved snapshot includes every alert and AI explanation recorded during that period, plus an aggregate narrative. The downloadable archive contains all rows; identifiers and raw content are excluded from the model prompt.</p><div class="ai-period-result report-output" aria-live="polite"></div></section><section class="panel stack"><h2>Snapshot history</h2><div class="report-archive">${rows.map(row=>`<details><summary>${esc(row.kind)} · ${esc(row.period)} · ${esc(row.language)}</summary><p data-no-translate>${esc(row.narrative.summary)}</p><p class="meta">${esc(row.stats.alerts_total)} alerts · ${esc(row.stats.explanations_total)} explanations · UTC</p><ul>${row.narrative.recommendations.map(r=>`<li data-no-translate>${esc(r)}</li>`).join('')}</ul><button class="btn small" type="button" data-action="download-ai-report" data-id="${esc(row.id)}">Download complete report archive</button></details>`).join('')||'<p class="meta">No saved AI period reports.</p>'}</div></section></div>`;
}
export async function runPeriodReport(form){
 const data=new FormData(form),kind=data.get('kind'),period=validateReportPeriod(kind,data.get('ai_period'));
 const record=await api('reports/generate','POST',{kind,period,language:getPreferences().language});
 form.parentElement.querySelector('.ai-period-result').innerHTML=`<div class="notice warning">AI-assisted draft · Review before sharing with administrators.</div><p data-no-translate>${esc(record.narrative.summary)}</p><p>${esc(record.stats.alerts_total)} alerts · ${esc(record.stats.explanations_total)} explanations</p><button class="btn small" data-action="download-ai-report" data-id="${esc(record.id)}">Download complete report archive</button>`;
}
export async function downloadPeriodReport(id){
 const rows=await api('reports?limit=100'),record=rows.find(row=>row.id===id);
 if(!record)throw new Error('Report is no longer in the recent list. Refresh and select it again.');
 const blob=new Blob([JSON.stringify(record,null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),anchor=document.createElement('a');
 anchor.href=url;anchor.download=`extsecure-${record.kind}-${record.period}-${record.language}.json`;anchor.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
export function changePeriodInput(event){if(event.target.matches('[data-form="ai-report"] [name="kind"]')){const input=event.target.form.querySelector('[name="ai_period"]');input.type=event.target.value==='monthly'?'month':'date';input.value=previousPeriod(event.target.value);}}
