import {escapeHtml as esc} from './core.js';
export const SUGGESTION_CATEGORIES=[['feature','New feature'],['interface','Interface improvement'],['accessibility','Accessibility improvement'],['other','Other improvement']];
export const SUGGESTION_STATUSES=[['new','New'],['under_review','Under review'],['planned','Planned'],['completed','Completed'],['declined','Declined']];

export function suggestionCreateBody(data){return {title:data.title.trim(),category:data.category,description:data.description.trim()};}
export function suggestionReviewBody(data,row){
 if(!row)throw new Error('Select a suggestion to review.');
 return {expected_revision:row.revision,status:data.status,response:data.response.trim()};
}

export function suggestionsPanel({rows,row,reviewer,status,offset},{form,field,select,textarea,notice,details,table,tag,btn,date,selectRows}){
 const statusTag=value=>tag(SUGGESTION_STATUSES.find(([key])=>key===value)?.[1]??value);
 const submission=form('suggestion-submit',field('Suggestion title','title','text','','required minlength="5" maxlength="160"')+
  select('Suggestion category','category',SUGGESTION_CATEGORIES)+textarea('Describe your suggestion','description','','required minlength="20" maxlength="3000"')+
  '<p class="meta">Explain what could improve and how it would help. Do not include passwords, personal details or private browsing information.</p>','Submit suggestion');
 const heading=`<section class="panel stack"><h2>Suggest an improvement</h2>${notice('Share ideas for improving ExtSecure. Suggestions do not change security settings or approve website access.')}${reviewer?details('Submit your own suggestion',submission):submission}</section>`;
 const listing=`<section class="panel stack"><h2>${reviewer?'Review user suggestions':'My suggestions'}</h2>${select('Suggestion status','suggestion_status',[['','All suggestions'],...SUGGESTION_STATUSES],status)}${table(rows,[['Suggestion','title'],['Category',r=>esc(SUGGESTION_CATEGORIES.find(([key])=>key===r.category)?.[1]??r.category)],['Status',r=>statusTag(r.status)],['Submitted by','reporter'],['Submitted',r=>esc(date(r.created_at))]])}<div class="row">${btn('Previous','suggestion-previous','small',offset?'':'disabled')}${btn('Next','suggestion-next','small',rows.length===50?'':'disabled')}</div></section>`;
 const selected=row?`<section class="panel stack"><h2>Suggestion details</h2>${selectRows('Suggestion',rows,row.id)}<h3 data-no-translate>${esc(row.title)}</h3><p class="feedback-copy" data-no-translate>${esc(row.description)}</p><div class="row">${statusTag(row.status)}<span class="meta" data-no-translate>${esc(row.reporter)} · ${esc(date(row.created_at))}</span></div>${row.response?`<h3>Administrator response</h3><p class="feedback-copy" data-no-translate>${esc(row.response)}</p><p class="meta" data-no-translate>${esc(row.reviewed_by)} · ${esc(date(row.reviewed_at))}</p>`:notice('Your suggestion is waiting for administrator review.')}${reviewer?details('Update suggestion status',form('suggestion-review',select('New status','status',SUGGESTION_STATUSES.slice(1),row.status==='new'?'under_review':row.status)+textarea('Response to the user','response',row.response??'','required minlength="10" maxlength="2000"'),'Save response')):''}</section>`:'';
 return heading+listing+selected;
}
