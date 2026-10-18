import test from 'node:test';
import assert from 'node:assert/strict';
import {safeApiPath} from '../core.js';
import {suggestionsPanel,suggestionCreateBody,suggestionReviewBody} from '../user-suggestions.js';
test('Suggestion routes support all statuses and reject other operations',()=>{
 for(const status of ['new','under_review','planned','completed','declined'])assert(safeApiPath(`/api/suggestions?status=${status}&limit=50&offset=0`,'GET'));
 assert(safeApiPath('/api/suggestions','POST'));
 assert(safeApiPath('/api/suggestions/abc-123/review','POST'));
 for(const [path,method] of [['/api/suggestions','DELETE'],['/api/suggestions?reporter=other','GET'],['/api/suggestions/../review','POST']])assert(!safeApiPath(path,method));
});
test('Request builders omit identity and use the server revision',()=>{
 assert.deepEqual(suggestionCreateBody({title:' Title ',description:' Details ',category:'feature',reporter:'spoof'}),{title:'Title',description:'Details',category:'feature'});
 assert.deepEqual(suggestionReviewBody({status:'planned',response:' Useful idea '},{revision:3}),{expected_revision:3,status:'planned',response:'Useful idea'});
 assert.throws(()=>suggestionReviewBody({},null));
});
test('Suggestion detail escapes user content and hides lower-role review controls',()=>{
 const helpers={form:(name,body)=>`FORM:${name} ${body}`,field:()=>'',select:()=>'',textarea:()=>'',notice:s=>s,details:(title,body)=>title+body,table:()=>'',tag:s=>s,btn:s=>s,date:()=>'',selectRows:()=>''};
 const row={id:'id',title:'<script>title</script>',description:'<img src=x onerror=alert(1)>',reporter:'<b>reporter</b>',status:'new',revision:1};
 const html=suggestionsPanel({rows:[row],row,reviewer:false,status:'',offset:0},helpers);
 assert(!html.includes('<script>'));assert(!html.includes('<img'));assert(html.includes('&lt;script&gt;'));
 assert(html.includes('FORM:suggestion-submit'));assert(!html.includes('FORM:suggestion-review'));
 assert(suggestionsPanel({rows:[row],row,reviewer:true,status:'',offset:0},helpers).includes('FORM:suggestion-review'));
});
