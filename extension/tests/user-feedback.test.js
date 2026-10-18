import test from 'node:test';
import assert from 'node:assert/strict';
import {feedbackSubmission,feedbackCreateBody,feedbackReviewBody} from '../user-feedback.js';
import {safeApiPath} from '../core.js';

test('Feedback routes pass the real extension worker allowlist',()=>{
 for(const path of ['/api/feedback','/api/feedback?limit=50&offset=0','/api/feedback?status=pending&limit=50&offset=50','/api/feedback?status=reviewed&limit=50&offset=0'])assert(safeApiPath(path,'GET'),path);
 assert(safeApiPath('/api/feedback','POST'));
 assert(safeApiPath('/api/feedback/abc-123/review','POST'));
 for(const [path,method] of [['/api/feedback','DELETE'],['/api/feedback?reporter=hasan','GET'],['/api/feedback/abc/delete','POST'],['/api/feedback/../review','POST']])assert(!safeApiPath(path,method));
});
test('Submission is scan-linked, escaped and explains privacy and containment',()=>{
 const helpers={details:(title,body)=>title+body,form:(_,body)=>body,select:()=>'',textarea:()=>'',notice:text=>text};
 const html=feedbackSubmission({id:'"><script>alert(1)</script>'},helpers);
 assert(!html.includes('<script>'));assert(html.includes('&lt;script&gt;'));
 assert(html.includes('does not change its score or release a block'));
 assert(html.includes('Do not include passwords'));assert(html.includes('name="scan_id"'));
 assert.equal(feedbackSubmission({},helpers),'');
});
test('Payloads contain only user-owned inputs and current review revision',()=>{
 assert.deepEqual(feedbackCreateBody({scan_id:'id',category:'challenge_warning',message:' explanation ',reporter:'spoof'}),{scan_id:'id',category:'challenge_warning',message:'explanation'});
 assert.deepEqual(feedbackReviewBody({outcome:'inconclusive',review_note:' More evidence needed ',revision:9},{status:'pending',revision:2}),{expected_revision:2,outcome:'inconclusive',review_note:'More evidence needed'});
 assert.throws(()=>feedbackReviewBody({}, {status:'reviewed'}));
});
