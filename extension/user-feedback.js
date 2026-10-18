import {escapeHtml as esc} from './core.js';

export const FEEDBACK_CATEGORIES=[['suspicious_result','Report a suspicious result'],['challenge_warning','Challenge a warning']];
export const FEEDBACK_OUTCOMES=[['threat_confirmed','Threat confirmed'],['false_positive','Warning appears incorrect'],['inconclusive','More evidence needed']];

export function feedbackSubmission(scan,{details,form,select,textarea,notice}){
  if(!scan?.id)return '';
  return details('Report a concern or challenge this warning',form('feedback-submit',
    `<input type="hidden" name="scan_id" value="${esc(scan.id)}">`+
    notice('An administrator will review your feedback against this scan. Submitting feedback does not change its score or release a block.')+
    select('Feedback type','category',FEEDBACK_CATEGORIES)+
    textarea('What seems wrong or suspicious?','message','','required minlength="10" maxlength="2000"')+
    '<p class="meta">Describe what you noticed. Do not include passwords, personal details, full URLs or file contents.</p>',
    'Send feedback'));
}

export function feedbackCreateBody(data){
  return {scan_id:data.scan_id,category:data.category,message:data.message.trim()};
}

export function feedbackReviewBody(data,row){
  if(!row||row.status!=='pending')throw new Error('Refresh and select pending feedback.');
  return {expected_revision:row.revision,outcome:data.outcome,review_note:data.review_note.trim()};
}
