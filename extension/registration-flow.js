import {escapeHtml as esc} from './core.js';

export const LOGIN_HELP='Sign-in was not accepted. New users must create an account, finish authenticator verification and receive approval before logging in. Approved users should check their username and password.';

export function registrationReceipt(data,role,origin){
 if(data?.registered!==true||data.status!=='pending_review'||typeof data.username!=='string'||!/^[a-z0-9][a-z0-9._-]{2,79}$/.test(data.username)||!['normal_user','manager','administrator'].includes(role))throw new Error('Registration confirmation was incomplete. Check the connection and retry verification before assuming the request was submitted.');
 return {username:data.username,role,status:'pending_review',api_origin:origin,submitted_at:new Date().toISOString()};
}

export function registrationPendingPanel(receipt,{notice,btn}){
 return `<section class="stack" data-registration-pending><h1>Registration submitted</h1>${notice('Authenticator verification is complete. The request was sent for approval. Sign in after a reviewer approves it.')}<dl><dt>Username</dt><dd data-no-translate>${esc(receipt.username)}</dd><dt>Requested role</dt><dd>${esc({normal_user:'Normal user',manager:'Manager',administrator:'Administrator'}[receipt.role]??receipt.role)}</dd><dt>Submitted to API</dt><dd class="code" data-no-translate>${esc(receipt.api_origin)}</dd></dl><p>Ask a higher-role reviewer to open Accounts → Pending registrations. The head administrator can review all lower roles.</p>${btn('Continue to log in','registration-continue','primary full')}<p class="meta">Continue after approval. This confirmation records submission, not approval.</p></section>`;
}
