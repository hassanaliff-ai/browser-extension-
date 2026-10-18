import test from 'node:test';
import assert from 'node:assert/strict';
import {registrationReceipt,registrationPendingPanel,LOGIN_HELP} from '../registration-flow.js';
test('Registration confirmation requires an actual verified pending response',()=>{
 for(const data of [{},{registered:false},{registered:true,status:'active',username:'test-user'}])assert.throws(()=>registrationReceipt(data,'normal_user','https://api.example'));
 const receipt=registrationReceipt({registered:true,status:'pending_review',username:'test-user',password:'DO NOT KEEP',totp_secret:'DO NOT KEEP'},'normal_user','https://api.example');
 assert.equal(receipt.username,'test-user');assert.equal(receipt.status,'pending_review');assert(!JSON.stringify(receipt).includes('DO NOT KEEP'));
 assert(LOGIN_HELP.includes('receive approval before logging in'));
});
test('Pending confirmation escapes content and offers login without granting access',()=>{
 const html=registrationPendingPanel({username:'<script>',role:'normal_user',api_origin:'https://api.example'},{notice:s=>s,btn:s=>s});
 assert(!html.includes('<script>'));assert(html.includes('&lt;script&gt;'));assert(html.includes('Submitted to API'));assert(html.includes('Continue to log in'));assert(html.includes('not approval'));
});
