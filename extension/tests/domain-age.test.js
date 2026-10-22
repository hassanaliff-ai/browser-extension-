import test from 'node:test';
import assert from 'node:assert/strict';
import {domainAgeText} from '../domain-age.js';
test('RDAP explanation is available in saved scan evidence',()=>{
 assert.equal(domainAgeText({target_kind:'url',signals:[{code:'new_domain',detail:'SecureScope RDAP: age 12 days.'}]}),'SecureScope RDAP: age 12 days.');
});
test('Live domain age and Unknown remain explicit',()=>{
 assert.match(domainAgeText({target_kind:'url',domain_age:{status:'Known',age_days:45}}),/45 days/);
 assert.match(domainAgeText({target_kind:'url',domain_age:{status:'Unknown'}}),/Unknown does not mean safe/);
});
test('No invented domain age for files or older scans',()=>{
 assert.equal(domainAgeText({target_kind:'download',domain_age:{status:'Known',age_days:8}}),'');
 assert.equal(domainAgeText({target_kind:'url'}),'');
 assert.match(domainAgeText({target_kind:'url',domain_age:{status:'Known',age_days:-1}}),/unavailable/);
});
