export function domainAgeText(result) {
  if(result.target_kind!=='url')return '';
  const signal=result.signals?.find(s=>s.code==='new_domain');
  if(signal?.detail)return signal.detail;
  const age=result.domain_age;
  if(!age)return '';
  if(age.status==='Known'&&Number.isInteger(age.age_days)&&age.age_days>=0)
    return `SecureScope RDAP: domain registered ${age.age_days} days ago. Domain age alone does not establish safety or a threat.`;
  return 'SecureScope RDAP: domain age unavailable. Retry later; Unknown does not mean safe.';
}
