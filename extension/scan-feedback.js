const LOOKUP_REASONS={
  not_found:'The hash lookup ran, but VirusTotal has no report for this file. File contents were not uploaded. Unknown means there is not enough reputation evidence; it does not mean safe.',
  not_configured:'File reputation checks are unavailable because the existing backend provider is not configured. Ask the backend owner to check VirusTotal settings.',
  provider_auth_failed:'VirusTotal rejected the backend credentials. Ask the backend owner to check the existing API key.',
  rate_limited:'The reputation lookup reached a request limit. Wait for the retry period before checking again.',
  lookup_failed:'The reputation provider could not be reached or did not return a successful report. Retry later; no safe verdict was assigned.',
  timeout:'VirusTotal did not finish in time. Check the result again later or review other approved evidence.',
  invalid_response:'The provider returned an incomplete or invalid analysis. The risk result stays Unknown until usable evidence is available.',
};
export function lookupFeedback(result) {
  const lookup=result.file_lookup??result.lookup??(result.provider_evidence?.reason?{reason_code:result.provider_evidence.reason}:null);
  if(!lookup)return result.severity==='Unknown'?{message:'No usable reputation evidence was returned. Retry the check or investigate through an approved method; Unknown is not a safe result.',warning:true}:null;
  const reason=lookup.reason_code??lookup.reason;
  const missingUrl=reason==='not_found'&&result.target_kind==='url';
  if(reason)return {message:missingUrl?'VirusTotal has no report for this exact address. Review the destination independently or retry later.':LOOKUP_REASONS[reason]??lookup.reason??'No usable reputation report is available. Retry later or review other evidence.',warning:true,
    retry: Number.isInteger(lookup.retry_after_seconds)&&lookup.retry_after_seconds>0?lookup.retry_after_seconds:null,
    cached:lookup.cache_hit===true};
  if(result.file_lookup&&['clear','suspicious','malicious'].includes(lookup.verdict))return {message:'The file hash reputation lookup completed. Review the recorded detections and their coverage.',warning:false,cached:lookup.cache_hit===true};
  if(lookup.status==='complete')return {message:'The website reputation lookup completed. The risk result reflects the returned evidence.',warning:false,cached:lookup.cached===true};
  return result.severity==='Unknown'?{message:'No usable reputation evidence was returned. Retry the check or investigate through an approved method; Unknown is not a safe result.',warning:true}:null;
}
