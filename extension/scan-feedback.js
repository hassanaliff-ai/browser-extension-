const FILE_REASONS={
  not_found:'The hash lookup ran, but VirusTotal has no report for this file. File contents were not uploaded. Unknown means there is not enough reputation evidence; it does not mean safe.',
  not_configured:'File reputation checks are unavailable because the existing backend provider is not configured. Ask the backend owner to check VirusTotal settings.',
  provider_auth_failed:'VirusTotal rejected the backend credentials. Ask the backend owner to check the existing API key.',
  rate_limited:'The reputation lookup reached a request limit. Wait for the retry period before checking again.',
  lookup_failed:'The reputation provider could not be reached or did not return a successful report. Retry later; no safe verdict was assigned.',
  invalid_response:'The provider returned an incomplete or invalid analysis. The risk result stays Unknown until usable evidence is available.',
};
export function lookupFeedback(result) {
  const lookup=result.file_lookup??result.lookup;
  if(!lookup)return result.severity==='Unknown'?{message:'No usable reputation evidence was returned. Retry the check or investigate through an approved method; Unknown is not a safe result.',warning:true}:null;
  const reason=lookup.reason;
  if(reason)return {message:FILE_REASONS[reason]??reason,warning:true,
    retry: Number.isInteger(lookup.retry_after_seconds)&&lookup.retry_after_seconds>0?lookup.retry_after_seconds:null,
    cached:lookup.cache_hit===true};
  if(result.file_lookup&&['clear','suspicious','malicious'].includes(lookup.verdict))return {message:'The file hash reputation lookup completed. Review the risk result and recorded detections; Low does not guarantee safety.',warning:false,cached:lookup.cache_hit===true};
  if(lookup.status==='complete')return {message:'The website reputation lookup completed. The risk result reflects the returned evidence.',warning:false,cached:lookup.cached===true};
  return result.severity==='Unknown'?{message:'No usable reputation evidence was returned. Retry the check or investigate through an approved method; Unknown is not a safe result.',warning:true}:null;
}
