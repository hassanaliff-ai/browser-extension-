export function updateAccessDecision(form) {
  if(form?.dataset.form!=='access-review')return;
  const duration=form.querySelector('[name="duration"]');
  if(!duration)return;
  const approved=form.querySelector('[name="decision"]')?.value==='approve';
  const field=duration.closest('.field');
  if(field)field.hidden=!approved;
  duration.disabled=!approved;
  duration.required=approved;
}
