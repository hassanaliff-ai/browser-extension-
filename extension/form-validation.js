// Keep native constraints while replacing browser balloons with accessible inline feedback.
import {translate} from './locale.js';
let sequence=0;
export function validationMessage(field){
 if(field.type==='checkbox'&&field.validity.valueMissing)return 'Confirm the selected action before continuing.';
 if(field.type==='radio'&&field.validity.valueMissing)return 'Choose a device access option before continuing.';
 if(field.validity.valueMissing)return 'Complete the required field before continuing.';
 if(field.validity.tooShort)return 'Add more detail before continuing.';
 return 'Check the highlighted field before continuing.';
}
export function installFormValidation(root){
 root.addEventListener('invalid',event=>{
  const form=event.target.form;if(!form)return;
  event.preventDefault();
  const field=form.querySelector('input:invalid,select:invalid,textarea:invalid')??event.target;
  let error=form.querySelector('.form-error');
  if(!error){error=document.createElement('div');error.className='notice error form-error';error.setAttribute('role','alert');form.append(error);}
  if(!error.id)error.id='form-feedback-'+ ++sequence;
  error.dataset.clientValidation='true';error.textContent=translate(validationMessage(field));error.hidden=false;
  field.setAttribute('aria-invalid','true');
  const described=new Set((field.getAttribute('aria-describedby')??'').split(' ').filter(Boolean));described.add(error.id);field.setAttribute('aria-describedby',[...described].join(' '));
  field.focus({preventScroll:false});
 },true);
}
export function clearFormValidation(field){
 const form=field.form;if(!form?.querySelectorAll)return;
 for(const control of form.querySelectorAll('[aria-invalid=true]'))if(control.validity?.valid)control.removeAttribute('aria-invalid');
 const error=form.querySelector('.form-error');
 if(error?.dataset.clientValidation==='true'&&!form.querySelector('[aria-invalid=true]')){error.hidden=true;delete error.dataset.clientValidation;}
}
