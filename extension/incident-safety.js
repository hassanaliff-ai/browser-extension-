import {escapeHtml as esc} from './core.js';

export function incidentSafetyPanel(row, c) {
  const {notice, details, form, check, reason, can} = c;
  const actions = row.safety_plan?.actions ?? [];
  const recorded = row.safety_plan?.recorded_by;
  const protections = row.device_protection;
  const checklist = actions.map(a => check(a.description, 'safety_' + a.code, a.completed)).join('');
  return `<section class="panel stack"><h2>User safety actions</h2>${notice('Record only actions actually completed. These checks are operator confirmations, not proof that the device is clean.')}${recorded ? `<p class="meta">Last recorded by <bdi data-no-translate>${esc(recorded)}</bdi></p>` : ''}${can('cases') && actions.length ? form('case-safety', checklist + reason(), 'Save safety review') : `<ul>${actions.map(a => `<li>${esc(a.description)}</li>`).join('')}</ul>`}${notice('Device protection controls access through ExtSecure. It does not isolate the operating system or quarantine files.', 'warning')}${protections?.blocked ? notice('The affected device is blocked in ExtSecure. Review any unblock separately in device inventory.', 'warning') : protections?.registered && can('incident-admin') ? details('Block affected device', form('case-block-device', check('I confirm that ExtSecure access for the affected device should be blocked.', 'confirmed') + reason(), 'Block device access')) : notice('Device blocking requires a registered device and administrator access.')}</section>${can('incident-admin') ? `<section class="panel stack"><h2>Remove incident</h2>${notice('Removal deletes this incident and its notes. Scan evidence, active threat blocks and the administrative audit trail remain. If a threat is still blocked, create a new investigation before requesting release.', 'warning')}${details('Remove this incident permanently', form('case-remove', check('I understand that this incident and its notes will be removed.', 'confirmed') + reason(), 'Remove incident'))}</section>` : ''}`;
}

export function incidentActionBody(action, fields, row) {
  if (!row?.id || !Number.isInteger(row.revision)) throw new Error('Refresh the incident before continuing.');
  const base = {reason: fields.reason, expected_revision: row.revision};
  if (action === 'case-safety') {
    const checks = (row.safety_plan?.actions ?? []).filter(a => fields['safety_' + a.code] === 'on' || fields['safety_' + a.code] === true).map(a => a.code);
    if (!checks.length) throw new Error('Select at least one completed safety action.');
    return {...base, checks};
  }
  if (!['case-remove', 'case-block-device'].includes(action)) throw new Error('Unknown incident action.');
  if (fields.confirmed !== 'on' && fields.confirmed !== true) throw new Error('Confirm the incident action before continuing.');
  if (action === 'case-remove') return {...base, confirmed: true};
  if (!row.device_protection?.registered || !Number.isInteger(row.device_protection.revision)) throw new Error('Refresh the registered device before blocking it.');
  return {...base, confirmed: true, expected_device_revision: row.device_protection.revision};
}
