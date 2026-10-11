import {escapeHtml} from './core.js';

export function databasePanel(status) {
  const e=escapeHtml,c=status.connection??{};
  const rows=Object.entries(status.table_rows??{}).sort(([a],[b])=>a.localeCompare(b));
  const location=c.engine==='PostgreSQL'?`${c.host}:${c.port} / ${c.database} / ${c.schema}`:c.engine??'Unknown';
  return `<section class="panel stack"><h2>Database connection</h2>
    <div class="notice ${status.healthy?'success':'warning'}">${status.healthy?'Verified PostgreSQL storage':'Storage requires review'}</div>
    <p data-no-translate><strong>${e(location)}</strong></p>
    <p class="meta">This is the database used by this API. Refresh to verify it again. Passwords and connection strings are never shown.</p>
    ${status.reason?`<p>${e(status.reason)}</p>`:''}
    ${status.checked_at?`<p class="meta" data-no-translate>${e(status.checked_at)}</p>`:''}
    ${rows.length?`<p>${e(status.table_count)} tables · ${e(status.view_count)} views · ${e(status.total_rows)} saved records</p>
    <p>In pgAdmin, open the database and schema shown above. Tables appear under Schemas → public → Tables. Risk results and reporting totals also appear under Views.</p>
    <details><summary>Saved records by table</summary><div class="table-wrap"><table><thead><tr><th>Table</th><th>Saved records</th></tr></thead><tbody>${rows.map(([name,count])=>`<tr><td data-no-translate>${e(name)}</td><td>${e(count)}</td></tr>`).join('')}</tbody></table></div></details>
    <p class="meta">Zero records can be correct: findings require detected signals, alerts require high severity, and reports must be generated. No sample threats are inserted into your live database.</p>`:''}
  </section>`;
}
