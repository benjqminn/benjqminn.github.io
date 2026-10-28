import assert from 'node:assert/strict';
import { readFile, writeFile, stat } from 'node:fs/promises';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const registry = JSON.parse(await readFile(resolve(root, 'docs/credential-sources.json'), 'utf8'));
const records = registry.credentials;
const escape = (value) => String(value).replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
const groups = [
  ['all', 'All'], ['certifications', 'Certifications'], ['skills', 'Skill badges'],
  ['office', 'Microsoft Office'], ['courses', 'Courses'], ['archive', 'Archive'],
];
assert(records.length && new Set(records.map(record => record.id)).size === records.length, 'Credential IDs must be unique');
for (const record of records) {
  assert(groups.some(([category]) => category === record.category), `Unknown category: ${record.category}`);
  assert.equal(new URL(record.href).protocol, 'https:');
  if (record.asset) {
    assert.match(record.asset, /^assets\/(badges|training)\/[a-z0-9-]+\.(webp|svg)$/);
    assert((await stat(resolve(root, 'public', record.asset))).isFile());
  }
}
const count = (category) => records.filter(record => category === 'all' || record.category === category).length;
const filters = groups.map(([category, label]) => `          <button class="credential-filter" type="button" data-credential-filter="${category}" aria-pressed="${category === 'all'}" aria-controls="credential-gallery">${label}<span>${count(category)}</span></button>`).join('\n');
const cards = records.map((record, index) => {
  const isCertificate = record.category === 'courses' && record.source !== 'Credly';
  const artwork = record.asset
    ? `<div class="credential-art${isCertificate ? ' credential-art--certificate' : ''}"><img src="${escape(record.asset)}" width="${record.width}" height="${record.height}" loading="lazy" decoding="async" alt="${escape(record.name)} ${isCertificate ? 'certificate' : 'issued badge'}."></div>`
    : `<div class="credential-art credential-art--course"><svg viewBox="0 0 48 48" aria-hidden="true"><path d="M24 13C17 7 9 8 4 10v29c7-3 13-2 20 3m0-29c7-6 15-5 20-3v29c-7-3-13-2-20 3V13M10 17h8m-8 7h8m12-7h8m-8 7h8"/></svg><span>${escape(record.issuer)}</span></div>`;
  const date = record.category === 'archive' ? 'Expired March 31, 2026' : record.issued
    ? `Issued ${new Date(`${record.issued}T12:00:00Z`).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' })}`
    : record.details.split('\n').at(-1);
  const label = record.source === 'Credly' ? `View ${record.name} on Credly` : `View ${record.name} credential record`;
  return `          <article class="credential-card${record.category === 'archive' ? ' credential-card--archive' : ''}" data-carousel-slide data-credential-category="${record.category}" role="group" aria-roledescription="slide" aria-label="${index + 1} of ${records.length}"><a class="credential-link" href="${escape(record.href)}" aria-label="${escape(label)}">${artwork}<div class="credential-copy"><p class="credential-kind">${escape(record.kind)}</p><p class="credential-issuer">${escape(record.issuer.replace(' Training and Certification', ''))}</p><h4>${escape(record.title)}<span>${escape(record.subtitle)}</span></h4><p class="credential-date">${escape(date)}</p><span class="project-link">${record.category === 'courses' ? 'View certificate' : record.category === 'archive' ? 'View archived badge' : 'View credential'}<span aria-hidden="true">↗</span></span></div></a></article>`;
}).join('\n');
const section = `      <div class="credentials-showcase carousel" data-carousel role="region" aria-roledescription="carousel" aria-labelledby="credentials-heading">
        <div class="credentials-heading"><div><p class="section-kicker">Learning & credentials</p><h3 id="credentials-heading">Certifications & credentials</h3><p>Certifications, demonstrated skills, and completed courses.</p></div><div class="carousel-controls" hidden><button class="carousel-arrow" type="button" data-carousel-prev aria-label="Previous credentials" aria-controls="credential-gallery"><span aria-hidden="true">←</span></button><span class="carousel-status" data-carousel-status role="status" aria-live="polite" aria-atomic="true">1–3 / ${records.length}</span><button class="carousel-arrow" type="button" data-carousel-next aria-label="Next credentials" aria-controls="credential-gallery"><span aria-hidden="true">→</span></button></div></div>
        <div class="credential-filters" role="group" aria-label="Filter credentials" hidden>
${filters}
        </div>
        <p class="credential-summary" data-credential-summary role="status" aria-live="polite" aria-atomic="true">All credentials · ${records.length} records</p>
        <div class="credential-track" id="credential-gallery" data-carousel-track role="group" tabindex="0" aria-label="Credential cards. Use left and right arrow keys to browse.">
${cards}
        </div>
        <p class="gallery-hint">Swipe or use the arrows to browse. Open a card for its credential record.</p>
      </div>`;
const homePath = resolve(root, 'public/index.html');
const home = await readFile(homePath, 'utf8');
const region = /      <div class="credentials-showcase[\s\S]*?\n      <\/div>(?=\r?\n    <\/section>)/;
assert(region.test(home), 'Missing credential region');
await writeFile(homePath, home.replace(region, section));
console.log(`Rendered ${records.length} credential records across ${groups.length - 1} categories.`);
