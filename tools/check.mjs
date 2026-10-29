import assert from 'node:assert/strict';
import { readFile, readdir, stat } from 'node:fs/promises';
import { resolve, dirname, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const publicRoot = resolve(projectRoot, 'public');
const files = await readdir(publicRoot, { recursive: true });
const htmlFiles = files.filter((filename) => extname(filename) === '.html');
for (const filename of htmlFiles) {
  const source = await readFile(resolve(publicRoot, filename), 'utf8');
  assert.match(source, /<html lang="en">/);
  assert.match(source, /name="viewport"/);
  assert.match(source, /Content-Security-Policy/);
  assert.equal((source.match(/<h1[ >]/g) || []).length, 1, `${filename}: exactly one main heading`);
  assert.doesNotMatch(source, /<script(?![^>]*\bsrc=)|\son[a-z]+\s*=|\sstyle\s*=/i);
  assert.doesNotMatch(source, /webpages\.charlotte\.edu|itis3135|May 2027|learning in progress/i);
  const ids = [...source.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
  assert.equal(ids.length, new Set(ids).size, `${filename}: unique IDs`);
  for (const match of source.matchAll(/\b(?:href|src)="([^"]+)"/g)) {
    const target = match[1];
    if (/^(https:|mailto:)/.test(target)) continue;
    if (target.startsWith('#')) {
      assert(ids.includes(target.slice(1)), `Missing anchor ${target} in ${filename}`);
      continue;
    }
    const parsed = new URL(target, 'https://portfolio.local/' + filename);
    const path = resolve(publicRoot, decodeURIComponent(parsed.pathname.replace(/^\//, '')));
    if (parsed.hash) {
      const linkedFile = (await stat(path)).isDirectory() ? resolve(path, 'index.html') : path;
      const linkedSource = await readFile(linkedFile, 'utf8');
      const fragment = decodeURIComponent(parsed.hash.slice(1));
      assert(linkedSource.includes('id="' + fragment + '"'), 'Missing linked anchor ' + target + ' in ' + filename);
    }
    const targetMetadata = await stat(path);
    if (targetMetadata.isDirectory()) {
      assert((await stat(resolve(path, 'index.html'))).isFile(), `Missing index for ${target}`);
    } else {
      assert(targetMetadata.isFile(), `Missing ${target}`);
    }
  }
}
const home = await readFile(resolve(publicRoot, 'index.html'), 'utf8');
assert.match(home, /Expected December 2026/);
assert.match(home, /Technology Analyst Development Program/);
assert.match(home, /Summer 2026/);
assert.doesNotMatch(home, /15\+|100% QA|CrowdStrike|XSOAR|ExtraHop/);
assert.match(home, /Implementation is private/);
assert.doesNotMatch(home, /math(?:ematics)? minor/i);
const resume = await readFile(resolve(publicRoot, 'assets/Benjamin-Taylor-Resume.pdf'));
assert.equal(resume.subarray(0, 5).toString(), '%PDF-');
assert(resume.length < 2_000_000, 'Resume should stay under 2 MB');
const totalBytes = (await Promise.all(files.map(async (filename) => {
  const metadata = await stat(resolve(publicRoot, filename));
  return metadata.isFile() ? metadata.size : 0;
}))).reduce((total, bytes) => total + bytes, 0);
assert(totalBytes < 1_500_000, 'Static site should stay under 1.5 MB');
console.log(`Checked ${htmlFiles.length} pages, local links, anchors, content safeguards, PDF, and asset budget (${(totalBytes / 1024).toFixed(0)} KB).`);
