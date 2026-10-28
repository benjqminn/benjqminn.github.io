import { cp, mkdir, readdir, rm } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const outputRoot = resolve(projectRoot, 'dist');
if (outputRoot !== resolve(projectRoot, 'dist')) throw new Error('Unexpected output path.');
await rm(outputRoot, { recursive: true, force: true });
await mkdir(outputRoot, { recursive: true });
for (const entry of await readdir(resolve(projectRoot, 'public'))) {
  await cp(resolve(projectRoot, 'public', entry), resolve(outputRoot, entry), { recursive: true });
}
console.log('Built dist/ from public/ only. Legacy course files are excluded.');
