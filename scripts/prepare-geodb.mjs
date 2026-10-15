import { mkdir, readFile, writeFile, access } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
export const revision = '1bf6cabfb63c1a14af0971749c2120a3e5c77d72';
export const geoDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '../.local/geo-db');
export async function prepareGeodb() {
  await mkdir(geoDirectory, { recursive: true });
  try {
    const manifest = JSON.parse(await readFile(resolve(geoDirectory, 'provenance.json'), 'utf8'));
    if (manifest.revision === revision) {
      const db = await readFile(resolve(geoDirectory, 'ip2region_v4.xdb'));
      if (createHash('sha256').update(db).digest('hex') === manifest.databaseSha256) {
        for (const file of ['index.js','util.js','searcher.js']) await access(resolve(geoDirectory,file));
        return manifest;
      }
    }
  } catch {}
  const base = `https://raw.githubusercontent.com/lionsoul2014/ip2region/${revision}/`;
  const files = ['binding/javascript/index.js','binding/javascript/util.js','binding/javascript/searcher.js','data/ip2region_v4.xdb','README.md'];
  const hashes = await Promise.all(files.map(async path => {
    const response = await fetch(base + path, { signal: AbortSignal.timeout(90000) });
    if (!response.ok) throw Error(`IP database download failed: ${response.status} ${path}`);
    const buffer = Buffer.from(await response.arrayBuffer());
    const name = path.split('/').at(-1);
    await writeFile(resolve(geoDirectory,name),buffer);
    return { name, sha256: createHash('sha256').update(buffer).digest('hex'), bytes: buffer.length };
  }));
  await writeFile(resolve(geoDirectory,'package.json'),JSON.stringify({type:'module',private:true}));
  const manifest = { provider:'ip2region',source:'https://github.com/lionsoul2014/ip2region',revision,downloadedAt:new Date().toISOString(),databaseSha256:hashes.find(h=>h.name.endsWith('.xdb')).sha256,files:hashes,notice:'离线 IP 地理信息估计；不是路由器物理位置证明。' };
  await writeFile(resolve(geoDirectory,'provenance.json'),JSON.stringify(manifest,null,2));
  return manifest;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result=await prepareGeodb(); console.log(JSON.stringify({provider:result.provider,revision:result.revision,files:result.files.map(f=>({name:f.name,bytes:f.bytes}))}));
}
