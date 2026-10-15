import { execFile } from 'node:child_process';
import { resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { mkdir, readFile, writeFile, rename } from 'node:fs/promises';
import { resolve4 } from 'node:dns/promises';
import { prepareGeodb, geoDirectory } from './prepare-geodb.mjs';
import { lookupIP, observeSourceIP, getLocationStats } from './ip-locations.mjs';
import { normalizeWebsite, probeWebsite, classifyWebsiteResult } from './website-validation.mjs';
export const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const localDirectory = resolve(projectRoot,'.local/measurements');
export const targets = [
  {id:'baidu',name:'百度',avatar:'百',domain:'www.baidu.com'},
  {id:'bilibili',name:'哔哩哔哩',avatar:'哔',domain:'www.bilibili.com'},
  {id:'qq',name:'腾讯网',avatar:'腾',domain:'www.qq.com'}
];
const children = new Set();
export function abortMeasurements() { for(const child of children)child.kill(); }
export function execute(command,args,timeout) {
  return new Promise(resolveResult=>{
    const startedAt=new Date().toISOString();
    const child=execFile(command,args,{windowsHide:true,timeout,maxBuffer:4*1024*1024,encoding:'buffer'},(error,stdout,stderr)=>{
      children.delete(child);
      const decode=buffer=>buffer?(command==='tracert.exe'?new TextDecoder('gb18030').decode(buffer):buffer.toString('utf8')):'';
      resolveResult({startedAt,finishedAt:new Date().toISOString(),pid:child.pid,stdout:decode(stdout),stdoutBytes:stdout,stderr:decode(stderr),exitCode:error?error.code:0,killed:!!error?.killed});
    });
    children.add(child);
  });
}
export function privateAddress(ip) {
  if(!ip)return false;
  const parts=ip.split('.').map(Number);
  return parts[0]===10 || parts[0]===127 || (parts[0]===192&&parts[1]===168) || (parts[0]===172&&parts[1]>=16&&parts[1]<=31) || (parts[0]===169&&parts[1]===254) || (parts[0]===100&&parts[1]>=64&&parts[1]<=127) || (parts[0]===198&&[18,19].includes(parts[1]));
}
export function parseTracert(text,targetIP) {
  const hops=[];
  for(const line of text.split(/\r?\n/)) {
    const match=line.match(/^\s*(\d+)\s+(.+)$/);if(!match)continue;
    const hop=Number(match[1]);if(hop<1||hop>64)continue;
    const ip=match[2].match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)?.[0]||null;
    const samples=[...match[2].matchAll(/<\s*(\d+)\s*(?:ms|毫秒)|(\d+(?:\.\d+)?)\s*(?:ms|毫秒)|(\*)/g)].slice(0,3).map(m=>m[3]?{kind:'timeout',ms:null}:m[1]?{kind:'upper-bound',ms:Number(m[1])}:{kind:'value',ms:Number(m[2])});
    const exact=samples.filter(s=>s.kind==='value').map(s=>s.ms).sort((a,b)=>a-b);
    const rtt=exact.length?exact[Math.floor(exact.length/2)]:null;
    const rttText=rtt!==null?`${rtt.toFixed(1)} ms`:samples.some(s=>s.kind==='upper-bound')?`<${Math.max(...samples.filter(s=>s.kind==='upper-bound').map(s=>s.ms))} ms`:'—';
    const isPrivate=privateAddress(ip),isDestination=ip===targetIP;
    hops.push({hop,name:!ip?'未响应节点':isDestination?'目的服务节点':isPrivate?hop===1?'本地网关':'私网中间节点':'公网中间节点',ip,type:!ip?'未知节点':isDestination?'目的节点':isPrivate?hop===1?'本地网关':'私网网络':'公网路由',status:ip?'responded':'timeout',samples,rtt,rttText,private:isPrivate,region:null,city:null,coordinates:null,rawLine:line.trim(),note:!ip?'未收到 ICMP 响应；位置未知。超时不能证明业务丢包。':isPrivate?'私网地址不能通过公网 IP 库定位；不推测本机或节点所在城市。':isDestination?'目的 IP 与本次 HTTPS 连接一致。地区来自离线 IP 库估计。':''});
  }
  return hops;
}
let geoCache;
async function geolocator() {
  if(!geoCache)geoCache=(async()=>{
    const provenance=await prepareGeodb();
    const binding=await import(pathToFileURL(resolve(geoDirectory,'index.js')).href);
    const dbPath=resolve(geoDirectory,'ip2region_v4.xdb');
    binding.verifyFromFile(dbPath);
    const searcher=binding.newWithBuffer(binding.IPv4,binding.loadContentFromFile(dbPath));
    const provinces=JSON.parse(await readFile(resolve(projectRoot,'dist/assets/china-provinces.json'),'utf8')).features;
    const clean=name=>(name||'').replace(/省|市|自治区|维吾尔|壮族|回族/g,'');
    return {provenance,async lookup(ip){
      if(!ip||privateAddress(ip))return null;
      const raw=await searcher.search(ip);if(!raw)return null;
      const fields=raw.split('|');
      const [country,province,city,isp,countryCode]=fields.length===5?fields:[fields[0],fields[2],fields[3],fields[4],null];
      const feature=provinces.find(f=>clean(f.properties.name)===clean(province));
      return {country,region:province==='0'?null:province,city:city==='0'?null:city,isp:isp==='0'?null:isp,countryCode,regionCode:feature?.properties.adcode||null,coordinates:feature?.properties.center||feature?.properties.centroid||null,coordinateMeaning:'省级中心示意坐标；不是节点物理坐标',source:'ip2region 离线库',accuracy:'地区估计',raw};
    }};
  })();
  return geoCache;
}
export async function readMeasurements() {
  try{const data=JSON.parse(await readFile(resolve(localDirectory,'latest.json'),'utf8'));for(const connection of data.connections||[]){connection.url ||= `${connection.protocol?.toLowerCase()||'https'}://${connection.domain}/`;connection.validation ||= classifyWebsiteResult({...connection.http,tlsRequired:connection.protocol!=='HTTP'});}return data;}catch{return null;}
}
export async function collectRouteMeasurements({ids=targets.map(t=>t.id),onProgress=()=>{}}={}) {
  if(process.platform!=='win32')throw Error('当前采集器需要 Windows tracert.exe 和 curl.exe。');
  const selected=targets.filter(t=>ids.includes(t.id));if(!selected.length)throw Error('请选择支持的网站。');
  const runID=new Date().toISOString().replace(/[:.]/g,'-');
  const runDirectory=resolve(localDirectory,runID);await mkdir(runDirectory,{recursive:true});
  let locator=null,geoError=null;
  try{locator=await geolocator();}catch(error){geoError=error.message;onProgress('离线定位不可用，将保留真实 IP 和未知地区');}
  const measured=await Promise.all(selected.map(async target=>{
    onProgress(`正在访问 ${target.domain}`);
    let dnsAddresses=[],dnsError=null;try{dnsAddresses=await resolve4(target.domain);}catch(error){dnsError=error.message;}
    const format=JSON.stringify({httpCode:'%{http_code}',remoteIP:'%{remote_ip}',remotePort:'%{remote_port}',localIP:'%{local_ip}',localPort:'%{local_port}',dnsSeconds:'%{time_namelookup}',connectSeconds:'%{time_connect}',tlsSeconds:'%{time_appconnect}',totalSeconds:'%{time_total}',downloadBytes:'%{size_download}',tlsVerifyResult:'%{ssl_verify_result}'});
    const args=['-4','--silent','--show-error','--output','NUL','--connect-timeout','6','--max-time','18','--user-agent','Mozilla/5.0 RouteLensLocalValidation/1.0','--write-out',format,`https://${target.domain}/`];
    const curl=await execute('curl.exe',args,22000);
    let http={};try{http=JSON.parse(curl.stdout);}catch{}
    for(const key of ['httpCode','remotePort','localPort','dnsSeconds','connectSeconds','tlsSeconds','totalSeconds','downloadBytes','tlsVerifyResult'])http[key]=http[key]===undefined?null:Number(http[key]);
    const destinationIP=http.remoteIP||dnsAddresses[0]||null;
    const connection={...target,protocol:'HTTPS',port:443,dnsAddresses,dnsError,destinationIP,http:{...http,exitCode:curl.exitCode,error:curl.stderr.trim()||null,startedAt:curl.startedAt,finishedAt:curl.finishedAt,processID:curl.pid,command:'curl.exe -4 (GET /, TLS 校验开启)'},bytes:http.downloadBytes||0,regions:[],regionCodes:[],mapCities:[],mapHops:[],hops:[],warnings:[]};
    await writeFile(resolve(runDirectory,`${target.id}-http.json`),JSON.stringify(connection.http,null,2));
    if(!destinationIP){connection.warnings.push('网站连接失败且没有可用 DNS 地址。');return connection;}
    onProgress(`正在探测 ${target.domain} → ${destinationIP}`);
    const trace=await execute('tracert.exe',['-4','-d','-h','24','-w','600',destinationIP],65000);
    await writeFile(resolve(runDirectory,`${target.id}-tracert.txt`),trace.stdout,'utf8');
    if(trace.stdoutBytes)await writeFile(resolve(runDirectory,`${target.id}-tracert.bin`),trace.stdoutBytes);
    connection.hops=parseTracert(trace.stdout,destinationIP);
    connection.trace={command:`tracert.exe -4 -d -h 24 -w 600 ${destinationIP}`,method:'ICMP / IPv4',maxHops:24,timeoutMs:600,encoding:'GB18030 → UTF-8',startedAt:trace.startedAt,finishedAt:trace.finishedAt,exitCode:trace.exitCode,processKilled:trace.killed,reachedDestination:connection.hops.some(h=>h.ip===destinationIP),rawFile:`${runID}/${target.id}-tracert.txt`,rawBytesFile:`${runID}/${target.id}-tracert.bin`};
    for(const [index,h] of connection.hops.entries()) {
      try{h.geo=locator?await locator.lookup(h.ip):null;}catch(error){h.geo=null;h.geolocationError=error.message;connection.warnings.push('离线定位失败，保留未知地区。');}
      if(h.geo){h.region=h.geo.region;h.city=h.geo.city;h.coordinates=h.geo.coordinates;}
      if(h.geo?.regionCode&&!connection.regionCodes.includes(h.geo.regionCode)){connection.regionCodes.push(h.geo.regionCode);connection.regions.push(h.region);}
      if(h.coordinates){connection.mapHops.push(index);connection.mapCities.push(h.city||h.region||'地区估计');}
    }
    try{connection.destinationGeo=locator?await locator.lookup(destinationIP):null;}catch{connection.destinationGeo=null;}
    connection.destination=connection.destinationGeo?.city||connection.destinationGeo?.region||'地区未知';
    const timeoutCount=connection.hops.filter(h=>h.status==='timeout').length;
    if(timeoutCount)connection.warnings.push(`${timeoutCount} 跳未响应，无法确认这些节点的地区。`);
    if(!connection.trace.reachedDestination)connection.warnings.push('ICMP 探测未到达目标；目标的 HTTPS 连通性请单独查看。');
    if(http.httpCode<200||http.httpCode>=400)connection.warnings.push(`HTTP 返回 ${http.httpCode||'失败'}，与路由可达性分开判断。`);
    if(http.remoteIP&&http.remoteIP!==destinationIP)connection.warnings.push('路由目标与 HTTPS 远端 IP 不一致。');
    onProgress(`${target.name}完成：${connection.hops.length} 跳，${timeoutCount} 跳未响应`);
    return connection;
  }));
  const previous=await readMeasurements();
  const connections=targets.map(t=>measured.find(c=>c.id===t.id)||previous?.connections.find(c=>c.id===t.id)).filter(Boolean);
  const sourceIP=measured.find(c=>c.http.localIP)?.http.localIP||null;
  const result={schemaVersion:2,mode:'measured',collectedAt:new Date().toISOString(),runID,scope:'本机对指定网站的一次 HTTPS 访问及同一远端 IP 的 ICMP 路由探测；不代表所有进程和全部流量。',source:{label:'我的电脑',ip:sourceIP,city:null,region:null,coordinates:null,note:'本机所在地区未采集；私网 IP 不能定位。'},geolocation:locator?.provenance||null,geolocationError:geoError,connections,notice:'IP、响应及延迟来自实测；地区为离线数据库估计。ICMP 探测路径不保证与业务流量完全相同。未响应节点保持未知，地图不补造途经地区。'};
  await writeFile(resolve(runDirectory,'measurements.json'),JSON.stringify(result,null,2));
  const temporary=resolve(localDirectory,`${runID}.tmp.json`);await writeFile(temporary,JSON.stringify(result,null,2));await rename(temporary,resolve(localDirectory,'latest.json'));
  return result;
}

export async function collectMeasurements({ids=targets.map(t=>t.id),selectedTargets=null,onProgress=()=>{}}={}) {
  if(process.platform!=='win32')throw Error('当前采集器需要 Windows curl.exe。');
  const previous=await readMeasurements();
  const available=[...targets,...(previous?.connections||[])];
  const candidates=selectedTargets||ids.map(id=>available.find(target=>target.id===id)).filter(Boolean);
  const selected=[...new Map(candidates.map(target=>{const normalized=normalizeWebsite(target.url||`https://${target.domain}/`,targets);return[normalized.id,normalized];})).values()];
  if(!selected.length||selected.length>30)throw Error('请选择 1 至 30 个网站。');
  const start=performance.now(),before=getLocationStats();
  const runID=new Date().toISOString().replace(/[:.]/g,'-');
  const runDirectory=resolve(localDirectory,runID);await mkdir(runDirectory,{recursive:true});
  onProgress('正在访问网站并确认公网出口');
  const sourcePromise=observeSourceIP();
  const measuredConnections=[];
  let nextTarget=0;
  const connectionsPromise=Promise.all(Array.from({length:Math.min(4,selected.length)},async()=>{while(nextTarget<selected.length){
    const target=selected[nextTarget++];
    onProgress(`正在访问 ${target.url}`);
    const {http,validation}=await probeWebsite(target,{execute});
    const destinationIP=http.remoteIP||null;
    onProgress(`${target.name}：${validation.label}${destinationIP?'，正在核对实际远端位置':''}`);
    const destinationGeo=destinationIP?await lookupIP(destinationIP):null;
    const connection={...target,http,validation,destinationIP,destinationGeo,destination:destinationGeo?.cityLabel||destinationGeo?.regionLabel||'位置未知',bytes:http.downloadBytes||0,hops:[],mapHops:[],mapCities:[],regions:[],regionCodes:[],warnings:[],endpointOnly:true};
    if(validation.status!=='success')connection.warnings.push(`${validation.label}：${validation.detail}`);
    if(destinationGeo?.verification.status!=='consistent')connection.warnings.push(destinationGeo?.verification.note||'没有可核对的目的位置');
    await writeFile(resolve(runDirectory,`${target.id}-http.json`),JSON.stringify(http,null,2));
    measuredConnections.push(connection);
  }})).then(()=>selected.map(target=>measuredConnections.find(connection=>connection.id===target.id)));
  const [sourceGeo,measured]=await Promise.all([sourcePromise,connectionsPromise]);
  for(const c of measured){c.source={ip:sourceGeo.ip||null,publicIP:sourceGeo.ip||null,localIP:c.http.localIP||null,geo:sourceGeo};onProgress(`${c.name}：${c.validation.label}${c.destinationIP?` · ${c.destinationGeo?.verification.label||'位置未知'}`:''}`);}
  const idsMeasured=new Set(measured.map(connection=>connection.id));
  const connections=[...measured,...(previous?.connections||[]).filter(connection=>connection.endpointOnly&&!idsMeasured.has(connection.id))].slice(0,30);
  const after=getLocationStats();
  const result={schemaVersion:4,mode:'measured',view:'endpoints',collectedAt:new Date().toISOString(),runID,source:measured[0].source,connections,lastMeasuredIDs:measured.map(connection=>connection.id),historyLimit:30,timing:{durationMs:Math.round(performance.now()-start),websiteRequests:selected.length,successfulRequests:measured.filter(connection=>connection.validation.status==='success').length,failedRequests:measured.filter(connection=>connection.validation.status==='failed').length,httpErrorResponses:measured.filter(connection=>connection.validation.status==='http-error').length,geolocationRequests:after.networkRequests-before.networkRequests,geolocationCacheHits:after.cacheHits-before.cacheHits,geolocationCacheTTLHours:24,tracerouteExecuted:false},scope:'自定义 HTTP/HTTPS 网站的真实 GET 请求，地图仅展示公网源 IP 和实际连接的远端 IP；没有建立连接时不补造目的位置。',notice:'源为第三方服务观测的公网出口；目的为实际连接远端 IP。位置来自 IPWHOIS / IPinfo 的 IP 地理估计，来源有分歧时明确标注。箭头仅表示连接方向，不代表实际网络路径。真实访问记录只存本地，第三方查询仅发送公网 IP。'};
  await writeFile(resolve(runDirectory,'measurements.json'),JSON.stringify(result,null,2));
  const temp=resolve(localDirectory,`${runID}.tmp.json`);await writeFile(temp,JSON.stringify(result,null,2));await rename(temp,resolve(localDirectory,'latest.json'));
  return result;
}
