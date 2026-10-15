import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { mkdir, writeFile, readFile, rename, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { lookupIP, observeSourceIP, isPublicIP, getCachedIP } from './ip-locations.mjs';

export const trafficDirectory = resolve('.local/traffic');
const script = resolve('python/traffic.py');
const datasets = new Map();
const clients = new Set();
let liveProcess, offlineProcess, activeGeo = 0, startingLive=false, saveQueue=Promise.resolve();
const geoQueue = [];
let geoStarts = [];
let interfaceCache;
const python = process.env.ROUTELENS_PYTHON || 'python';

function worker(args) {
  return spawn(python, ['-u', script, ...args], { windowsHide:true, env:{...process.env,PYTHONIOENCODING:'utf-8'}, stdio:['pipe','pipe','pipe'] });
}
export async function listInterfaces() {
  if(interfaceCache && Date.now()-interfaceCache.time<30000) return interfaceCache.value;
  const value = await new Promise((resolvePromise,reject) => {
    const child = worker(['interfaces']); let output='', error='';
    const timeout=setTimeout(()=>{child.kill();reject(Error('Python 网卡检查超时'));},10000);
    child.stdout.on('data',chunk=>output+=chunk); child.stderr.on('data',chunk=>error+=chunk);
    child.on('error',reject);
    child.on('close',code=>{clearTimeout(timeout);try {const result=JSON.parse(output.trim());if(code||result.error)throw Error(result.error||error);resolvePromise(result.interfaces);}catch(err){reject(err);}});
  });
  interfaceCache={time:Date.now(),value}; return value;
}
export function regionFor(geo) {
  if(!geo?.coordinates) return {key:'unknown',label:'未知 / 私网 / 待定位',coordinates:null};
  return {key:[geo.countryCode,geo.regionLabel||geo.region||geo.cityLabel].join('/'),label:[geo.country||geo.countryCode,geo.regionLabel||geo.region||geo.cityLabel].filter(Boolean).join(' · '),coordinates:geo.coordinates};
}
export function aggregateRegions(flows,overflowPackets=0,overflowBytes=0) {
  const groups = new Map();
  for(const flow of flows) {
    const region=regionFor(flow.geo);
    const group=groups.get(region.key)||{...region,packets:0,bytes:0,ipCount:0,ips:[],representativeIP:flow.ip,representativePackets:-1};
    group.packets+=flow.packets;group.bytes+=flow.bytes;group.ipCount++;
    if(group.ips.length<12)group.ips.push(flow.ip);
    if(flow.packets>group.representativePackets){group.coordinates=region.coordinates;group.representativeIP=flow.ip;group.representativePackets=flow.packets;}
    groups.set(region.key,group);
  }
  if(overflowPackets){const group=groups.get('unknown')||{key:'unknown',label:'未知 / 私网 / 待定位',coordinates:null,packets:0,bytes:0,ipCount:0,ips:[]};group.packets+=overflowPackets;group.bytes+=overflowBytes;groups.set('unknown',group);}
  return [...groups.values()].sort((a,b)=>b.packets-a.packets);
}
function newDataset(mode,options) {
  const data={id:randomUUID(),mode,status:'starting',startedAt:new Date().toISOString(),updatedAt:null,scope:options.scope||'outgoing',sourceIPs:options.sourceIPs||[],
    name:options.name||'实时网卡采集',interfaces:[],source:null,totals:{capturedPackets:0,packets:0,bytes:0,ignoredPackets:0,unparsedPackets:0,overflowPackets:0,truncatedPackets:0},flows:new Map(),recordings:[],error:null,geoQueued:0,geoFinished:0,geoLimit:250,revision:0};
  datasets.set(mode,data);return data;
}
export function getTraffic(mode='live',{full=false,dataset=null}={}) {
  const data=dataset||datasets.get(mode);if(!data)return {mode,status:'idle',flows:[],regions:[],totals:{packets:0,bytes:0},sourceIPs:[]};
  const flows=[...data.flows.values()].sort((a,b)=>b.packets-a.packets), trackedBytes=flows.reduce((sum,flow)=>sum+flow.bytes,0);
  const {flows:ignored,...metadata}=data;
  return {...metadata,flows:full?flows:flows.slice(0,200),totalDestinations:flows.length,displayLimit:200,
    regions:aggregateRegions(flows,data.totals.overflowPackets,Math.max(0,data.totals.bytes-trackedBytes)),
    geoPending:flows.filter(flow=>['checking-cache','queued','locating'].includes(flow.geoStatus)).length,
    geoUnlocated:flows.filter(flow=>!flow.geo?.coordinates).length,notice:'包数按可解析目的 IP 的帧计数，字节为 PCAP 原始帧长，包含链路头和重传。地区是第三方 IP 库估计；地图按地区汇总，不表示中间路由。'};
}
function touch(data) {data.updatedAt=new Date().toISOString();data.revision++;}
async function locate(data,flow) {
  if(flow.geoStatus)return;
  if(!isPublicIP(flow.ip)){flow.geoStatus='unavailable';flow.geo={coordinates:null,verification:{label:'私网 / 保留地址'},sources:[]};return;}
  flow.geoStatus='checking-cache';
  const cached=await getCachedIP(flow.ip).catch(()=>null);
  if(cached){flow.geo=cached;flow.geoStatus='located';data.geoFinished++;touch(data);if(data.status==='completed')save(data).catch(()=>{});return;}
  if(data.geoQueued>=data.geoLimit){flow.geoStatus='limited';return;}
  flow.geoStatus='queued';data.geoQueued++;geoQueue.push({data,flow});
}
const locator=setInterval(()=>{
  geoStarts=geoStarts.filter(stamp=>Date.now()-stamp<60000);
  while(activeGeo<2 && geoQueue.length && geoStarts.length<30) {
    const {data,flow}=geoQueue.shift();if(datasets.get(data.mode)!==data)continue;
    activeGeo++;geoStarts.push(Date.now());flow.geoStatus='locating';
    lookupIP(flow.ip).then(geo=>{flow.geo=geo;flow.geoStatus=geo.coordinates?'located':'failed';}).catch(error=>{flow.geoStatus='failed';flow.geoError=error.message;}).finally(()=>{activeGeo--;data.geoFinished++;touch(data);if(data.status==='completed')save(data).catch(()=>{});});
  }
},250);locator.unref();

async function save(data) {
  saveQueue=saveQueue.catch(()=>{}).then(async()=>{
    const body=JSON.stringify(getTraffic(data.mode,{full:true,dataset:data}),null,2);
    await mkdir(resolve(trafficDirectory,data.id),{recursive:true});
    await writeFile(resolve(trafficDirectory,data.id,'summary.json'),body);
    if(datasets.get(data.mode)===data){const path=resolve(trafficDirectory,`latest-${data.mode}.json`);await writeFile(path+'.tmp',body);await rename(path+'.tmp',path);}
  });await saveQueue;
}
function connectWorker(child,data) {
  let stderr='',reportedError=false;
  child.stderr.on('data',chunk=>stderr=(stderr+chunk).slice(-4000));
  createInterface({input:child.stdout}).on('line',line=>{
    try {
      const event=JSON.parse(line);
      if(event.event==='ready'){data.status='running';data.scope=event.scope;data.sourceIPs=event.sourceIPs;data.interfaces=event.interfaces;data.recordings=event.recordings;}
      if(event.event==='batch'){
        data.totals=event.totals;
        for(const incoming of event.flows){let flow=data.flows.get(incoming.ip);if(flow)Object.assign(flow,incoming);else{flow={...incoming};data.flows.set(flow.ip,flow);locate(data,flow);}}
      }
      if(event.event==='error'){reportedError=true;data.status='error';data.error=event.error;}
      if(event.event==='done'){data.status='completed';data.finishedAt=new Date().toISOString();data.durationMs=event.durationMs;data.captureStats=event.captureStats;data.recordings=event.recordings;data.recordingLimited=event.recordingLimited;}
      touch(data);
    } catch(error){data.error=`Python 输出无效：${error.message}`;}
  });
  child.on('error',error=>{reportedError=true;data.status='error';data.error=`Python 无法启动：${error.message}`;touch(data);});
  child.on('close',code=>{
    if(!reportedError&&code!==0){data.status='error';data.error=stderr||`Python 退出码 ${code}`;}
    else if(data.status!=='error')data.status='completed';
    touch(data);save(data).catch(()=>{});
    if(data.mode==='live')liveProcess=null;else offlineProcess=null;
  });
  child.stdin.on('error',()=>{});
  return child;
}
export async function startLive({interfaces,record=false}={}) {
  if(liveProcess||startingLive)throw Error('实时抓包正在运行');
  startingLive=true;
  try {
  const available=await listInterfaces();
  if(!Array.isArray(interfaces)||!interfaces.length||interfaces.length>8||interfaces.some(id=>!available.some(device=>device.id===id&&device.addresses.length&&!device.loopback)))throw Error('请选择有效网卡');
  const data=newDataset('live',{scope:'outgoing'});
  const args=['live','--interfaces',interfaces.join(',')];
  if(record){await mkdir(resolve(trafficDirectory,data.id),{recursive:true});args.push('--record-dir',resolve(trafficDirectory,data.id));}
  liveProcess=connectWorker(worker(args),data);
  // Independent of packet decoding; an unavailable egress never blocks capture.
  observeSourceIP().then(source=>{if(datasets.get('live')===data){data.source=source;touch(data);if(data.status==='completed')save(data).catch(()=>{});}}).catch(()=>{});
  return getTraffic();
  } finally {startingLive=false;}
}
export function stopLive() {
  if(liveProcess){const data=datasets.get('live');data.status='stopping';touch(data);liveProcess.stdin.write('stop\n');}
  return getTraffic();
}
export function startOffline({file,name,scope='all',sourceIPs=[]}) {
  if(offlineProcess)throw Error('已有离线分析正在运行');
  if(!['all','outgoing'].includes(scope)||!Array.isArray(sourceIPs)||sourceIPs.length>64||sourceIPs.some(ip=>!isIP(ip))||(scope==='outgoing'&&!sourceIPs.length))throw Error('出站分析需要填写有效源 IP，可用逗号分隔');
  const data=newDataset('offline',{scope,sourceIPs,name});
  const args=['offline','--file',file,'--scope',scope,'--sources',sourceIPs.join(',')];
  offlineProcess=connectWorker(worker(args),data);
  if(scope==='outgoing'&&sourceIPs.length===1&&isPublicIP(sourceIPs[0]))lookupIP(sourceIPs[0]).then(source=>{data.source=source;touch(data);}).catch(()=>{});
  return getTraffic('offline');
}
export function streamTraffic(req,res,mode) {
  res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-store','Connection':'keep-alive'});
  const client={res,mode,revision:-1};clients.add(client);
  res.write(`data: ${JSON.stringify(getTraffic(mode))}\n\n`);
  req.on('close',()=>clients.delete(client));
}
const streamer=setInterval(()=>{
  for(const client of clients){const revision=datasets.get(client.mode)?.revision||0;if(revision!==client.revision){client.revision=revision;if(!client.res.writableNeedDrain)client.res.write(`data: ${JSON.stringify(getTraffic(client.mode))}\n\n`);}else client.res.write(': heartbeat\n\n');}
},1000);streamer.unref();
export async function recording(mode,index) {
  const data=datasets.get(mode);if(!data||data.status!=='completed')throw Error('请停止抓包后下载');
  const name=data.recordings[index];if(!name)throw Error('没有此 PCAP');
  const path=resolve(trafficDirectory,data.id,name);return {name,path,size:(await stat(path)).size};
}
export function shutdownTraffic() {
  if(liveProcess){liveProcess.stdin.write('stop\n');setTimeout(()=>liveProcess?.kill(),1500).unref();}
  offlineProcess?.kill();for(const client of clients)client.res.end();
}
for(const mode of ['live','offline']){
  try {
    const data=JSON.parse(await readFile(resolve(trafficDirectory,`latest-${mode}.json`),'utf8'));
    if(!/^[a-f0-9-]{36}$/.test(data.id)||!Array.isArray(data.flows))continue;
    data.flows=new Map(data.flows.map(flow=>[flow.ip,flow]));
    if(['running','starting','stopping'].includes(data.status)){data.status='completed';data.error='上次采集被服务重启中断';}
    const pendingFlows=[...data.flows.values()].filter(flow=>['checking-cache','queued','locating'].includes(flow.geoStatus));
    data.geoQueued=Math.max(0,data.geoQueued-pendingFlows.length);
    datasets.set(mode,data);
    await Promise.all([...data.flows.values()].map(async flow=>{const cached=await getCachedIP(flow.ip);if(cached){flow.geo=cached;flow.geoStatus='located';}}));
    for(const flow of pendingFlows){if(!flow.geo?.coordinates){delete flow.geoStatus;locate(data,flow);}}
    touch(data);
  }catch{}
}
