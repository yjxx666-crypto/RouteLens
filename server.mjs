import http from 'node:http';
import { readFile, stat, mkdir, unlink } from 'node:fs/promises';
import { createWriteStream, createReadStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';
import { randomUUID } from 'node:crypto';
import { extname, resolve, sep } from 'node:path';
import { gzipSync } from 'node:zlib';
import { collectMeasurements, readMeasurements, localDirectory, targets, abortMeasurements } from './scripts/measurements.mjs';
import { normalizeWebsite } from './scripts/website-validation.mjs';
import { listInterfaces, getTraffic, startLive, stopLive, startOffline, streamTraffic, trafficDirectory, recording, shutdownTraffic } from './scripts/traffic.mjs';
const root = resolve('dist');
const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml' };
const staticCache = new Map();
let job = { running: false, message: '等待采集', completedAt: null, error: null };
function json(res,status,data) { res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(data)); }
let uploading=false;
function localWrite(req){return (!req.headers.origin||['http://127.0.0.1:4318','http://localhost:4318'].includes(req.headers.origin))&&req.headers['x-routelens']==='local';}
async function readJSON(req){let body='';for await(const chunk of req){body+=chunk;if(body.length>8192)throw Error('请求过长');}return JSON.parse(body);}
const server = http.createServer(async (req, res) => {
  try {
    if(!['127.0.0.1:4318','localhost:4318'].includes(req.headers.host)){json(res,403,{error:'只接受本机访问'});return;}
    const url=new URL(req.url, 'http://127.0.0.1:4318');
    const pathname = decodeURIComponent(url.pathname);
    if(pathname.startsWith('/api/')) {
      if(pathname.startsWith('/api/traffic/')) {
        const mode=url.searchParams.get('mode')==='offline'?'offline':'live';
        if(req.method==='GET'&&pathname==='/api/traffic/interfaces'){try{json(res,200,{interfaces:await listInterfaces()});}catch(error){json(res,503,{error:error.message});}return;}
        if(req.method==='GET'&&pathname==='/api/traffic/snapshot'){json(res,200,getTraffic(mode));return;}
        if(req.method==='GET'&&pathname==='/api/traffic/events'){streamTraffic(req,res,mode);return;}
        if(req.method==='GET'&&pathname==='/api/traffic/export'){res.setHeader('Content-Disposition',`attachment; filename="routelens-${mode}.json"`);json(res,200,getTraffic(mode,{full:true}));return;}
        if(req.method==='GET'&&pathname==='/api/traffic/recording'){try{const file=await recording(mode,Number(url.searchParams.get('index')||0));res.writeHead(200,{'Content-Type':'application/vnd.tcpdump.pcap','Content-Disposition':`attachment; filename="${file.name}"`,'Content-Length':file.size,'Cache-Control':'no-store'});await pipeline(createReadStream(file.path),res);}catch(error){if(!res.headersSent)json(res,400,{error:error.message});}return;}
        if(req.method==='POST') {
          if(!localWrite(req)){json(res,403,{error:'只接受本地页面操作'});return;}
          try {
            if(pathname==='/api/traffic/start'){json(res,202,await startLive(await readJSON(req)));return;}
            if(pathname==='/api/traffic/stop'){json(res,200,stopLive());return;}
            if(pathname==='/api/traffic/upload') {
              if(uploading||['starting','running'].includes(getTraffic('offline').status)){json(res,409,{error:'已有离线文件正在处理'});return;}
              const name=(url.searchParams.get('name')||'capture.pcap').slice(0,160);
              if(!/\.pcap(ng)?$/i.test(name)){json(res,400,{error:'请选择 .pcap 或 .pcapng 文件'});return;}
              const scope=url.searchParams.get('scope')||'all',sourceIPs=(url.searchParams.get('sources')||'').split(',').map(ip=>ip.trim()).filter(Boolean);
              await mkdir(resolve(trafficDirectory,'uploads'),{recursive:true});
              const file=resolve(trafficDirectory,'uploads',randomUUID()+'.pcap');
              uploading=true;
              try {
                let size=0;
                const limit=new Transform({transform(chunk,encoding,callback){size+=chunk.length;callback(size>256*1024*1024?Error('文件超过 256 MB 上限'):null,chunk);}});
                await pipeline(req,limit,createWriteStream(file));
                if(size<24)throw Error('文件太短，无法解析 PCAP');
                const data=startOffline({file,name,scope,sourceIPs});json(res,202,data);
              } catch(error){await unlink(file).catch(()=>{});if(!res.destroyed)json(res,400,{error:error.message});}
              finally {uploading=false;}
              return;
            }
          } catch(error){json(res,400,{error:error.message});return;}
        }
        json(res,404,{error:'抓包接口不存在'});return;
      }
      if(req.method==='GET'&&pathname==='/api/status'){json(res,200,job);return;}
      if(req.method==='GET'&&pathname==='/api/measurements'){const data=await readMeasurements();json(res,data?200:404,data||{error:'尚无真实数据，请运行 node scripts/collect.mjs'});return;}
      if(req.method==='GET'&&pathname==='/api/raw') {
        const id=url.searchParams.get('id');if(!id||!/^[-a-z0-9]{1,64}$/.test(id)){json(res,400,{error:'无效的记录 ID'});return;}
        const data=await readMeasurements();const connection=data?.connections.find(c=>c.id===id);
        if(connection?.endpointOnly){json(res,200,{domain:connection.domain,command:connection.http.command,startedAt:connection.http.startedAt,text:JSON.stringify({url:connection.url,validation:connection.validation,http:connection.http,source:connection.source,destinationIP:connection.destinationIP,destinationGeo:connection.destinationGeo},null,2)});return;}
        if(!connection?.trace?.rawFile){json(res,404,{error:'没有原始探测记录'});return;}
        const path=resolve(localDirectory,connection.trace.rawFile);if(!path.startsWith(localDirectory+sep)){json(res,403,{error:'无效路径'});return;}
        const text=await readFile(path,'utf8');json(res,200,{domain:connection.domain,command:connection.trace.command,startedAt:connection.trace.startedAt,text});return;
      }
      if(req.method==='POST'&&pathname==='/api/measurements') {
        const origin=req.headers.origin;
        if((origin&&!['http://127.0.0.1:4318','http://localhost:4318'].includes(origin))||req.headers['x-routelens']!=='local'||!req.headers['content-type']?.startsWith('application/json')){json(res,403,{error:'只接受本地页面发起的采集'});return;}
        if(job.running){json(res,409,{error:'已有探测正在运行'});return;}
        let input,selected;
        try {
          input=await readJSON(req);
          if(!input||typeof input!=='object'||Array.isArray(input))throw Error('无效的验证请求');
          if('url' in input)selected=[normalizeWebsite(input.url,targets)];
          else {
            const previous=await readMeasurements();
            const available=previous?.connections?.length?previous.connections:targets;
            const chosen=input.id==='all'?available:available.filter(target=>target.id===input.id);
            if(!chosen.length)throw Error('未找到该网站记录，请输入网址。');
            selected=chosen.map(target=>normalizeWebsite(target.url||`https://${target.domain}/`,targets));
          }
        }catch(error){json(res,400,{error:error.message});return;}
        if(job.running){json(res,409,{error:'已有验证正在运行'});return;}
        job={running:true,message:'正在访问并核对端点',completedAt:null,error:null,targetIDs:selected.map(target=>target.id)};json(res,202,job);
        collectMeasurements({selectedTargets:selected,onProgress:message=>{job.message=message;}}).then(data=>{job={running:false,message:`验证完成：${data.timing.successfulRequests} 个成功，${data.timing.failedRequests} 个请求失败，${data.timing.httpErrorResponses} 个 HTTP 错误状态`,completedAt:data.collectedAt,error:null,targetIDs:data.lastMeasuredIDs};}).catch(error=>{job={running:false,message:'验证失败',completedAt:null,error:error.message,targetIDs:selected.map(target=>target.id)};});return;
      }
      json(res,404,{error:'接口不存在'});return;
    }
    if(req.method!=='GET'&&req.method!=='HEAD'){res.writeHead(405);res.end();return;}
    const file = resolve(root, '.' + (pathname === '/' ? '/index.html' : pathname));
    if (file !== root && !file.startsWith(root + sep)) { res.writeHead(403); res.end(); return; }
    const info = await stat(file);
    let asset = staticCache.get(file);
    if(!asset || asset.modified !== info.mtimeMs || asset.size !== info.size) {
      const body = await readFile(file);
      asset = { modified:info.mtimeMs,size:info.size,body,gzip:types[extname(file)] ? gzipSync(body) : null,etag:`"${info.size}-${info.mtimeMs}"` };
      if(staticCache.size >= 16) staticCache.delete(staticCache.keys().next().value);
      staticCache.set(file,asset);
    }
    const headers = { 'Content-Type':types[extname(file)] || 'application/octet-stream','Cache-Control':pathname.startsWith('/assets/') ? 'public, max-age=3600' : 'no-cache','ETag':asset.etag,'Vary':'Accept-Encoding' };
    if(req.headers['if-none-match'] === asset.etag) { res.writeHead(304,headers);res.end();return; }
    const compressed = asset.gzip && /\bgzip\b/.test(req.headers['accept-encoding'] || '');
    const body = compressed ? asset.gzip : asset.body;
    res.writeHead(200,{...headers,...(compressed ? {'Content-Encoding':'gzip'} : {}),'Content-Length':body.length});
    res.end(req.method === 'HEAD' ? undefined : body);
  } catch { res.writeHead(404); res.end('Not found'); }
});
server.listen(4318, '127.0.0.1', () => console.log('Local: http://127.0.0.1:4318'));
process.once('SIGINT',()=>{abortMeasurements();shutdownTraffic();server.close(()=>process.exit(0));});
