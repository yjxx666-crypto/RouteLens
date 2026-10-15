import { isIP } from 'node:net';
import { readFile, mkdir, writeFile, rename } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const directory=resolve(dirname(fileURLToPath(import.meta.url)),'../.local');
const cachePath=resolve(directory,'ip-location-cache.json');
export const CACHE_TTL_MS=24*60*60*1000;
const REQUEST_TIMEOUT_MS=4500;
const regionNames={Beijing:'北京','Beijing Shi':'北京',Tianjin:'天津','Tianjin Shi':'天津',Shanghai:'上海','Shanghai Shi':'上海',Chongqing:'重庆','Chongqing Shi':'重庆',Hebei:'河北',Shanxi:'山西','Inner Mongolia':'内蒙古',Liaoning:'辽宁',Jilin:'吉林',Heilongjiang:'黑龙江',Jiangsu:'江苏',Zhejiang:'浙江',Anhui:'安徽',Fujian:'福建',Jiangxi:'江西',Shandong:'山东',Henan:'河南',Hubei:'湖北',Hunan:'湖南',Guangdong:'广东',Guangxi:'广西',Hainan:'海南',Sichuan:'四川',Guizhou:'贵州',Yunnan:'云南',Tibet:'西藏',Shaanxi:'陕西',Gansu:'甘肃',Qinghai:'青海',Ningxia:'宁夏',Xinjiang:'新疆','Hong Kong':'香港',Macau:'澳门',Taiwan:'台湾'};
const cityNames={Beijing:'北京',Tianjin:'天津',Shanghai:'上海',Chongqing:'重庆',Guangzhou:'广州',Shenzhen:'深圳',Cangzhou:'沧州',Hangzhou:'杭州',Nanjing:'南京',Wuhan:'武汉',Chengdu:'成都',Fuzhou:'福州',Jinan:'济南',Shijiazhuang:'石家庄',Zhuhai:'珠海',Dongguan:'东莞',Baoding:'保定',Changsha:'长沙',HongKong:'香港'};
let cache,loadPromise,writeQueue=Promise.resolve();
const pending=new Map();
const stats={networkRequests:0,cacheHits:0};
export function getLocationStats(){return{...stats};}

export function isPublicIPv4(ip){
  if(isIP(ip)!==4)return false;
  const [a,b,c]=ip.split('.').map(Number);
  return !(a===0||a===10||a===127||a>=224||(a===172&&b>=16&&b<=31)||(a===192&&b===168)||(a===169&&b===254)||(a===100&&b>=64&&b<=127)||(a===198&&[18,19].includes(b))||(a===192&&b===0&&[0,2].includes(c))||(a===198&&b===51&&c===100)||(a===203&&b===0&&c===113));
}
function canonicalIP(ip){return isIP(ip)===6?new URL(`http://[${ip}]/`).hostname.slice(1,-1):ip;}
export function isPublicIP(ip){
  if(isIP(ip)===4)return isPublicIPv4(ip);
  if(isIP(ip)!==6)return false;
  const normalized=canonicalIP(ip),first=parseInt(normalized.split(':')[0],16);
  return first>=0x2000&&first<=0x3fff&&!/^2001:(db8|[012]?[0-9a-f]):/i.test(normalized)&&!/^3fff:/i.test(normalized);
}
function label(value,names){return names[value]||names[value?.replace(/\s+(Shi|Sheng)$/i,'')]||value||null;}
function key(value){const translated=label(value,regionNames)||'';return (cityNames[translated]||translated).toLowerCase().replace(/province|city|省|市|自治区|壮族|回族|维吾尔|\s|[-_.]/g,'');}
export function compareLocations(sources){
  const valid=sources.filter(s=>s.ok&&s.location?.coordinates);
  if(!valid.length)return{status:'unavailable',label:'定位不可用',note:'第三方位置查询没有成功，保持未知。'};
  if(valid.length===1)return{status:'single-source',label:'单一来源',note:'只有一家提供位置，尚未完成双源核对。'};
  const [a,b]=valid.map(s=>s.location);
  const country=a.countryCode===b.countryCode;
  const region=key(a.region)===key(b.region);
  const city=key(a.city)===key(b.city);
  return country&&region&&city?{status:'consistent',label:'双源一致',note:'两家服务的国家、地区及城市一致；仍属于 IP 地理位置估计。'}:{status:'conflicting',label:'来源有分歧',note:'两家服务返回的位置不完全一致，地图采用 IPWHOIS 的估计并同时展示两家结果。'};
}
function normalize(provider,data){
  let lat,lon,countryCode,region,city,isp;
  if(provider==='IPWHOIS'){if(data.latitude==null||data.longitude==null)return null;lat=Number(data.latitude);lon=Number(data.longitude);countryCode=data.country_code;region=data.region;city=data.city;isp=data.connection?.isp||data.connection?.org||null;}
  else{[lat,lon]=(data.loc||'').split(',').map(Number);countryCode=data.country;region=data.region;city=data.city;isp=data.org||null;}
  if(!Number.isFinite(lat)||!Number.isFinite(lon)||Math.abs(lat)>85||Math.abs(lon)>180)return null;
  return{countryCode,country:({CN:'中国',US:'美国',GB:'英国',JP:'日本',AR:'阿根廷',DE:'德国',SG:'新加坡',AU:'澳大利亚',CA:'加拿大',FR:'法国',KR:'韩国'})[countryCode]||countryCode,region,regionLabel:label(region,regionNames),city,cityLabel:label(city,cityNames),coordinates:[lon,lat],isp,coordinateMeaning:'第三方 IP 库返回的 WGS84 估计坐标，不能证明设备物理位置。'};
}
async function request(provider,ip=''){
  stats.networkRequests++;
  const url=provider==='IPWHOIS'?`https://ipwho.is/${ip}`:`https://ipinfo.io/${ip?ip+'/':''}json`;
  const queriedAt=new Date().toISOString(),start=performance.now();
  try{
    const response=await fetch(url,{signal:AbortSignal.timeout(REQUEST_TIMEOUT_MS)});
    if(!response.ok)throw Error(`HTTP ${response.status}`);
    const raw=await response.json();if(raw.success===false||raw.error)throw Error(raw.message||'服务返回错误');
    if(!isPublicIP(raw.ip)|| (ip&&canonicalIP(raw.ip)!==canonicalIP(ip)))throw Error('服务返回的 IP 与查询不符，或不是公网地址');
    const location=normalize(provider,raw);if(!location)throw Error('没有可用的经纬度');
    return{provider,url,queriedAt,durationMs:Math.round(performance.now()-start),ok:true,ip:raw.ip,location};
  }catch(error){return{provider,url,queriedAt,durationMs:Math.round(performance.now()-start),ok:false,error:error.message};}
}
async function loadCache(){if(cache)return cache;if(!loadPromise)loadPromise=(async()=>{try{cache=JSON.parse(await readFile(cachePath,'utf8'));}catch{cache={version:1,entries:{}};}return cache;})();return loadPromise;}
async function persist(){writeQueue=writeQueue.catch(()=>{}).then(async()=>{await mkdir(directory,{recursive:true});const temp=cachePath+'.tmp';await writeFile(temp,JSON.stringify(cache,null,2));await rename(temp,cachePath);});await writeQueue;}
export function clearMemoryCache(){cache=null;loadPromise=null;pending.clear();}
export async function getCachedIP(ip){
  if(!isPublicIP(ip))return null;
  const stored=await loadCache(),entry=stored.entries[ip];
  const ttl=entry?.verification.status==='single-source'?5*60*1000:CACHE_TTL_MS;
  return entry&&Date.now()-Date.parse(entry.checkedAt)<ttl?lookupIP(ip):null;
}
export async function lookupIP(ip,{seed=null}={}){
  if(!isPublicIP(ip))return{ip,coordinates:null,verification:{status:'unavailable',label:'无法定位',note:'私网及保留地址不发送到外部查询服务。'},sources:[],cacheHit:false};
  const stored=await loadCache(),entry=stored.entries[ip];
  const ttl=entry?.verification.status==='single-source'?5*60*1000:CACHE_TTL_MS;
  if(entry&&Date.now()-Date.parse(entry.checkedAt)<ttl){stats.cacheHits++;const sources=entry.sources.map(source=>source.location?{...source,location:{...source.location,regionLabel:label(source.location.region,regionNames),cityLabel:label(source.location.city,cityNames)}}:source);return{...entry,country:({CN:'中国',US:'美国',GB:'英国',JP:'日本',AR:'阿根廷',DE:'德国',SG:'新加坡',AU:'澳大利亚',CA:'加拿大',FR:'法国',KR:'韩国'})[entry.countryCode]||entry.countryCode,sources,regionLabel:label(entry.region,regionNames),cityLabel:label(entry.city,cityNames),verification:compareLocations(sources),cacheHit:true,cacheAgeMs:Date.now()-Date.parse(entry.checkedAt)};}
  if(pending.has(ip))return pending.get(ip);
  const task=(async()=>{
    const sources=await Promise.all([seed?.ok&&seed.ip===ip?seed:request('IPWHOIS',ip),request('IPinfo',ip)]);
    const primary=sources.find(s=>s.ok&&s.provider==='IPWHOIS')||sources.find(s=>s.ok);
    const verification=compareLocations(sources);
    const result={ip,...primary?.location,coordinates:primary?.location.coordinates||null,selectedProvider:primary?.provider||null,verification,sources,checkedAt:new Date().toISOString(),cacheHit:false,cacheTTLHours:24};
    if(primary){stored.entries[ip]=result;await persist();}
    else if(entry)return{...entry,cacheHit:true,stale:true,verification:{status:'stale',label:'缓存已过期',note:'第三方查询失败，暂时展示已标注日期的旧估计。'},latestFailures:sources};
    return result;
  })();pending.set(ip,task);try{return await task;}finally{pending.delete(ip);}
}
export async function observeSourceIP(){
  const observation=await request('IPWHOIS');
  if(!observation.ok)return{ip:null,coordinates:null,observation,sources:[],verification:{status:'unavailable',label:'出口未知',note:observation.error}};
  const geo=await lookupIP(observation.ip,{seed:observation});
  return{...geo,observation,note:'公网出口由第三方当前 IP 接口观测。它不是本机内网地址；分流、代理或多出口网络可能对不同目标使用不同出口。'};
}
