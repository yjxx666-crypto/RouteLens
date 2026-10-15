const $=selector=>document.querySelector(selector), NS='http://www.w3.org/2000/svg';
const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const number=value=>Number(value||0).toLocaleString('zh-CN');
const bytes=value=>value<1024?`${value||0} B`:value<1048576?`${(value/1024).toFixed(1)} KB`:value<1073741824?`${(value/1048576).toFixed(2)} MB`:`${(value/1073741824).toFixed(2)} GB`;
const clock=value=>value?new Date(value*1000).toLocaleTimeString('zh-CN',{hour12:false}):'—';
const state={mode:'live',data:null,stream:null,geography:null,world:null,selected:null,frame:null,mapScope:'china',lastGeometry:null,revision:null};
const project=([lon,lat])=>[(lon+180)*3,(90-lat)*3];
function svg(tag,attributes,parent){const element=document.createElementNS(NS,tag);for(const [key,value]of Object.entries(attributes))element.setAttribute(key,value);parent?.appendChild(element);return element;}
function message(text,error=false){$('#capture-status-note').textContent=text;$('.capture-status').classList.toggle('error',error);}
async function api(path,body){const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-RouteLens':'local'},body:JSON.stringify(body||{})});const data=await response.json();if(!response.ok)throw Error(data.error||'操作失败');return data;}
function showMode(mode){
  window.trafficActive=mode!=='validation';document.body.classList.toggle('traffic-mode',window.trafficActive);
  $('#validation-workspace').hidden=window.trafficActive;$('#traffic-workspace').hidden=!window.trafficActive;
  document.querySelectorAll('[data-traffic-mode]').forEach(button=>{button.classList.toggle('active',button.dataset.trafficMode===mode);if(button.dataset.trafficMode===mode)button.setAttribute('aria-current','page');else button.removeAttribute('aria-current');});
  state.stream?.close();state.stream=null;
  if(mode==='validation'){$('.page-heading .eyebrow').textContent='网站连接端点';$('#page-title').textContent='网站验证';$('#page-description').textContent='访问网站，核对实际目的 IP 与地区。';$('#breadcrumb-current').textContent='网站验证';$('#mode-label').textContent='本机运行';requestAnimationFrame(()=>window.fitValidationMap?.());return;}
  state.mode=mode;state.data=null;state.selected=null;state.revision=null;
  $('.page-heading .eyebrow').textContent=mode==='live'?'本机出站流量':'历史流量分析';
  $('#page-title').textContent=mode==='live'?'实时流量':'PCAP 分析';
  $('#page-description').textContent=mode==='live'?'查看流量去向，按地区统计包数与流量。':'导入抓包文件，查看目的地区与流量分布。';
  $('#breadcrumb-current').textContent=mode==='live'?'实时流量':'PCAP 分析';$('#mode-label').textContent='本机运行';$('#session-label').textContent='数据保留在本机';
  $('#live-controls').hidden=mode!=='live';$('#offline-controls').hidden=mode!=='offline';
  $('#traffic-export').href=`/api/traffic/export?mode=${mode}`;
  fetch(`/api/traffic/snapshot?mode=${mode}`,{cache:'no-store'}).then(r=>r.json()).then(data=>{if(state.mode===mode&&window.trafficActive)render(data);}).catch(error=>message(error.message,true));
  state.stream=new EventSource(`/api/traffic/events?mode=${mode}`);
  state.stream.onmessage=event=>{try{render(JSON.parse(event.data));}catch(error){message(`数据刷新失败：${error.message}`,true);}};
  state.stream.onerror=()=>message('本机服务暂时断开，正在重连…',true);
  fitMap();
}
window.showTrafficMode=showMode;
function render(data){
  state.data=data;
  const labels={idle:'等待开始',starting:'正在打开网卡',running:state.mode==='live'?'正在抓包':'正在分析',stopping:'正在停止',completed:state.mode==='live'?'抓包已停止':'解析完成',error:'采集失败'};
  $('#capture-state').textContent=labels[data.status]||data.status;
  $('#capture-dot').style.background=data.status==='running'?'#bce68a':data.status==='error'?'#dc9b72':'#6e8b91';
  const ipv4=data.sourceIPs?.filter(ip=>!ip.includes(':'))||[],ipv6Count=(data.sourceIPs?.length||0)-ipv4.length;
  const sourceLabel=[...ipv4,ipv6Count?`${ipv6Count} 个 IPv6 地址`:null].filter(Boolean).join(' · ');
  message(data.error||`${data.scope==='all'?'全部包':state.mode==='live'?'本机出站':'指定源出站'}${sourceLabel?` · ${sourceLabel}`:''}${data.name&&state.mode==='offline'?` · ${data.name}`:''}`,!!data.error);
  const active=['starting','running','stopping'].includes(data.status);
  if(state.mode==='live'){$('#capture-start').disabled=active;$('#capture-stop').disabled=!['starting','running'].includes(data.status);$('#record-pcap').disabled=active;document.querySelectorAll('.adapter-option input').forEach(input=>input.disabled=active);}
  $('#analyze-pcap').disabled=state.mode==='offline'&&active;
  const totals=data.totals||{},regions=data.regions||[],located=regions.filter(region=>region.coordinates);
  $('#traffic-packets').textContent=number(totals.packets);$('#traffic-bytes').textContent=bytes(totals.bytes);
  $('#traffic-packet-note').textContent=`已读 ${number(totals.capturedPackets)} 帧 · 忽略 ${number(totals.ignoredPackets)}`;
  $('#traffic-destinations').textContent=number(data.totalDestinations);
  $('#traffic-regions').textContent=number(located.length);
  $('#traffic-geo-note').textContent=`${number(data.geoUnlocated)} 个 IP 未定位${data.geoPending?` · ${number(data.geoPending)} 个待核对`:''}`;
  $('.traffic-stats .stat-card:first-child .stat-label').textContent=data.scope==='all'?'已解析包数':'出站包数';
  $('.traffic-stats .stat-card:nth-child(2) .stat-label').textContent=data.scope==='all'?'已解析流量':'出站流量';
  const duration=data.durationMs||Math.max(0,Date.now()-Date.parse(data.startedAt));
  $('#traffic-rate').textContent=state.mode==='offline'?(data.durationMs?`文件解析耗时 ${(data.durationMs/1000).toFixed(2)} s`:'正在流式解析文件'):duration?`会话均值 ${bytes(totals.bytes/(duration/1000))}/s · 原始帧长`:'含链路头与重传';
  const drops=(data.captureStats||[]).reduce((sum,item)=>sum+item.dropped+item.interfaceDropped,0);
  $('#traffic-quality').textContent=`未解析 ${number(totals.unparsedPackets)} 帧 · 截短 ${number(totals.truncatedPackets)} 帧 · ${data.status==='completed'?`驱动报告丢包 ${number(drops)}`:'驱动丢包数在停止后核对'}${totals.overflowPackets?` · 容量外 ${number(totals.overflowPackets)} 包归入未知`:''}。每会话自动核对至多 ${data.geoLimit||250} 个新公网 IP，其余保持未知。`;
  $('#traffic-table-note').textContent=`共 ${number(data.totalDestinations)} 个${data.totalDestinations>data.displayLimit?` · 展示前 ${data.displayLimit} 个，导出包含全部`:''}`;
  $('#traffic-map-caption').textContent=`${located.length} 个已定位地区 · ${number(totals.packets)} 包`;
  $('#traffic-source-note').textContent=state.mode==='offline'?(data.source?.coordinates?`文件源 IP ${data.source.ip}`:'历史源位置未知，仅标记目的地区'):(data.source?.ip?`出口观测 ${data.source.ip} · ${data.source.cityLabel||'位置未知'}`:'公网出口正在观测；目的 IP 统计持续进行');
  $('#recording-links').innerHTML=data.status==='completed'?(data.recordings||[]).map((name,index)=>`<a href="/api/traffic/recording?mode=${state.mode}&index=${index}">下载 ${esc(name)} ↗</a>`).join('')+(data.recordingLimited?' · PCAP 达到 256 MB 上限，统计继续但文件仅含前段数据':''):'';
  $('#device-location').textContent=data.source?.cityLabel?`${data.source.cityLabel} · 出口估计`:'本机网卡 / 真实数据';
  if(!state.selected&&located.length)state.selected=located[0].key;
  if(located.some(region=>region.key&&!region.key.startsWith('CN/'))&&state.mapScope==='china'&&!state.manualScope){state.mapScope='world';$('#traffic-map-scope').value='world';drawLand();fitMap();}
  renderRegions();renderTable();renderMap();
}
function renderRegions(){
  const regions=[...(state.data?.regions||[])],metric=$('#region-metric').value;
  regions.sort((a,b)=>b[metric]-a[metric]);const total=regions.reduce((sum,region)=>sum+region[metric],0),max=regions[0]?.[metric]||1;
  $('#region-ranking').innerHTML=regions.map((region,index)=>`<button class="region-row ${state.selected===region.key?'active':''}" data-region="${esc(region.key)}"><span class="rank">${String(index+1).padStart(2,'0')}</span><span><strong>${esc(region.label)}</strong><span class="region-bar"><i style="width:${Math.max(1,region[metric]/max*100)}%"></i></span><small>${region.ipCount} 个 IP · ${bytes(region.bytes)}</small></span><span class="region-number">${metric==='packets'?number(region.packets):bytes(region.bytes)}<small>${total?(region[metric]/total*100).toFixed(1):0}%${metric==='packets'?' · 包':''}</small></span></button>`).join('')||'<p class="traffic-placeholder">尚无流量记录</p>';
  renderDetail();
}
function renderDetail(){
  const region=state.data?.regions?.find(item=>item.key===state.selected);
  if(!region){$('#region-detail').textContent='点击地区查看目的 IP 和定位来源';return;}
  const flow=state.data.flows.find(item=>item.ip===region.representativeIP),geo=flow?.geo;
  $('#region-detail').innerHTML=`<strong>${esc(region.label)}</strong><p>${number(region.packets)} 包 · ${bytes(region.bytes)} · ${region.ipCount} 个目的 IP</p><div class="region-detail-ips">${region.ips.map(esc).join('<br>')}${region.ipCount>region.ips.length?'<br>… 完整列表见导出':''}</div><p>标记采用该地区流量最多 IP 的坐标估计${geo?` · ${esc(geo.verification?.label||'未知')}`:''}，表示地区汇总。</p>${(geo?.sources||[]).map(source=>`<a href="${esc(source.url)}" target="_blank" rel="noopener noreferrer">${esc(source.provider)} ↗</a>`).join('')}${geo?.checkedAt?`<p>核对时间 ${esc(new Date(geo.checkedAt).toLocaleString('zh-CN',{hour12:false}))}${geo.cacheHit?' · 缓存':''}</p>`:''}`;
}
function renderTable(){
  const search=$('#traffic-search').value.trim().toLowerCase();
  const labels={'checking-cache':'检查缓存',queued:'等待定位',locating:'正在核对',located:'',failed:'查询失败',limited:'达到自动定位上限',unavailable:'无法外部定位'};
  $('#traffic-destinations-body').innerHTML=(state.data?.flows||[]).filter(flow=>[flow.ip,flow.geo?.regionLabel,flow.geo?.cityLabel,flow.geo?.country].join(' ').toLowerCase().includes(search)).map(flow=>`<tr><td class="mono">${esc(flow.ip)}</td><td>${esc([flow.geo?.country,flow.geo?.regionLabel,flow.geo?.cityLabel].filter((value,index,array)=>value&&array.indexOf(value)===index).join(' / ')||'位置未知')}<div class="geo-state ${esc(flow.geoStatus)}">${esc(labels[flow.geoStatus]||flow.geo?.verification?.label||'未知')}${flow.geo?.cacheHit?' · 缓存':''}</div></td><td class="mono">${number(flow.packets)}</td><td class="mono">${bytes(flow.bytes)}</td><td>${esc(Object.keys(flow.protocols||{}).join(' / '))}</td><td class="mono">${clock(flow.lastSeen)}</td></tr>`).join('')||'<tr><td colspan="6">暂无匹配记录</td></tr>';
}
function geometryPath(geometry){const polygons=geometry.type==='Polygon'?[geometry.coordinates]:geometry.coordinates;return polygons.map(polygon=>polygon.map(ring=>ring.map((coordinate,index)=>{const [x,y]=project(coordinate);return `${index?'L':'M'}${x.toFixed(1)},${y.toFixed(1)}`;}).join('')+'Z').join('')).join('');}
function drawLand(){
  if(state.lastGeometry===state.mapScope)return;
  $('#traffic-land').replaceChildren();$('#traffic-labels').replaceChildren();
  const geography=state.mapScope==='world'?state.world:state.geography;
  for(const feature of geography.features){if(!['Polygon','MultiPolygon'].includes(feature.geometry?.type))continue;svg('path',{d:geometryPath(feature.geometry),class:'province','data-name':feature.properties.name||feature.properties.NAME_ZH||feature.properties.NAME},$('#traffic-land'));
    const center=feature.properties.centroid||feature.properties.center;if(state.mapScope==='china'&&center){const [x,y]=project(center);svg('text',{x,y,class:'province-label','text-anchor':'middle'},$('#traffic-labels')).textContent=(feature.properties.name||'').replace(/省|自治区|壮族|回族|维吾尔/g,'');}}
  state.lastGeometry=state.mapScope;
}
function setFrame(frame){state.frame=frame;$('#traffic-map').setAttribute('viewBox',`${frame.cx-frame.width/2} ${frame.cy-frame.height/2} ${frame.width} ${frame.height}`);renderMap();}
function fitMap(){const stage=$('#traffic-map-stage');if(!stage?.clientWidth)return;const width=state.mapScope==='china'?Math.max(165,120*stage.clientWidth/stage.clientHeight):Math.max(1100,570*stage.clientWidth/stage.clientHeight);setFrame({cx:state.mapScope==='china'?850:540,cy:state.mapScope==='china'?166:270,width,height:width*stage.clientHeight/stage.clientWidth});}
function renderMap(){
  if(!state.frame||!state.geography)return;drawLand();
  const stage=$('#traffic-map-stage'),unit=state.frame.width/stage.clientWidth,regions=state.data?.regions?.filter(region=>region.coordinates)||[];
  const source=state.data?.source?.coordinates?state.data.source:null,max=Math.max(1,...regions.map(region=>region.packets)),occupied=[];
  $('.traffic-map-legend span:first-child').hidden=!source;
  $('#traffic-pins').replaceChildren();$('#traffic-lines').replaceChildren();$('#traffic-map-empty').hidden=regions.length>0;
  document.querySelectorAll('#traffic-land .province').forEach(element=>element.classList.toggle('active-region',regions.some(region=>region.key.startsWith('CN/')&&element.dataset.name?.startsWith(region.key.slice(3)))));
  document.querySelectorAll('#traffic-labels .province-label').forEach(element=>element.style.fontSize=`${10*unit}px`);
  for(const region of regions){const [x,y]=project(region.coordinates),radius=6+Math.sqrt(region.packets/max)*12;
    if(source){const [sx,sy]=project(source.coordinates),distance=Math.hypot(x-sx,y-sy);let path;if(distance<unit*15)path=`M${sx},${sy-5*unit} C${sx-45*unit},${sy-75*unit} ${x+75*unit},${y-75*unit} ${x+radius*unit},${y}`;else path=`M${sx},${sy} Q${(sx+x)/2},${(sy+y)/2-25*unit} ${x},${y}`;svg('path',{d:path,class:`traffic-line ${region.key===state.selected?'selected':''}`,'marker-end':'url(#traffic-head)'},$('#traffic-lines'));}
    const pin=svg('g',{class:`traffic-pin ${state.selected===region.key?'active':''}`,transform:`translate(${x},${y}) scale(${unit})`,'data-region':region.key,role:'button',tabindex:0,'aria-label':`${region.label} ${region.packets} 包`},$('#traffic-pins'));
    svg('title',{},pin).textContent=`${region.label} · ${number(region.packets)} 包 · ${bytes(region.bytes)} · ${region.ipCount} IP`;
    svg('circle',{r:radius},pin);
    const label=region.label.replace('中国 · ',''),labelWidth=Math.min(145,Math.max(65,[...label].reduce((sum,char)=>sum+(char.charCodeAt(0)>255?10:5.5),0))),height=30;
    const screenX=(x-state.frame.cx+state.frame.width/2)/unit,screenY=(y-state.frame.cy+state.frame.height/2)/unit;
    let lx=radius+7,ly=-12,chosen=false;
    for(const dy of [-12,24,-48,58,-84,92,-120]){for(const dx of [radius+7,-radius-labelWidth-7]){const box={x:screenX+dx,y:screenY+dy,w:labelWidth,h:height};if(box.x<5||box.y<65||box.x+box.w>stage.clientWidth-5||box.y+box.h>stage.clientHeight-46)continue;if(occupied.some(other=>box.x<other.x+other.w+5&&box.x+box.w+5>other.x&&box.y<other.y+other.h+4&&box.y+box.h+4>other.y))continue;lx=dx;ly=dy;occupied.push(box);chosen=true;break;}if(chosen)break;}
    if(chosen||region.key===state.selected){svg('path',{d:`M${lx>0?radius:-radius},0 L${lx>0?lx-4:lx+labelWidth+4},${ly+11}`,class:'traffic-label-leader'},pin);svg('text',{x:lx,y:ly+10},pin).textContent=label;svg('text',{x:lx,y:ly+25,class:'pin-count'},pin).textContent=`${number(region.packets)} 包`;}
    pin.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();selectRegion(region.key);}});
  }
  if(source){const [x,y]=project(source.coordinates),group=svg('g',{class:'traffic-source',transform:`translate(${x},${y}) scale(${unit})`},$('#traffic-pins'));svg('circle',{r:4},group);svg('text',{x:-10,y:23,'text-anchor':'end'},group).textContent=`源 ${source.cityLabel||source.ip}`;}
}
function selectRegion(key){state.selected=key;renderRegions();renderMap();}
async function interfaces(){try{const response=await fetch('/api/traffic/interfaces'),data=await response.json();if(!response.ok)throw Error(data.error);const devices=data.interfaces.filter(device=>device.addresses.length&&!device.loopback&&device.up);const recommended=devices.find(device=>!/(VMware|Virtual|WAN|Hyper-V)/i.test(device.name)&&device.connected)||devices[0];$('#adapter-list').innerHTML=devices.map(device=>`<label class="adapter-option"><input type="checkbox" value="${esc(device.id)}" ${device===recommended?'checked':''}><span>${esc(device.name)}<small>${esc(device.addresses.join(' · '))}</small></span></label>`).join('');updateAdapterSummary();}catch(error){$('#adapter-summary').textContent='抓包环境不可用';$('#capture-start').disabled=true;message(error.message,true);}}
function updateAdapterSummary(){const chosen=[...document.querySelectorAll('.adapter-option input:checked')];const name=chosen.length===1?chosen[0].closest('label').querySelector('span').firstChild.textContent:`已选择 ${chosen.length} 张网卡`;$('#adapter-summary').textContent=name;$('#adapter-summary').title=name;}
async function init(){
  const [fragment,china,world]=await Promise.all([fetch('./traffic.html').then(r=>r.text()),fetch('./assets/china-provinces.json').then(r=>r.json()),fetch('./assets/world-countries.json').then(r=>r.json())]);
  $('#traffic-workspace').innerHTML=fragment;state.geography=china;state.world=world;
  document.addEventListener('click',event=>{const mode=event.target.closest('[data-traffic-mode]');if(mode)showMode(mode.dataset.trafficMode);const region=event.target.closest('[data-region]');if(region)selectRegion(region.dataset.region);});
  $('#adapter-list').addEventListener('change',updateAdapterSummary);
  $('#capture-start').addEventListener('click',async()=>{try{$('#capture-start').disabled=true;$('.adapter-picker').open=false;const selected=[...document.querySelectorAll('.adapter-option input:checked')].map(input=>input.value);render(await api('/api/traffic/start',{interfaces:selected,record:$('#record-pcap').checked}));}catch(error){$('#capture-start').disabled=false;message(error.message,true);}});
  $('#capture-stop').addEventListener('click',async()=>{try{render(await api('/api/traffic/stop'));}catch(error){message(error.message,true);}});
  $('#offline-scope').addEventListener('change',()=>$('#offline-sources').hidden=$('#offline-scope').value!=='outgoing');
  $('#pcap-file').addEventListener('change',()=>$('#pcap-name').textContent=$('#pcap-file').files[0]?.name||'尚未选择文件');
  $('#analyze-pcap').addEventListener('click',async()=>{const file=$('#pcap-file').files[0];if(!file){message('请先选择 PCAP 或 PCAPNG 文件',true);return;}if(file.size>256*1024*1024){message('文件超过 256 MB 上限',true);return;}try{$('#analyze-pcap').disabled=true;message('正在把文件传给本机分析器…');const params=new URLSearchParams({name:file.name,scope:$('#offline-scope').value,sources:$('#offline-sources').value});const response=await fetch(`/api/traffic/upload?${params}`,{method:'POST',headers:{'X-RouteLens':'local','Content-Type':'application/octet-stream'},body:file});const data=await response.json();if(!response.ok)throw Error(data.error);render(data);}catch(error){message(error.message,true);$('#analyze-pcap').disabled=false;}});
  $('#region-metric').addEventListener('change',renderRegions);$('#traffic-search').addEventListener('input',renderTable);
  $('#traffic-map-scope').addEventListener('change',()=>{state.manualScope=true;state.mapScope=$('#traffic-map-scope').value;drawLand();fitMap();});$('#traffic-fit').addEventListener('click',fitMap);
  const map=$('#traffic-map');let drag;
  map.addEventListener('wheel',event=>{event.preventDefault();if(!state.frame)return;const factor=event.deltaY<0?.9:1.1;const width=Math.min(2300,Math.max(40,state.frame.width*factor));setFrame({...state.frame,width,height:width*$('#traffic-map-stage').clientHeight/$('#traffic-map-stage').clientWidth});},{passive:false});
  map.addEventListener('pointerdown',event=>{if(event.target.closest('.traffic-pin'))return;drag={x:event.clientX,y:event.clientY,frame:{...state.frame}};map.setPointerCapture(event.pointerId);});map.addEventListener('pointermove',event=>{if(!drag)return;const unit=drag.frame.width/map.getBoundingClientRect().width;setFrame({...drag.frame,cx:drag.frame.cx-(event.clientX-drag.x)*unit,cy:drag.frame.cy-(event.clientY-drag.y)*unit});});for(const event of ['pointerup','pointercancel'])map.addEventListener(event,()=>drag=null);
  new ResizeObserver(fitMap).observe($('#traffic-map-stage'));
  showMode('live');await interfaces();
}
init().catch(error=>{const host=$('#traffic-workspace');host.hidden=false;host.textContent=`流量模块加载失败：${error.message}`;});
window.addEventListener('pagehide',()=>state.stream?.close());
