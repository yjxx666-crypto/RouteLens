const $ = selector => document.querySelector(selector);
const NS = 'http://www.w3.org/2000/svg';
const icon = name => `<svg aria-hidden="true"><use href="#i-${name}"/></svg>`;
const esc = value => String(value ?? '').replace(/[&<>"']/g, character => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
const time = value => value ? new Date(value).toLocaleString('zh-CN', {timeZone:'Asia/Shanghai', hour12:false}) : '未知';
const bytes = value => value < 1024 ? `${value} B` : value < 1048576 ? `${(value / 1024).toFixed(1)} KB` : `${(value / 1048576).toFixed(2)} MB`;
const milliseconds = seconds => Number.isFinite(seconds) ? `${(seconds * 1000).toFixed(1)} ms` : '—';
const location = geo => [geo?.country, geo?.regionLabel, geo?.cityLabel].filter((value,index,array) => value && array.indexOf(value) === index).join(' / ') || '位置未知';
const state = {data:null, current:null, geo:null, china:null, world:null, worldPromise:null, baseMap:'china', selected:'destination', collecting:false, frame:null, zoom:1, view:'map', fitted:false};
const mercator = latitude => Math.log(Math.tan(Math.PI / 4 + latitude * Math.PI / 360));
const project = ([longitude,latitude]) => [(longitude - 72) * 16, (mercator(54) - mercator(Math.max(-85,Math.min(85,latitude)))) * 620];

function svgElement(tag,attributes={},parent) {
  const element = document.createElementNS(NS,tag);
  for(const [name,value] of Object.entries(attributes)) element.setAttribute(name,value);
  if(parent) parent.appendChild(element);
  return element;
}
function toast(message) {
  $('#toast').textContent = message;
  $('#toast').classList.add('visible');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => $('#toast').classList.remove('visible'),4500);
}
function endpoints(connection=state.current) {
  if(!connection) return [];
  return [
    {role:'source', label:'源公网 IP', ip:connection.source?.ip, geo:connection.source?.geo, localIP:connection.http.localIP},
    {role:'destination', label:'实际目的 IP', ip:connection.destinationIP, geo:connection.destinationGeo}
  ];
}
function verificationBadge(geo) {
  const status = geo?.verification?.status || 'unavailable';
  return `<span class="verification-badge ${esc(status)}">${esc(geo?.verification?.label || '位置未知')}</span>`;
}
function verdict(connection=state.current){return connection?.validation||{status:connection?.http.exitCode===0?'success':'failed',label:connection?.http.exitCode===0?'访问成功':'访问失败',detail:connection?.http.error||'',hint:'',connected:!!connection?.destinationIP};}
function renderResult(){
  const connection=state.current;if(!connection)return;
  const result=verdict(connection),http=connection.http;
  const targetURL=connection.url||`https://${connection.domain}/`;
  const redirected=http.effectiveURL&&http.effectiveURL!==targetURL;
  $('#website-result').hidden=false;
  $('#website-result').className=`website-result ${result.status}`;
  $('#website-result').innerHTML=`<div class="website-result-heading"><span class="website-result-icon" aria-hidden="true">${result.status==='success'?'✓':result.status==='http-error'?'!':'×'}</span><strong>${esc(result.label)}</strong><small>${esc(time(http.startedAt))}</small></div><p>${esc(result.detail)}</p><div class="website-result-url"><span>验证网址</span><code>${esc(targetURL)}</code></div>${redirected?`<div class="website-result-url"><span>最终地址</span><code>${esc(http.effectiveURL)}</code></div>`:''}<p class="website-result-hint">${esc(result.hint)}${http.proxyUsed?' 本次使用代理，远端 IP 可能为代理地址。':''}</p>${http.error?`<details class="website-error-details"><summary>查看原始错误</summary><pre>${esc(http.error)}</pre></details>`:''}`;
}
function renderConnections() {
  $('#target-select').innerHTML=state.data.connections.map(connection=>`<option value="${esc(connection.id)}">${esc(connection.url||connection.domain)} · ${esc(verdict(connection).label)}</option>`).join('');
  $('#target-select').value=state.current.id;
  $('#connection-list').innerHTML = state.data.connections.map(connection => `
    <button class="connection-item ${connection.id === state.current.id ? 'selected' : ''}" data-connection="${esc(connection.id)}" aria-pressed="${connection.id === state.current.id}">
      <span class="site-avatar">${esc(connection.avatar)}</span><span><strong>${esc(connection.domain)}</strong><small>${esc(connection.source?.geo?.cityLabel || '出口未知')} → ${esc(connection.destination)} · HTTP ${connection.http.httpCode || '失败'}</small></span><span class="site-dot"></span>
    </button>`).join('');
  $('#connection-cards').innerHTML = state.data.connections.map(connection => `
    <article class="connection-card"><span class="site-avatar">${esc(connection.avatar)}</span><div><h3>${esc(connection.name)} <span class="website-history-status ${esc(verdict(connection).status)}">${esc(verdict(connection).label)}</span></h3><p class="website-history-url">${esc(connection.url||connection.domain)}</p><p>${esc(connection.destinationIP || '本次没有建立远端连接')} · ${esc(connection.destinationIP?connection.destination:'未绘制目的位置')}<br>${esc(time(connection.http.startedAt))}</p></div><div class="traffic">${bytes(connection.bytes)}<small>实测响应下载量</small></div><button class="button button-secondary" data-connection="${esc(connection.id)}">查看结果${icon('arrow')}</button></article>`).join('');
}
function renderEvidence() {
  const connection = state.current;
  if(!window.trafficActive){$('#mode-label').textContent = '本机运行';
  $('#session-label').textContent = '数据保留在本机';}
  $('#device-location').textContent = `${connection.source?.geo?.cityLabel || '位置未知'} · 公网出口估计`;
  $('#measurement-time').textContent = time(connection.http.startedAt);
  const timing = state.data.timing;
  const result=verdict(connection),http=connection.http;
  const tlsRequired=http.tlsRequired??connection.protocol==='HTTPS';
  const tlsStatus=!tlsRequired?'不适用（HTTP）':result.kind==='certificate'?'未通过':http.tlsVerifyResult===0&&(http.tlsSeconds>0||http.httpCode>0)?'通过':'未完成';
  $('#http-evidence').innerHTML = `
    <span><small>TCP 建连</small><strong>${result.connected||http.connectSeconds>0?milliseconds(http.connectSeconds):'未建立'}</strong></span>
    <span><small>请求总耗时</small><strong>${milliseconds(http.totalSeconds)}</strong></span>
    <span><small>TLS 校验</small><strong>${tlsStatus}</strong></span>
    <span><small>实际响应下载量</small><strong>${bytes(connection.bytes)}</strong></span>
    <span><small>最新刷新 / 定位缓存</small><strong>${timing ? `${(timing.durationMs / 1000).toFixed(2)} s · ${timing.geolocationCacheHits} 次命中` : '—'}</strong></span>`;
  $('#source-ip').textContent = connection.source?.ip || '未知';
  $('#source-region').textContent = `${connection.source?.geo?.cityLabel || '位置未知'} · 公网出口观测`;
  $('#destination-ip').textContent = connection.destinationIP || '未连接';
  $('#destination-region').textContent = connection.destinationIP?`${connection.destination} · 本次实际远端`:result.label;
  $('#http-status').textContent = connection.http.httpCode || '无响应';
  $('#http-status').classList.toggle('good',result.status==='success');
  $('#http-status').classList.toggle('warn',result.status!=='success');
  $('#http-note').textContent = result.status==='success'?`${connection.protocol} · 真实 GET`:(connection.http.httpCode?'已收到 HTTP 状态，详见验证结果':result.label);
  const geo = connection.destinationGeo;
  $('#verification-count').innerHTML = `${geo?.sources?.filter(source => source.ok).length || 0}<small>/ 2 来源</small>`;
  $('#verification-label').textContent = connection.destinationIP?`${geo?.verification?.label || '位置未知'}${geo?.cacheHit ? ' · 缓存' : ''}`:'未建立连接，不查询目的位置';
  $('#map-caption-path').textContent = connection.destinationIP?`${connection.source?.geo?.cityLabel || '未知'} → ${connection.destination}`:result.label;
  renderResult();
}
function renderEndpointTable() {
  $('#endpoint-body').innerHTML = endpoints().map(endpoint => `
    <tr class="hop-row ${endpoint.role === state.selected ? 'selected' : ''}" data-endpoint="${endpoint.role}" tabindex="0" aria-label="${endpoint.label} ${esc(endpoint.ip || '未知')}">
      <td><span class="endpoint-role ${endpoint.role}">${endpoint.label}</span></td><td><span class="mono">${esc(endpoint.ip || (endpoint.role==='destination'?'未建立连接':'未知'))}</span></td><td>${esc(endpoint.role==='destination'&&!endpoint.ip?'未查询':location(endpoint.geo))}</td><td>${endpoint.role==='destination'&&!endpoint.ip?'—':verificationBadge(endpoint.geo)}</td><td class="query-time">${esc(endpoint.role==='destination'&&!endpoint.ip?'—':time(endpoint.geo?.checkedAt))}</td>
    </tr>`).join('');
}
function renderDetails() {
  const endpoint = endpoints().find(item => item.role === state.selected);
  if(!endpoint) return;
  const geo = endpoint.geo;
  $('#detail-role').textContent = endpoint.role === 'source' ? 'SOURCE' : 'DESTINATION';
  $('#node-details').innerHTML = `
    <div class="detail-icon ${endpoint.role}">${icon(endpoint.role === 'source' ? 'monitor' : 'globe')}</div>
    <h3 class="detail-title">${esc(geo?.cityLabel || (endpoint.role==='destination'&&!endpoint.ip?'未建立连接':'位置未知'))} · ${endpoint.role === 'source' ? '源' : '目的'}</h3>
    <p class="detail-subtitle">${endpoint.role === 'source' ? '本机公网出口（第三方观测）' : esc(state.current.domain) + (endpoint.ip?' · 实际连接':' · '+esc(verdict().label))}</p>
    <dl class="detail-fields">
      <div class="detail-field"><dt>IP 地址</dt><dd class="mono">${esc(endpoint.ip || '未知')}</dd></div>
      ${endpoint.localIP ? `<div class="detail-field"><dt>本机内网 IP</dt><dd class="mono">${esc(endpoint.localIP)}</dd></div>` : ''}
      <div class="detail-field"><dt>地区估计</dt><dd>${esc(location(geo))}</dd></div>
      <div class="detail-field"><dt>坐标估计</dt><dd class="mono">${geo?.coordinates ? geo.coordinates.map(value => value.toFixed(4)).join(', ') : '未知'}</dd></div>
      <div class="detail-field"><dt>核对结果</dt><dd>${verificationBadge(geo)}</dd></div>
      <div class="detail-field"><dt>主来源</dt><dd>${esc(geo?.selectedProvider || '未知')}</dd></div>
      <div class="detail-field"><dt>定位缓存</dt><dd>${geo?.stale ? '过期估计' : geo?.cacheHit ? '命中 / 有效期 24 小时' : '本次查询'}</dd></div>
    ${endpoint.role==='destination'?`<div class="detail-field"><dt>访问状态</dt><dd>${esc(verdict().label)}</dd></div>`:''}</dl>
    <div class="detail-divider"></div><div class="provider-heading">第三方核对来源<span>可打开原始查询</span></div>
    <div class="provider-results">${(geo?.sources || []).map(source => `
      <a class="provider-result ${source.ok ? '' : 'failed'}" href="${esc(source.url)}" target="_blank" rel="noopener noreferrer"><strong>${esc(source.provider)}${icon('arrow')}</strong><span>${source.ok ? esc(location(source.location)) : esc(source.error || '查询失败')}</span><small>${esc(time(source.queriedAt))}</small></a>`).join('') || '<p class="empty-provider">暂无可用的第三方位置结果。</p>'}</div>
    <div class="endpoint-note ${geo?.verification?.status === 'conflicting' ? 'warning' : ''}">${esc(endpoint.role==='destination'&&!endpoint.ip?'本次没有实际远端 IP，不补造目的位置。':geo?.verification?.note || '位置未知，不推测坐标。')}${endpoint.role === 'source' ? '<br>分流、代理或多出口网络可能对不同目标使用不同公网出口。' : endpoint.ip?'<br>坐标来自第三方 IP 库，不能证明设备的精确物理位置。':''}</div>`;
}
function selectEndpoint(role) {
  if(!['source','destination'].includes(role)) return;
  state.selected = role;
  renderDetails(); renderEndpointTable();
  document.querySelectorAll('.endpoint-switch button,.endpoint-marker').forEach(element => element.classList.toggle('active',element.dataset.endpoint === role));
}
function selectConnection(id) {
  const connection = state.data?.connections.find(item => item.id === id);
  if(!connection) return;
  state.current = connection;
  state.selected = 'destination';
  $('#target-select').value = id;
  $('#website-url').value = connection.url||`https://${connection.domain}/`;
  renderConnections(); renderEvidence(); selectEndpoint('destination'); setView('map'); fitMap();
  updateBaseMap().catch(error=>toast(error.message));
}
function setView(view) {
  state.view = view;
  $('#map-view').hidden = view !== 'map';
  $('#connections-view').hidden = view !== 'connections';
  if(!window.trafficActive){$('#breadcrumb-current').textContent = '网站验证';
  $('#page-title').textContent = '网站验证';}
  document.querySelectorAll('[data-view]').forEach(element => {element.classList.toggle('active',element.dataset.view === view);element.setAttribute('aria-pressed',element.dataset.view === view);});
}
function polygonPath(geometry) {
  const polygons = geometry.type === 'Polygon' ? [geometry.coordinates] : geometry.coordinates;
  return polygons.map(polygon => polygon.map(ring => ring.map((point,index) => {
    const [x,y] = project(point); return `${index ? 'L' : 'M'}${x.toFixed(1)},${y.toFixed(1)}`;
  }).join('') + 'Z').join('')).join('');
}
function drawBaseMap() {
  $('#province-layer').replaceChildren();$('#map-labels').replaceChildren();
  for(const feature of state.geo.features) {
    if(!['Polygon','MultiPolygon'].includes(feature.geometry?.type)) continue;
    svgElement('path',{d:polygonPath(feature.geometry),class:'province','data-name':feature.properties.name||feature.properties.NAME_ZH||feature.properties.NAME},$('#province-layer'));
    const center = feature.properties.centroid || feature.properties.center;
    if(state.baseMap==='china'&&center && ![100000,310000,110000,120000,810000,820000].includes(feature.properties.adcode)) {
      const [x,y] = project(center);
      svgElement('text',{x,y,class:'province-label','text-anchor':'middle'},$('#map-labels')).textContent = feature.properties.name.replace(/省|自治区|壮族|回族|维吾尔/g,'');
    }
  }
}
function desiredBaseMap(){return endpoints().some(endpoint=>endpoint.geo?.coordinates&&endpoint.geo.countryCode&&endpoint.geo.countryCode!=='CN')?'world':'china';}
async function updateBaseMap(){
  if(desiredBaseMap()==='world'&&!state.world){
    state.worldPromise ||= fetch('./assets/world-countries.json').then(response=>{if(!response.ok)throw Error('世界底图加载失败');return response.json();}).catch(error=>{state.worldPromise=null;throw error;});
    state.world=await state.worldPromise;
  }
  const mode=desiredBaseMap();if(mode===state.baseMap)return;
  state.baseMap=mode;state.geo=mode==='world'?state.world:state.china;
  drawBaseMap();renderMap();
  $('#map-view .map-attribution').textContent=`底图：${mode==='world'?'Natural Earth':'DataV'} · 位置：IPWHOIS / IPinfo`;
}
function mapEndpoints() {
  return endpoints().filter(endpoint => endpoint.geo?.coordinates).map(endpoint => ({...endpoint,point:project(endpoint.geo.coordinates)}));
}
function setFrame(frame) {
  state.frame = frame;
  $('#route-map').setAttribute('viewBox',`${frame.cx - frame.width / 2} ${frame.cy - frame.height / 2} ${frame.width} ${frame.height}`);
  renderMap();
}
function fitMap() {
  const stage = $('#map-stage'),points = mapEndpoints().map(endpoint => endpoint.point);
  if(!stage.clientWidth || !stage.clientHeight) return;
  const xs = points.map(point => point[0]),ys = points.map(point => point[1]);
  const minX = points.length ? Math.min(...xs) : 320,maxX = points.length ? Math.max(...xs) : 1060;
  const minY = points.length ? Math.min(...ys) : 110,maxY = points.length ? Math.max(...ys) : 590;
  const width = Math.max(240,(maxX - minX) * 1.5 + 200,(maxY - minY + 140) * stage.clientWidth / stage.clientHeight);
  state.baseFrame = {cx:(minX + maxX)/2,cy:(minY + maxY)/2 - 10,width,height:width * stage.clientHeight / stage.clientWidth};
  state.zoom = 1; state.fitted = true;
  setFrame({...state.baseFrame});
}
function zoomMap(factor) {
  if(!state.frame) return;
  const zoom = Math.max(.5,Math.min(3,state.zoom * factor)),ratio = state.zoom / zoom;
  state.zoom = zoom;
  setFrame({...state.frame,width:state.frame.width * ratio,height:state.frame.height * ratio});
}
function renderMap() {
  if(!state.current || !state.frame) return;
  const points = mapEndpoints(),stage = $('#map-stage');
  const unit = state.frame.width / stage.clientWidth;
  document.querySelectorAll('.province-label').forEach(element => element.style.fontSize = `${11 * unit}px`);
  const samePosition = points.length === 2 && Math.hypot(points[0].point[0] - points[1].point[0],points[0].point[1] - points[1].point[1]) < .02;
  $('#map-overlap-note').hidden = !samePosition;
  $('#map-unknown-notice').hidden = points.length === 2;
  $('#map-unknown-notice').textContent = !state.current.destinationIP?`${verdict().label}：没有实际远端 IP，不绘制目的标记和箭头。`:points.length === 1 ? '一个端点位置未知，暂不绘制连接箭头。' : '两个端点位置未知，等待第三方定位结果。';
  $('#route-layer').replaceChildren(); $('#node-layer').replaceChildren();
  const regions = endpoints().map(endpoint => endpoint.geo?.regionLabel).filter(Boolean);
  document.querySelectorAll('.province').forEach(element => element.classList.toggle('highlight',regions.some(region => element.dataset.name.startsWith(region))));
  if(points.length === 2) {
    const [source,destination] = points,[sx,sy] = source.point,[dx,dy] = destination.point;
    let path;
    if(samePosition) path = `M${sx - 5*unit},${sy - 5*unit} C${sx - 100*unit},${sy - 95*unit} ${dx + 110*unit},${dy - 95*unit} ${dx + 12*unit},${dy - 12*unit}`;
    else {const distance = Math.hypot(dx-sx,dy-sy),offset = Math.min(8*unit,distance*.15),ux = (dx-sx)/distance,uy = (dy-sy)/distance;path = `M${sx+ux*offset},${sy+uy*offset} Q${(sx+dx)/2-30*unit},${(sy+dy)/2-20*unit} ${dx-ux*offset},${dy-uy*offset}`;}
    svgElement('path',{d:path,class:'connection-arrow','marker-end':'url(#direction-head)'},$('#route-layer'));
  }
  const labelWidth = stage.clientWidth < 520 ? 134 : 165;
  // Append source last so its inner marker remains clickable when estimates overlap.
  for(const endpoint of [...points].reverse()) {
    const [x,y] = endpoint.point,source = endpoint.role === 'source';
    const group = svgElement('g',{class:`endpoint-marker ${endpoint.role} ${state.selected === endpoint.role ? 'active' : ''}`,transform:`translate(${x},${y}) scale(${unit})`,role:'button',tabindex:0,'data-endpoint':endpoint.role,'aria-label':`${endpoint.label} ${endpoint.ip}，${endpoint.geo.cityLabel || '位置估计'}，查看详情`},$('#node-layer'));
    svgElement('title',{},group).textContent = `${endpoint.label} ${endpoint.ip} · ${location(endpoint.geo)} · ${endpoint.geo.verification.label}`;
    svgElement('circle',{r:samePosition ? source ? 7 : 15 : 8,class:'endpoint-ring'},group);
    if(source || !samePosition) svgElement('circle',{r:3,class:'endpoint-center'},group);
    const labelX = source ? -labelWidth - 18 : 20;
    const labelY = samePosition ? 0 : source ? -20 : 8;
    svgElement('path',{d:`M${source ? -9 : 10},0 L${source ? -17 : 19},${labelY + 20}`,class:'endpoint-label-leader'},group);
    svgElement('rect',{x:labelX,y:labelY,width:labelWidth,height:57,rx:6,class:'endpoint-label-background'},group);
    svgElement('text',{x:labelX+10,y:labelY+16,class:'endpoint-label-role'},group).textContent = `${source ? '源公网 IP' : '目的 IP'} · ${endpoint.geo.cityLabel || '未知'}`;
    svgElement('text',{x:labelX+10,y:labelY+32,class:'endpoint-label-ip'},group).textContent = endpoint.ip;
    svgElement('text',{x:labelX+10,y:labelY+47,class:'endpoint-label-status'},group).textContent = endpoint.geo.verification.label;
    group.addEventListener('keydown',event => {if(event.key === 'Enter' || event.key === ' '){event.preventDefault();selectEndpoint(endpoint.role);}});
  }
}
async function loadData({selectID=null}={}) {
  const response = await fetch('/api/measurements',{cache:'no-store'});
  if(response.status===404){state.data={connections:[]};state.current=null;$('#target-select').innerHTML='<option>暂无验证记录</option>';$('#connection-cards').innerHTML='<p class="website-empty-records">暂无验证记录，请输入网址开始验证。</p>';$('#node-details').textContent='输入网站后查看连接端点。';$('#map-loading').hidden=true;$('#raw-button').disabled=true;$('#export-button').disabled=true;return;}
  if(!response.ok) throw Error('无法读取网站验证记录，请稍后重试。');
  const data = await response.json();
  if(data.view !== 'endpoints' || !data.connections?.length) throw Error('请先运行新版采集器，生成源与目的真实数据');
  const currentID = selectID||state.current?.id;
  state.data = data;
  $('#map-loading').hidden=true;$('#raw-button').disabled=false;$('#export-button').disabled=false;
  selectConnection(data.connections.some(connection => connection.id === currentID) ? currentID : data.connections[0].id);
}
function formError(message){$('#website-form-error').hidden=!message;$('#website-form-error').textContent=message||'';$('#website-url').setAttribute('aria-invalid',message?'true':'false');}
async function measure(input) {
  if(state.collecting) return;
  formError(null);
  state.collecting = true;
  $('#job-progress').hidden = false;
  $('#job-progress').textContent = '正在访问并核对位置…';
  $('#trace-button span').textContent = '访问中…';
  for(const selector of ['#trace-button','#refresh-all','#website-url','#target-select']) $(selector).disabled = true;
  document.querySelectorAll('[data-website-url]').forEach(button=>button.disabled=true);
  try {
    const response = await fetch('/api/measurements',{method:'POST',headers:{'Content-Type':'application/json','X-RouteLens':'local'},body:JSON.stringify(input)});
    const started = await response.json();
    if(!response.ok) throw Error(started.error || '无法开始访问');
    let status;
    do {
      await new Promise(resolve => setTimeout(resolve,300));
      const poll = await fetch('/api/status',{cache:'no-store'});
      status = await poll.json();
      $('#job-progress').textContent = status.message;
    } while(status.running);
    if(status.error) throw Error(status.error);
    await loadData({selectID:input.url?started.targetIDs?.[0]:state.current?.id});
    toast(input.url?`${verdict().label} · ${(state.data.timing.durationMs / 1000).toFixed(2)} 秒`:status.message);
    $('#job-progress').hidden=true;
  } catch(error) {formError(error.message);$('#job-progress').hidden=true;}
  finally {state.collecting = false;$('#trace-button span').textContent = '验证网站';for(const selector of ['#trace-button','#refresh-all','#website-url','#target-select']) $(selector).disabled = false;document.querySelectorAll('[data-website-url]').forEach(button=>button.disabled=false);}
}
function setupEvents() {
  document.addEventListener('click',event => {
    const connection = event.target.closest('[data-connection]');if(connection) selectConnection(connection.dataset.connection);
    const endpoint = event.target.closest('[data-endpoint]');if(endpoint) selectEndpoint(endpoint.dataset.endpoint);
    const view = event.target.closest('[data-view]');if(view) {window.showTrafficMode?.('validation');setView(view.dataset.view);}
  });
  $('#endpoint-body').addEventListener('keydown',event => {if(event.key === 'Enter' || event.key === ' '){const row = event.target.closest('[data-endpoint]');if(row){event.preventDefault();selectEndpoint(row.dataset.endpoint);}}});
  $('#target-select').addEventListener('change',event => selectConnection(event.target.value));
  $('#website-form').addEventListener('submit',event=>{event.preventDefault();const url=$('#website-url').value.trim();if(!url){formError('请输入网站域名或网址。');$('#website-url').focus();return;}measure({url});});
  $('#website-url').addEventListener('input',()=>formError(null));
  document.querySelectorAll('[data-website-url]').forEach(button=>button.addEventListener('click',()=>{$('#website-url').value=button.dataset.websiteUrl;formError(null);$('#website-url').focus();}));
  $('#refresh-all').addEventListener('click',() => measure({id:'all'}));
  for(const selector of ['#about-button','#method-button']) $(selector).addEventListener('click',() => $('#about-dialog').showModal());
  for(const selector of ['#close-dialog','#dialog-done']) $(selector).addEventListener('click',() => $('#about-dialog').close());
  $('#close-raw').addEventListener('click',() => $('#raw-dialog').close());
  $('#raw-button').addEventListener('click',async () => {
    try {const response = await fetch(`/api/raw?id=${encodeURIComponent(state.current.id)}`),data = await response.json();if(!response.ok) throw Error(data.error);$('#raw-description').textContent = `${data.command} · ${time(data.startedAt)}`;$('#raw-text').textContent = data.text;$('#raw-dialog').showModal();}
    catch(error) {toast(error.message);}
  });
  $('#export-button').addEventListener('click',() => {
    if(!state.current) return;
    const payload = {schemaVersion:4,mode:'measured',view:'endpoints',exportedAt:new Date().toISOString(),connection:state.current,timing:state.data.timing,notice:state.data.notice};
    const url = URL.createObjectURL(new Blob([JSON.stringify(payload,null,2)],{type:'application/json'}));
    const link = document.createElement('a');link.href = url;link.download = `routelens-${state.current.id}-endpoints.json`;link.click();setTimeout(() => URL.revokeObjectURL(url),1000);toast('真实端点数据已导出');
  });
  $('#zoom-in').addEventListener('click',() => zoomMap(1.2));$('#zoom-out').addEventListener('click',() => zoomMap(1/1.2));$('#reset-map').addEventListener('click',fitMap);
  let drag = null;
  const map = $('#route-map');
  map.addEventListener('pointerdown',event => {if(event.target.closest('.endpoint-marker') || !state.frame) return;drag = {x:event.clientX,y:event.clientY,frame:{...state.frame}};map.setPointerCapture(event.pointerId);});
  map.addEventListener('pointermove',event => {if(!drag) return;const unit = drag.frame.width / map.getBoundingClientRect().width;setFrame({...drag.frame,cx:drag.frame.cx-(event.clientX-drag.x)*unit,cy:drag.frame.cy-(event.clientY-drag.y)*unit});});
  map.addEventListener('pointerup',() => drag = null);map.addEventListener('pointercancel',() => drag = null);
  map.addEventListener('wheel',event => {event.preventDefault();zoomMap(event.deltaY < 0 ? 1.1 : 1/1.1);},{passive:false});
  new ResizeObserver(() => {if(state.current) fitMap();}).observe($('#map-stage'));
}
async function init() {
  setupEvents();
  try {
    const response = await fetch('./assets/china-provinces.json');if(!response.ok) throw Error('地区底图加载失败');
    state.geo = await response.json();state.china=state.geo;drawBaseMap();await loadData();$('#map-loading').hidden = true;
  } catch(error) {$('#map-loading').textContent = error.message;$('#mode-label').textContent = '等待真实数据';toast(error.message);}
}
init();
window.fitValidationMap = fitMap;
