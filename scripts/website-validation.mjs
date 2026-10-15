import { createHash } from 'node:crypto';
import { domainToASCII } from 'node:url';
import { isIP } from 'node:net';

export function normalizeWebsite(input, presets=[]) {
  if(typeof input!=='string'||!input.trim())throw Error('请输入网站域名或网址。');
  const value=input.trim();
  if(value.length>2048)throw Error('网址不能超过 2048 个字符。');
  if(/[\s\u0000-\u001f\u007f\\]/u.test(value))throw Error('网址不能包含空白、控制字符或反斜杠。');
  const explicit=/^[a-z][a-z\d+.-]*:\/\//i.test(value);
  if(!explicit&&/^[a-z][a-z\d+.-]*:/i.test(value)&&!/^([^/?#]+):\d+(?:[/?#]|$)/.test(value)&&!value.startsWith('['))throw Error('仅支持 HTTP 或 HTTPS 网站。');
  let parsed;
  try{parsed=new URL(explicit?value:value.startsWith('//')?`https:${value}`:`https://${value}`);}catch{throw Error('网址格式无效，请输入域名或完整的 HTTP/HTTPS 地址。');}
  if(!['http:','https:'].includes(parsed.protocol))throw Error('仅支持 HTTP 或 HTTPS 网站。');
  if(parsed.username||parsed.password)throw Error('网址不能包含用户名或密码。');
  const hostname=parsed.hostname.replace(/^\[|\]$/g,'');
  if(!hostname)throw Error('网址缺少域名或 IP 地址。');
  if(!isIP(hostname)){
    const ascii=domainToASCII(hostname).replace(/\.$/,'');
    if(!ascii||ascii.length>253||ascii.split('.').some(label=>!label||label.length>63||!/^([a-z\d]|[a-z\d][a-z\d-]*[a-z\d])$/i.test(label)))throw Error('域名格式无效，请检查字符和拼写。');
  }
  parsed.hash='';
  const url=parsed.href;
  const preset=presets.find(target=>url===(target.url||`https://${target.domain}/`));
  return {id:preset?.id||`custom-${createHash('sha256').update(url).digest('hex').slice(0,20)}`,name:preset?.name||parsed.host,avatar:preset?.avatar||'网',domain:parsed.hostname,url,protocol:parsed.protocol.slice(0,-1).toUpperCase(),port:Number(parsed.port)||(parsed.protocol==='https:'?443:80),custom:!preset};
}

export function classifyWebsiteResult(http) {
  const code=http.exitCode,connected=!!http.remoteIP||http.connectSeconds>0;
  const base={connected,httpStatus:http.httpCode||null,errorCode:code,rawError:http.error||null};
  const failed=(kind,label,detail,hint)=>({...base,status:'failed',kind,label,detail,hint});
  if(code!==0){
    if(code===6)return failed('dns','域名解析失败','本机 DNS 未能解析该域名，本次没有建立到目标网站的连接。','请检查域名拼写、DNS 设置与网络连接，然后重试。');
    if(code===5)return failed('proxy-dns','代理解析失败','本机无法解析配置的代理服务器。','请检查代理地址和网络配置。');
    if(code===7)return failed('connect','连接失败','无法建立 TCP 连接，目标端口可能拒绝连接或网络不可达。','请检查协议、端口、网站可用性和网络连接。');
    if(code===28||http.killed){
      if(/resolv/i.test(http.error||''))return failed('dns-timeout','域名解析超时','DNS 解析未在时间限制内完成。','请检查 DNS 服务与网络后重试。');
      if(!connected&&!http.connectSeconds)return failed('connect-timeout','连接超时','未能在时间限制内建立到目标的连接。','目标可能不可达，请稍后重试或检查网络。');
      if(http.tlsRequired&&!http.tlsSeconds&&!http.httpCode)return failed('tls-timeout','TLS 协商超时','已连接远端，但 TLS 协商未及时完成。','请检查 HTTPS 服务与网络后重试。');
      return failed('response-timeout','响应超时','请求或响应未在时间限制内完成；已经收到的数据保留在凭据中。','网站响应较慢，请稍后重试。');
    }
    if([51,60].includes(code))return failed('certificate','证书校验失败','HTTPS 证书未通过本机信任校验，访问没有完成。','请检查证书有效期、域名匹配与本机时间。');
    if(code===35)return failed('tls','TLS 协商失败','与网站的 HTTPS 服务未能完成 TLS 协商。','请检查网站 HTTPS 服务或网络拦截情况。');
    if(code===47)return failed('redirect','网站跳转过多','请求超过 5 次跳转限制，可能存在循环跳转。','请检查网址，或直接输入最终页面地址。');
    if(code===52)return failed('empty-response','网站没有响应','远端连接没有返回可解析的 HTTP 响应。','请确认该端口提供 HTTP/HTTPS 服务。');
    if(code===63)return failed('response-limit','响应大小超限','已连接网站，但响应超过网站验证的 8 MB 读取上限。','可改为验证网站首页或较小的页面；实际远端 IP 仍保留。');
    if([18,55,56,92].includes(code))return failed('transfer','连接中断','请求发送或响应读取过程中断，收到的数据可能不完整。','请稍后重试，并检查网络和网站状态。');
    if(code==='ENOENT')return failed('runtime','验证工具不可用','本机没有找到 curl.exe。','请检查本机 curl 安装与 PATH。');
    return failed('request','访问失败','本次请求未完成，请查看原始错误信息。','请核对网址和网络后重试。');
  }
  if(!http.httpCode)return failed('no-http','未收到 HTTP 响应','请求没有返回可用的 HTTP 状态码。','请确认网站协议和端口。');
  if(http.httpCode>=400){
    const meanings={401:'网站要求身份认证。',403:'网站拒绝了本次访问。',404:'请求的页面不存在。',429:'网站限制了请求频率。'};
    return {...base,status:'http-error',kind:'http',label:`HTTP ${http.httpCode}`,detail:`网站已返回 HTTP 响应，${meanings[http.httpCode]||(http.httpCode>=500?'服务器报告错误。':'请求未被正常处理。')}`,hint:'网络连接与 HTTP 状态分开判断；可检查页面路径或稍后重试。'};
  }
  return {...base,status:'success',kind:'ok',label:'访问成功',detail:`网站已返回 HTTP ${http.httpCode}。`,hint:http.redirectCount?`已跟随 ${http.redirectCount} 次跳转，定位采用最终连接的远端 IP。`:'目的 IP 取自本次真实连接。'};
}

export async function probeWebsite(target,{execute,connectTimeout=5,maxTime=15,maxBytes=8*1024*1024}={}) {
  const format=JSON.stringify({httpCode:'%{http_code}',remoteIP:'%{remote_ip}',remotePort:'%{remote_port}',localIP:'%{local_ip}',localPort:'%{local_port}',dnsSeconds:'%{time_namelookup}',connectSeconds:'%{time_connect}',tlsSeconds:'%{time_appconnect}',totalSeconds:'%{time_total}',downloadBytes:'%{size_download}',tlsVerifyResult:'%{ssl_verify_result}',effectiveURL:'%{url_effective}',redirectCount:'%{num_redirects}',proxyUsed:'%{proxy_used}'});
  const args=['--disable','--silent','--show-error','--output','NUL','--connect-timeout',String(connectTimeout),'--max-time',String(maxTime),'--max-filesize',String(maxBytes),'--location','--max-redirs','5','--proto','=http,https','--proto-redir','=http,https','--user-agent','Mozilla/5.0 RouteLensLocalValidation/2.0','--write-out',format,'--url',target.url];
  const curl=await execute('curl.exe',args,(maxTime+3)*1000);
  let http={};try{http=JSON.parse(curl.stdout);}catch{}
  for(const key of ['httpCode','remotePort','localPort','dnsSeconds','connectSeconds','tlsSeconds','totalSeconds','downloadBytes','tlsVerifyResult','redirectCount','proxyUsed'])http[key]=http[key]===undefined?null:Number(http[key]);
  http={...http,remoteIP:http.remoteIP||null,localIP:http.localIP||null,tlsRequired:(http.effectiveURL||target.url).startsWith('https:'),exitCode:curl.exitCode,error:curl.stderr.trim()||null,killed:curl.killed,startedAt:curl.startedAt,finishedAt:curl.finishedAt,processID:curl.pid,command:`curl.exe (GET ${target.url}, TLS 校验开启, 最多 5 次跳转)`};
  return {http,validation:classifyWebsiteResult(http)};
}
