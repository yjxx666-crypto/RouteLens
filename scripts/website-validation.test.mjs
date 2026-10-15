import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import { mkdtemp,readFile,access,writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { normalizeWebsite, classifyWebsiteResult, probeWebsite } from './website-validation.mjs';
import { execute, targets, projectRoot } from './measurements.mjs';

test('接受自定义域名、路径、端口、IDN，网址规范化并稳定去重',()=>{
  assert.equal(normalizeWebsite('www.baidu.com',targets).id,'baidu');
  const target=normalizeWebsite('HTTP://Example.COM:8080/a?x=1#section');
  assert.equal(target.url,'http://example.com:8080/a?x=1');assert.equal(target.port,8080);assert.equal(target.protocol,'HTTP');
  assert.equal(target.id,normalizeWebsite('http://example.com:8080/a?x=1').id);
  assert.match(normalizeWebsite('例子.测试').domain,/^xn--/);
  assert.equal(normalizeWebsite('https://[2606:4700::1111]/').protocol,'HTTPS');
});
test('拒绝非网站协议、凭据、坏域名及控制字符',()=>{
  for(const input of ['', 'file:///C:/Windows/win.ini','ftp://example.com','javascript:alert(1)','https://user:secret@example.com','example com','https://bad_.example','https://a..com','https://-bad.com','https://example.com:99999','https://exa\nmple.com/'])assert.throws(()=>normalizeWebsite(input),input);
});
test('HTTP 错误属于已响应，超时即使已有 HTTP 200 也不是访问成功',()=>{
  assert.equal(classifyWebsiteResult({exitCode:0,httpCode:404,remoteIP:'127.0.0.1'}).status,'http-error');
  const partial=classifyWebsiteResult({exitCode:28,httpCode:200,remoteIP:'127.0.0.1',connectSeconds:.01,tlsRequired:false});
  assert.equal(partial.status,'failed');assert.equal(partial.kind,'response-timeout');
  assert.equal(classifyWebsiteResult({exitCode:28,connectSeconds:0}).kind,'connect-timeout');
  assert.equal(classifyWebsiteResult({exitCode:60,remoteIP:'127.0.0.1'}).kind,'certificate');
});
test('真实 curl 验证成功、跳转、404、断连、超时、循环跳转与大小上限',{skip:process.platform!=='win32'},async t=>{
  const sockets=new Set();
  const server=http.createServer((req,res)=>{
    if(req.url==='/ok'){res.end('actual test response');return;}
    if(req.url==='/redirect'){res.writeHead(302,{Location:'/ok'});res.end();return;}
    if(req.url==='/loop'){res.writeHead(302,{Location:'/loop'});res.end();return;}
    if(req.url==='/slow')return;
    if(req.url==='/partial'){res.writeHead(200);res.write('partial');return;}
    if(req.url==='/empty'){req.socket.destroy();return;}
    if(req.url==='/large'){res.writeHead(200,{'Content-Length':2048});res.end(Buffer.alloc(2048));return;}
    res.writeHead(404);res.end('missing');
  });
  server.on('connection',socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));});
  await new Promise(resolvePromise=>server.listen(0,'127.0.0.1',resolvePromise));
  t.after(async()=>{for(const socket of sockets)socket.destroy();await new Promise(resolvePromise=>server.close(resolvePromise));});
  const base=`http://127.0.0.1:${server.address().port}`;
  const probe=path=>probeWebsite(normalizeWebsite(base+path),{execute,connectTimeout:.4,maxTime:.8,maxBytes:1024});
  const ok=await probe('/ok');assert.equal(ok.validation.status,'success');assert.equal(ok.http.remoteIP,'127.0.0.1');assert.equal(ok.http.tlsRequired,false);
  const redirected=await probe('/redirect');assert.equal(redirected.http.redirectCount,1);assert.equal(redirected.http.effectiveURL,base+'/ok');
  assert.equal((await probe('/404')).validation.status,'http-error');
  assert.equal((await probe('/empty')).validation.kind,'empty-response');
  assert.equal((await probe('/slow')).validation.kind,'response-timeout');
  const partial=await probe('/partial');assert.equal(partial.http.httpCode,200);assert.equal(partial.validation.status,'failed');
  assert.equal((await probe('/loop')).validation.kind,'redirect');
  assert.equal((await probe('/large')).http.exitCode,63);
});
test('真实 DNS 失败与拒绝连接保留失败结果和空远端 IP',{skip:process.platform!=='win32'},async()=>{
  const dns=await probeWebsite(normalizeWebsite('https://routelens-does-not-exist.invalid/'),{execute,connectTimeout:2,maxTime:3});
  assert.equal(dns.validation.kind,'dns');assert.equal(dns.http.remoteIP,null);
  const server=http.createServer();await new Promise(resolvePromise=>server.listen(0,'127.0.0.1',resolvePromise));const port=server.address().port;await new Promise(resolvePromise=>server.close(resolvePromise));
  const refused=await probeWebsite(normalizeWebsite(`http://127.0.0.1:${port}/`),{execute,connectTimeout:3,maxTime:4});
  assert.equal(refused.validation.kind,'connect');assert.equal(refused.http.remoteIP,null);
});
test('真实自签名 TLS 证书被拒绝，不绕过校验',{skip:process.platform!=='win32'},async t=>{
  const openssl='D:/apps/miniconda/Library/bin/openssl.exe';
  try{await access(openssl);}catch{t.skip('测试证书生成工具不可用');return;}
  const directory=await mkdtemp(resolve(projectRoot,'.local/website-tls-test-'));
  const key=resolve(directory,'key.pem'),cert=resolve(directory,'cert.pem'),config=resolve(directory,'openssl.cnf');
  await writeFile(config,'[req]\ndistinguished_name=dn\n[dn]\n');
  const generated=await execute(openssl,['req','-config',config,'-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],10000);
  assert.equal(generated.exitCode,0,generated.stderr);
  const server=https.createServer({key:await readFile(key),cert:await readFile(cert)},(req,res)=>res.end('TLS test'));
  await new Promise(resolvePromise=>server.listen(0,'127.0.0.1',resolvePromise));
  t.after(()=>new Promise(resolvePromise=>{server.closeAllConnections();server.close(resolvePromise);}));
  const result=await probeWebsite(normalizeWebsite(`https://localhost:${server.address().port}/`),{execute,connectTimeout:2,maxTime:3});
  assert.equal(result.validation.kind,'certificate',result.http.error);assert.equal(result.validation.status,'failed');
});
