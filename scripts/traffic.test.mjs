import test from 'node:test';
import assert from 'node:assert/strict';
import { aggregateRegions } from './traffic.mjs';
import { isPublicIP, getCachedIP, getLocationStats } from './ip-locations.mjs';

test('地区聚合保留未知流量，按原始帧字节守恒',()=>{
  const geo={countryCode:'CN',country:'中国',regionLabel:'北京',coordinates:[116,40]};
  const groups=aggregateRegions([{ip:'a',packets:3,bytes:300,geo},{ip:'b',packets:5,bytes:1000,geo},{ip:'192.168.1.1',packets:2,bytes:200}],1,100);
  assert.equal(groups.reduce((sum,item)=>sum+item.packets,0),11);
  assert.equal(groups.reduce((sum,item)=>sum+item.bytes,0),1600);
  assert.equal(groups[0].ipCount,2);assert.equal(groups[0].representativeIP,'b');
  assert.equal(groups.find(group=>group.key==='unknown').packets,3);
});
test('IPv6 可定位公网，保留地址不外发，缓存检查不产生网络请求',async()=>{
  for(const ip of ['2001:4860::8888','2606:4700::1111'])assert.equal(isPublicIP(ip),true);
  for(const ip of ['::1','fe80::1','fd00::1','2001:db8::1','3fff::1'])assert.equal(isPublicIP(ip),false);
  const before=getLocationStats().networkRequests;
  assert.equal(await getCachedIP('2001:db8::1'),null);
  assert.equal(getLocationStats().networkRequests,before);
});
