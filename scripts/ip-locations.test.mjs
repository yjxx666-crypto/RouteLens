import test from 'node:test';
import assert from 'node:assert/strict';
import {compareLocations,isPublicIPv4,lookupIP,getLocationStats} from './ip-locations.mjs';
const source=(provider,region,city,countryCode='CN')=>({provider,ok:true,location:{countryCode,region,city,coordinates:[117.1,39.1]}});
test('normalizes municipality aliases instead of reporting a false disagreement',()=>{
  assert.equal(compareLocations([source('IPWHOIS','Tianjin Shi','Tianjin'),source('IPinfo','Tianjin','Tianjin')]).status,'consistent');
  assert.equal(compareLocations([source('IPWHOIS','北京市','北京'),source('IPinfo','Beijing','Beijing')]).status,'consistent');
});
test('preserves real city differences, single sources and total failures',()=>{
  assert.equal(compareLocations([source('IPWHOIS','Guangdong','Guangzhou'),source('IPinfo','Guangdong','Shenzhen')]).status,'conflicting');
  assert.equal(compareLocations([source('IPWHOIS','Beijing','Beijing'),{provider:'IPinfo',ok:false}]).status,'single-source');
  assert.equal(compareLocations([{provider:'IPWHOIS',ok:false}]).status,'unavailable');
});
test('never sends private or documentation IPs to geolocation providers',async()=>{
  const before=getLocationStats().networkRequests;
  for(const ip of ['192.168.112.44','10.28.1.38','100.64.0.1','198.18.0.1','203.0.113.80','127.0.0.1','not-an-ip']){assert.equal(isPublicIPv4(ip),false);assert.equal((await lookupIP(ip)).coordinates,null);}
  assert.equal(getLocationStats().networkRequests,before);assert.equal(isPublicIPv4('182.61.200.108'),true);
});
