import test from 'node:test';
import assert from 'node:assert/strict';
import { parseTracert, privateAddress } from './measurements.mjs';
test('preserves mixed Chinese/English timings, upper bounds and timeout samples',()=>{
  const hops=parseTracert('  1     1 ms     *        2 ms  192.168.1.1\r\n  2    <1 毫秒   <1 毫秒   <1 毫秒 10.28.1.38\r\n  3     *        *        *     请求超时。\r\n  4    10 ms    12 ms    11 ms  182.61.200.110','182.61.200.110');
  assert.deepEqual(hops.map(h=>h.hop),[1,2,3,4]);assert.equal(hops[1].rttText,'<1 ms');assert.equal(hops[1].rtt,null);assert.deepEqual(hops[1].samples.map(s=>s.kind),['upper-bound','upper-bound','upper-bound']);assert.equal(hops[2].status,'timeout');assert.equal(hops[2].ip,null);assert.equal(hops[2].coordinates,null);assert.equal(hops[3].rtt,11);
});
test('retains a responding hop even when timing unit is unrecognized',()=>{const hops=parseTracert('  1     1 ticks     2 ticks     3 ticks  10.0.0.1','182.61.200.110');assert.equal(hops.length,1);assert.equal(hops[0].ip,'10.0.0.1');assert.equal(hops[0].rtt,null);});
test('identifies private, carrier NAT and benchmark/fake-DNS addresses',()=>{for(const ip of ['10.28.1.38','192.168.112.254','172.16.0.1','100.64.0.1','198.18.0.1'])assert.equal(privateAddress(ip),true);assert.equal(privateAddress('182.61.200.110'),false);});
