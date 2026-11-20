'use strict';

// Synthetic summaries; this exercise neither reads nor emits network packets.
const approvedRouters = [
  { vlan: 40, port: 'edge-uplink-1', source: 'fe80::1', mac: '02:00:00:00:40:01' },
  { vlan: 40, port: 'edge-uplink-2', source: 'fe80::2', mac: '02:00:00:00:40:02' },
];
const baseline = {
  ...approvedRouters[0], code: 0, ipv6HopLimit: 255,
  checksumVerified: true, structureValid: true,
  routerLifetime: 1800, prefix: '2001:db8:40::/64',
  prefixPreferred: 1800, prefixValid: 3600,
  dns: '2001:db8:40::53', dnsLifetime: 1200,
};
const cases = [
  ['LAB-01', {}, 'expected_advertisement'],
  ['LAB-02', approvedRouters[1], 'expected_advertisement'],
  ['LAB-03', { port: 'desk-07' }, 'unexpected_ingress_or_router'],
  ['LAB-04', { ipv6HopLimit: 64 }, 'invalid_header'],
  ['LAB-05', { routerLifetime: 0 }, 'default_router_withdrawal'],
  ['LAB-06', { prefix: '2001:db8:41::/64' }, 'unexpected_prefix'],
  ['LAB-07', { dns: '2001:db8:41::53' }, 'unexpected_dns'],
  ['LAB-08', { port: null, checksumVerified: null }, 'insufficient_observation'],
  ['LAB-09', { dnsLifetime: 0 }, 'dns_withdrawal'],
  ['LAB-10', { source: '2001:db8:40::1' }, 'invalid_header'],
];

function classify(observation) {
  // Text is canonical and metadata is pre-checked in this fixed fixture.
  if (observation.code !== 0 || observation.ipv6HopLimit !== 255
      || !/^fe[89ab][0-9a-f]:/i.test(observation.source)
      || observation.checksumVerified === false || observation.structureValid === false) {
    return 'invalid_header';
  }
  if (!observation.port || observation.checksumVerified !== true || observation.structureValid !== true) {
    return 'insufficient_observation';
  }
  const approved = approvedRouters.some(router =>
    ['vlan', 'port', 'source', 'mac'].every(field => router[field] === observation[field])
  );
  if (!approved) return 'unexpected_ingress_or_router';
  if (observation.prefix !== baseline.prefix) return 'unexpected_prefix';
  if (observation.dns !== baseline.dns) return 'unexpected_dns';
  if (observation.routerLifetime === 0) return 'default_router_withdrawal';
  if (observation.dnsLifetime === 0) return 'dns_withdrawal';
  return 'expected_advertisement';
}

let passed = 0;
for (const [id, change, expected] of cases) {
  const actual = classify({ ...baseline, ...change });
  console.log(id + ' ' + actual);
  if (actual === expected) passed++;
}
console.log('Expected results: ' + passed + '/' + cases.length);
if (passed !== cases.length) throw new Error('A case differed from the worksheet.');
