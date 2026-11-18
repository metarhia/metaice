'use strict';

const net = require('node:net');

const IPV4_SUBNETS = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.168.0.0', 16],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
];
const BLOCKED = (() => {
  const ipv4 = new net.BlockList();
  const ipv6 = new net.BlockList();
  for (let i = 0; i < IPV4_SUBNETS.length; i++) {
    const subnet = IPV4_SUBNETS[i];
    ipv4.addSubnet(subnet[0], subnet[1], 'ipv4');
  }
  ipv6.addAddress('::', 'ipv6');
  ipv6.addAddress('::1', 'ipv6');
  ipv6.addSubnet('fc00::', 7, 'ipv6');
  ipv6.addSubnet('fe80::', 10, 'ipv6');
  ipv6.addSubnet('ff00::', 8, 'ipv6');
  ipv6.addSubnet('::ffff:0:0', 96, 'ipv6');
  return { ipv4, ipv6 };
})();

const isPrivate = (address) => {
  const family = net.isIP(address);
  if (!family) return true;
  const type = family === 4 ? 'ipv4' : 'ipv6';
  return BLOCKED[type].check(address, type);
};

module.exports = { isPrivate };
