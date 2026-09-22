'use strict';

const METHODS = {
  http: { request: 'networkRequest', get: 'networkRequest', createServer: 'networkServer' },
  https: { request: 'networkRequest', get: 'networkRequest', createServer: 'networkServer' },
  http2: { connect: 'networkConnect', createServer: 'networkServer', createSecureServer: 'networkServer' },
  net: { connect: 'networkConnect', createConnection: 'networkConnect', createServer: 'networkServer' },
  tls: { connect: 'networkConnect', createServer: 'networkServer' },
  dgram: { createSocket: 'networkSocket' },
};
const DNS = ['lookup', 'lookupService', 'resolve', 'resolve4', 'resolve6', 'resolveAny', 'resolveCaa',
  'resolveCname', 'resolveMx', 'resolveNaptr', 'resolveNs', 'resolvePtr', 'resolveSoa', 'resolveSrv',
  'resolveTxt', 'reverse'];
METHODS.dns = Object.fromEntries(DNS.map((method) => [method, 'networkDns']));
METHODS['dns/promises'] = METHODS.dns;

function networkModule(specifier) {
  const name = specifier.replace(/^node:/, '');
  return Object.prototype.hasOwnProperty.call(METHODS, name) ? { kind: 'network-module', module: name } : null;
}
function networkMethod(namespace, method) {
  const methods = METHODS[namespace.module];
  if (!Object.prototype.hasOwnProperty.call(methods, method)) return null;
  return { kind: 'network-method', category: methods[method], rule: `node:${namespace.module}.${method}` };
}
module.exports = { networkModule, networkMethod };
