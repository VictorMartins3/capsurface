'use strict';

const PROCESS_METHODS = new Set(['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork']);

// Classify the API's launch mode, not what the selected executable will do.
// Options held in variables or assembled dynamically remain unresolved.
function processOperation(method, args, unwrap) {
  if (method === 'exec' || method === 'execSync') return 'execShell';
  if (method === 'fork') return 'execDirect';
  if (args.some((arg) => arg.type === 'SpreadElement')) return 'execUnresolved';
  const rest = args.slice(1).map(unwrap);
  if (rest[0] && rest[0].type === 'ArrayExpression') rest.shift();
  if (method === 'execFile' && rest.length && /^(?:FunctionExpression|ArrowFunctionExpression)$/.test(rest[rest.length - 1].type)) rest.pop();
  if (!rest.length) return 'execDirect';
  if (rest.length !== 1 || rest[0].type !== 'ObjectExpression') return 'execUnresolved';
  let result = 'execDirect';
  for (const prop of rest[0].properties) {
    if (prop.type !== 'Property' || prop.computed || prop.kind !== 'init' || prop.method) return 'execUnresolved';
    const name = prop.key.name || prop.key.value;
    if (name === '__proto__') return 'execUnresolved';
    if (name !== 'shell') continue;
    const value = unwrap(prop.value);
    if (value.type !== 'Literal') result = 'execUnresolved';
    else if (value.value === true || (typeof value.value === 'string' && value.value.length)) result = 'execShell';
    else if (value.value === false || value.value === '') result = 'execDirect';
    else result = 'execUnresolved';
  }
  return result;
}

module.exports = { PROCESS_METHODS, processOperation };
