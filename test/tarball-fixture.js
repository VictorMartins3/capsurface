'use strict';

const crypto = require('crypto');

function header(name, size, type = '0', link = '') {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100); h.write('0000600\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
  h.write(size.toString(8).padStart(11, '0') + '\0', 124);
  h.write('00000000000\0', 136); h.fill(32, 148, 156); h.write(type, 156); h.write(link, 157, 100);
  h.write('ustar\0', 257); h.write('00', 263);
  const sum = h.reduce((total, byte) => total + byte, 0);
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  return h;
}
function tar(entries, end = Buffer.alloc(1024)) {
  return Buffer.concat([...entries.flatMap((entry) => {
    const body = Buffer.from(entry.body || '');
    return [header(entry.name, body.length, entry.type, entry.link), body, Buffer.alloc((512 - body.length % 512) % 512)];
  }), end]);
}
function integrity(data, algorithm = 'sha512') { return `${algorithm}-${crypto.createHash(algorithm).update(data).digest('base64')}`; }
function paxRecord(key, value) {
  const body = `${key}=${value}\n`;
  let length = Buffer.byteLength(body) + 2;
  while (length !== Buffer.byteLength(body) + String(length).length + 1) length = Buffer.byteLength(body) + String(length).length + 1;
  return `${length} ${body}`;
}

module.exports = { header, tar, integrity, paxRecord };
