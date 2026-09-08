'use strict';
function leftPad(str, len, ch) {
  str = String(str);
  ch = ch || ' ';
  while (str.length < len) str = ch + str;
  return str;
}
module.exports = leftPad;
