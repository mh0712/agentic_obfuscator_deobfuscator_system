
function _0x2801(min, max) {
  return Math['floor'](Math['random']() * (max - min + 1)) + min;
}

function _0xcd4f(number) {
  return number % 2 === 0;
}

function _0x5b83() {
  const _0x2b7e = _0x2801(1, 100);
  console['log']('Generated\x20number:', _0x2b7e);

  if (_0xcd4f(_0x2b7e)) {
    console['log']('The\x20number\x20is\x20even.');
  } else {
    console['log']('The\x20number\x20is\x20odd.');
  }
}

_0x5b83();