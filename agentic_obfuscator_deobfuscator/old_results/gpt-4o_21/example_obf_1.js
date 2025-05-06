var _0x5049 = [
  "replace",
  "toUpperCase",
  "includes",
  "hello\x20world\x20from\x20javascript",
  "log",
  "Original\x20String:\x20",
  "Reversed\x20String:\x20",
  "Capitalized\x20Words:\x20",
  "Contains\x20\x27world\x27:\x20",
  "world",
  "split",
  "reverse",
  "join",
];
(function (_0x577d27, _0x8ea0aa) {
  var _0x2ef37f = function (_0x287437) {
    while (--_0x287437) {
      _0x577d27["push"](_0x577d27["shift"]());
    }
  };
  _0x2ef37f(++_0x8ea0aa);
})(_0x5049, 0x11b);
var _0x411a = function (_0x3c2c61, _0x24d0a7) {
  _0x3c2c61 = _0x3c2c61 - 0x0;
  var _0x14832d = _0x5049[_0x3c2c61];
  return _0x14832d;
};
function reverseString(_0x54a44e) {
  return _0x54a44e[_0x411a("0x0")]("")[_0x411a("0x1")]()[_0x411a("0x2")]("");
}
function capitalizeWords(_0x17f6e1) {
  return _0x17f6e1[_0x411a("0x3")](/\b\w/g, (_0x429798) =>
    _0x429798[_0x411a("0x4")]()
  );
}
function containsSubstring(_0xd3d241, _0x4a51dc) {
  return _0xd3d241[_0x411a("0x5")](_0x4a51dc);
}
let myString = _0x411a("0x6");
console[_0x411a("0x7")](_0x411a("0x8") + myString);
console[_0x411a("0x7")](_0x411a("0x9") + reverseString(myString));
console[_0x411a("0x7")](_0x411a("0xa") + capitalizeWords(myString));
console[_0x411a("0x7")](
  _0x411a("0xb") + containsSubstring(myString, _0x411a("0xc"))
);
