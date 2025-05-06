var _0x1473 = [
  "log",
  "Original\x20String:\x20",
  "Reversed\x20String:\x20",
  "Capitalized\x20Words:\x20",
  "Contains\x20\x27world\x27:\x20",
  "world",
  "split",
  "reverse",
  "join",
  "replace",
  "toUpperCase",
  "includes",
  "hello\x20world\x20from\x20javascript",
];
(function (_0x569cc3, _0x52dd1c) {
  var _0x1dabe0 = function (_0x28b6d7) {
    while (--_0x28b6d7) {
      _0x569cc3["push"](_0x569cc3["shift"]());
    }
  };
  _0x1dabe0(++_0x52dd1c);
})(_0x1473, 0x1c0);
var _0x4c38 = function (_0x555ab3, _0x10c37e) {
  _0x555ab3 = _0x555ab3 - 0x0;
  var _0x239e86 = _0x1473[_0x555ab3];
  return _0x239e86;
};
function reverseString(_0x1fdbd4) {
  return _0x1fdbd4[_0x4c38("0x0")]("")[_0x4c38("0x1")]()[_0x4c38("0x2")]("");
}
function capitalizeWords(_0x175a57) {
  return _0x175a57[_0x4c38("0x3")](/\b\w/g, (_0x53a385) =>
    _0x53a385[_0x4c38("0x4")]()
  );
}
function containsSubstring(_0x2602e9, _0x17ff0a) {
  return _0x2602e9[_0x4c38("0x5")](_0x17ff0a);
}
let myString = _0x4c38("0x6");
console[_0x4c38("0x7")](_0x4c38("0x8") + myString);
console[_0x4c38("0x7")](_0x4c38("0x9") + reverseString(myString));
console[_0x4c38("0x7")](_0x4c38("0xa") + capitalizeWords(myString));
console[_0x4c38("0x7")](
  _0x4c38("0xb") + containsSubstring(myString, _0x4c38("0xc"))
);
