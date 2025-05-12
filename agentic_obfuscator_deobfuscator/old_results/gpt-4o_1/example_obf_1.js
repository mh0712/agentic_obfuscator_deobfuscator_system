// Function outlining + variable renaming
function _a(a, b) {
  return Math.floor(Math.random() * _b(a, b)) + a;
}

function _b(min, max) {
  return max - min + 1;
}

function _c(num) {
  return num % 2 === 0;
}

function _d() {
  const _x = _a(1, 100);

  // Opaque predicate (always true)
  if ((99 ^ 99) === 0) {
    _e("Number generated:", _x);
  }

  if (_c(_x)) {
    _e("It's even.");
  } else {
    _e("It's odd.");
  }
}

// Console alias
function _e(msg, val) {
  if (true) {
    console.log(msg, val);
  }
}

// String encoding (Base64)
function _f(str) {
  return atob(str);
}

_d();

// Dead code (never runs)
function _unused() {
  const junk = Math.pow(5, 2) && false ? "This is junk" : "Still junk";
  if (false || 0 > 1) {
    console.log(junk);
  }
}

console.log(_f("VGhpcyBpcyBhIGhpZGRlbiBtZXNzYWdlIQ==")); // "This is a hidden message!"
