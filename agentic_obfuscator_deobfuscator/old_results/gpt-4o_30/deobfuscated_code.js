var strings = [
  "TkFve=,", "HAZL=,", "UkifoU0=,", "WnRJKg=", "YaFsA==", "YW##WAUg", 
  "ZJdkb2hpZWRhdGE=", "YXVtk3RFak5qTTBoT1ZZNAM=", "VGFKUw=,", "VTFIJ=", 
  "YFxWNFakbpZG9n", 
];
(function (array, value) {
  var rotate = function (count) {
    while (--count) {
      array.push(array.shift());
    }
  };
  rotate(++value);
})(strings, 271);

var decodeString = function (index, offset) {
  index = index - 0x0;
  var str = strings[index];
  if (decodeString.cached === undefined) {
    (function () {
      var global = (typeof globalThis !== "undefined" ? globalThis : self);
      var base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
      global.atob || (global.atob = function (input) {
        var str = String(input).replace(/=+$/, '');
        for (
          var bc = 0, bs, buffer, idx = 0, output = '';
          buffer = str.charAt(idx++);
          ~buffer && (bs = bc % 4 ? bs * 64 + buffer : buffer, bc++ % 4) ? 
          output += String.fromCharCode(255 & bs >> (-2 * bc & 6)) : 0
        ) {
          buffer = base64Alphabet.indexOf(buffer);
        }
        return output;
      });
    })();
    decodeString.decodeBase64 = function (string) {
      var base64Dec = atob(string);
      var decodedURI = [];
      for (var i = 0, length = base64Dec.length; i < length; i++) {
        decodedURI += '%' + ('00' + base64Dec.charCodeAt(i).toString(16)).slice(-2);
      }
      return decodeURIComponent(decodedURI);
    };
    decodeString.cache = {};
    decodeString.cached = true;
  }
  var cachedValue = decodeString.cache[index];
  if (cachedValue === undefined) {
    str = decodeString.decodeBase64(str);
    decodeString.cache[index] = str;
  } else {
    str = cachedValue;
  }
  return str;
};

const item1 = new Item(decodeString(0), 1000);
const item2 = new Item(decodeString(1), 500);
const collection = new Collection();
item1.addAmount(200);
item1.subtractAmount(150);
const logInterval = setInterval(function () {
  logItemData();
}, 4000);
item2.addAmount(300);
item1.transferAmount(500, item2);
collection.add(decodeString(2));
collection.add(decodeString(3));
collection.add(decodeString(4));
collection.add(decodeString(5));
item1.showData();
item2.showData();
collection.show();

function logItemData(loop) {
  function checkType(input) {
    if (typeof input === 'number') {
      executeCode(() => {});
    } else {
      if (("" + input / input).length !== decodeString(6).length || input % 20 === 0) {
        (function () {
          return true;
        })
          .toString(decodeString(7) + decodeString(8))
          .call(decodeString(9));
      } else {
        (function () {
          return false;
        })
          .toString(decodeString(7) + decodeString(8))
          .call(decodeString(10));
      }
    }
    checkType(++loop);
  }
  try {
    if (loop) {
      return checkType;
    } else {
      checkType(0);
    }
  } catch (e) {}
}

/* Definitions of Item and Collection classes should remain unchanged now. */
