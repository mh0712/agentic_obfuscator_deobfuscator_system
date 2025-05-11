// Define an array with encoded strings
var encodedStrings = [
  "XCtxKyAqKD86VE0tdXoweE4xOFMvMGNpSkssMWcnKSsnICtpQCk8Kw",
  "aW5pdDA=",
  "dGVzdA==",
  "Y2FuJ3QgZm9yYmVlIHRoaXMgdGVzdA==",
  "aHlwZXJsaW5r",
  "REVSbXVEVg=",
  "YWxleGVeZ2FmYW5p",
  "bG5r",
  "YlN0cmVuZw==",
  "IH0KZnVuY3Rpb24gaWFiaW4=",
  "LiB3ZSBkK0VsZGUgd2l0aA==",
  "cmVxdWVzdA==",
  "YERlY2VkIG9yIG5vdCBnaXZpbmcgdG8gbW9kaWZ5",
  "ZTAwUGhhcmFtJ2V0ZXIgYXJhd3JhWSBhKQ==",
  "dXJnJGNvZGluZyBmdW5jdGlvbjogcmVmZXJlbmNl",
  "ZGF0YTM=",
  "dmVyc2l0eSBzdGF0ZW1lbnQgdGVzdGluZw==",
  "ZW5jb3BzJF9nYXSoLlZlYWdlbnRyZQ==",
  "RGVjb3hgJlNvbm5ldGg=",
  "aG9zdCBjb25maWcKUmVmZXJlbmNlR3JlLg==",
  "WXdodGVYBG9iZQ==",
  "UFdhdWMoc2ltaWxhcju9ZY==",
  "Z2VuZXJpYXRlIGFuIGVobmdtYE5eeHMoVE1fYA==",
  "UE4lZWkgZmluYWwieSBidWc=",
  "bmFycmF0aXZl",
  "c3lzdGVtIGNvZGluZyB2aWV3IG90aGVyIGZ1bmN0aW9u",
  "c3RhdGVtZW50IHRlc3Q=",
  "c3VwcHlvbmUgZ2FudGEgY29kaW5nCg==",
  "QGV4cG9ydCBkaW5lZCBtb2R1bGVhcH=IA==",
  "UkdoeXBlKQ==",
  "c2NyaXB0IG1lbnRpAkk9",
  "cHJvdmlkZWQgZGVmIGNpJ21wbGV0ZSA0nAE=",
  "UkBlbmF5IHRoZXNlIGZ1bmN0ZG9kIFRUV0Q9CiBGZW51bQ==",
  "aDdod3RydElvYSBhbnRSdXJ0aGF0ZQ==",
  "UExldW5nO2VoLmdhb0FsR0FxIDw/IGlm",
  "RXNoP2V0eChmYXlsZWFyZXN4IBt8bHVT&p==",
  "a2hpcEkNcG9zdFJpcmnkgVRTQXNg==",
  "QmlsbC5jYSBjb25zdCB0aEyQ2hlcg==",
  "ZW1wbG9jY3VxaAA=",
  "YXkgY29waWVkIHN0YXRlbWVudCB0b29s",
  "WW91IGZsaWxsIHRoaXMgcHx4hrAGFyZnY6",
  "LVVSTR52YXJhdGVyZQ==",
  "SW5zdGFuY2UgdFsBCnZhbHVlStrZ2hgC3lebg==",
  "cm9sZShtYW5ha2FlJ2xvbmcgbT8vUg==",
  "VGhlcmUgKg==",
  "aXN0YXQ=",
  "Tk91dGVyZGVmIHh5/sdm",
  "TWFrZXJ6IHdpZWApbi9lPD8=",
  "b3BlcmF0b3IgY29sbGVjdGlzbiBhISBGb2xsb3ccG==",
  "Y29udGFpZyB3ZXIgb2ZmZXJlZA==",
  "Y3JlYXRlYWQgbG9naW4gZXhoYUFpcmU=", 
  "UHVibGlzaCBYSFpHQG1vZGlmACBlbmRzdHkq"
];

// Function to iterate and decode base64 encoded strings 
function decodeBase64Strings() {
  var decodedArray = [];
  encodedStrings.forEach(function(encodedString) {
    // Decode each encoded string and add to decoded list
    var decodedString = atob(encodedString);
    decodedArray.push(decodedString);
  });
  return decodedArray;
}

// Initiate decoding process
var decodedStrings = decodeBase64Strings();

// The decoded strings can now be used or logged
console.log(decodedStrings);
