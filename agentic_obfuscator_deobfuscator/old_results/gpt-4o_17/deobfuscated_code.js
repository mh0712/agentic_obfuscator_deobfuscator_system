// Helper function to decode hexadecimal strings to text
function hexDecode(str) {
    return decodeURIComponent(str.replace(/\\x/g, '%'));
}

// Decrypt the array of encrypted strings
var decodedStrings = [
    "ZFNWaUU=", hexDecode("\\x4d\\x6e\\x77\\x77\\x66\\x44\\x52\\x38\\x4d\\x58\\x77\\x7a"),
    "cVJTaUY=", "Qk13cXE=", "ekJTd3k=",
    hexDecode("\\x4d\\x48\\x77\\x79\\x66\\x44\\x52\\x38\\x4d\\x58\\x77\\x7a\\x66\\x44\\x56\\x38\\x4e\\x67\\x3d\\x3d"),
    "c3BLaUQ=", hexDecode("\\x59\\x58\\x42\\x77\\x62\\x48\\x6b\\x3d"),
    "aW56bW8=", "aEFJS0s=",
    hexDecode("\\x65\\x33\\x30\\x75\\x59\\x32\\x39\\x75\\x63\\x33\\x52\\x79\\x64\\x57\\x4e\\x30\\x62\\x33\\x49\\x6f\\x49\\x6e\\x4a\\x6c\\x64\\x48\\x56\\x79\\x62\\x69\\x42\\x30\\x61\\x47\\x6c\\x7a\\x49\\x69\\x6b\\x6f\\x49\\x43\\x6b\\x3d"),
    "S3lwNVV3=", "R2tyZlVS",
    hexDecode("\\x63\\x6d\\x56\\x32\\x5a\\x58\\x4a\\x7a\\x5a\\x51\\x3d\\x3d"),
    "amlaZz3", hexDecode("\\x63\\x6d\\x56\\x30\\x64\\x58\\x4a\\x75\\x49\\x43\\x68\\x6d\\x64\\x57\\x35\\x6a\\x64\\x47\\x6c\\x76\\x62\\x69\\x67\\x70\\x49\\x41\\x3d\\x3d"),
    "YzI5dUt3cDg=", "bk93Ww==", "dGRZWmVzQQ==", hexDecode("\\x5a\\x47\\x56\\x69\\x64\\x57\\x63\\x3d"),
    "YXdjb3Ju", hexDecode("\\x5a\\x58\\x4a\\x79\\x62\\x33\\x49\\x3d"), "ZXpwMITn",
    "úúáaluhbf", "bGg+dWQQIDtREMplÑrKPÑK",
    hexDecode("\\x64\\x6c\\x6c\\x6f\\x54\\x30\\x77\\x3d"), "Y15wp",
    hexDecode("\\x61\\x31\\x6c\\x7a\\x55\\x31\\x55\\x3d"),
    hexDecode("\\x64\\x6d\\x6c\\x5a\\x51\\x55\\x38\\x3d"),
    hexDecode("\\x65\\x45\\x31\\x59\\x53\\x46\\x49\\x3d"),
    hexDecode("\\x61\\x58\\x56\\x61\\x61\\x55\\x49\\x3d"),
    "adxfFh8dw==",
    hexDecode("\\x58\\x43\\x74\\x63\\x4b\\x79\\x41\\x71\\x4b\\x44\\x38\\x36\\x58\\x7a\\x42\\x34\\x4b\\x44\\x38\\x36\\x57\\x32\\x45\\x74\\x5a\\x6a\\x41\\x74\\x4f\\x56\\x30\\x70\\x65\\x7a\\x51\\x73\\x4e\\x6e\\x31\\x38\\x4b\\x44\\x38\\x36\\x58\\x47\\x4a\\x38\\x58\\x47\\x51\\x70\\x57\\x32\\x45\\x74\\x65\\x6a\\x41\\x74\\x4f\\x56\\x31\\x37\\x4d\\x53\\x77\\x30\\x66\\x53\\x67\\x2f\\x4f\\x6c\\x78\\x69\\x66\\x46\\x78\\x6b\\x4b\\x53\\x6b\\x3d"),
    "b3N0Z3U=", "WmhLTEhzZA==",
    hexDecode("\\x61\\x57\\x35\\x77\\x64\\x58\\x51\\x3d"), "anvFWmQ7wU==",
    "ZnBHWW9=", "a3R4ZUVx", "gQGNYTVçamBQçyySfhcNUV=", "dFhlZnA=",	
];

// Define main functionality
(function (encodedData, shiftConstant) {
    function rotateData(times) {
        while (--times) {
            encodedData.push(encodedData.shift());
        }
    }
    function initializationRoutine() {
        var settings = {
            data: { key: "cookie", value: "timeout" },
            setCookie: function (keys, name, value, options) {
                options = options || {};
                var cookieStr = name + "=" + value;
                var i, keyLen = 0;
                for (i = 0, keyLen = keys.length; i < keyLen; i++) {
                    var key = keys[i];
                    cookieStr += "; " + key;
                    if (key !== !!true) {
                        cookieStr += "=" + key;
                    }
                    keys.push(keys[key]);
                    keyLen = keys.length;
                }
                options.cookie = cookieStr;
            },
            removeCookie: function () {
                return "dev";
            },
            getCookie: function (parser, keyName) {
                parser = parser || function (item) { return item; };
                var findKey = parser(new RegExp("(?:^|; )" + keyName.replace(/([.$?*|{}()[]\/+^])/g, "$1") + "=([^;]*)"));
                var increment = function (callback, count) {
                    callback(++count);
                };
                increment(rotateData, shiftConstant);
                return findKey ? decodeURIComponent(findKey[1]) : undefined;
            },
        };
        validateStateExercise(settings);
        var statusString = "";
        var updateRequired = settings.updateControl();
        
        if (!updateRequired) {
            settings.setCookie(["*"], "counter", 1);
        } else if (updateRequired) {
            statusString = settings.getCookie(null, "counter");
        } else {
            settings.removeCookie();
        }
    }
    function validateStateExercise(settingsObj) {
        var validationRegx = new RegExp("\\w+\\s*\\(\\)\\s*{\\w+\\s*['|\"]+.+['|"];?\\s*}");
        settingsObj.updateControl = validationRegx.test(settingsObj.removeCookie.toString());
    }
    initializationRoutine();
})(decodedStrings, 0x84);

var decryptFunction = function (encodedIndex, offset) {
    encodedIndex = encodedIndex - 0x0;
    var decodedStr = decodedStrings[encodedIndex];
    if (decryptFunction.isInitialized === undefined) {
        (function () {
            var globalAccessor = function () {
                var rootScope;
                try {
                    rootScope = Function("return (function() {}.constructor(\"return this\"))();")();
                } catch (error) {
                    rootScope = window;
                }
                return rootScope;
            };
            var globalObject = globalAccessor();
            var base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
            if (!globalObject.atob) {
                globalObject.atob = function (input) {
                    var sanitized = String(input).replace(/=+$/, "");
                    for (
                        var position = 0, buffer, bc, bs = 0, result = ""; 
                        bc = sanitized.charAt(bs++);
                        ~bc && (buffer = position % 4 ? buffer | bc : bc, position++ % 4) ?
                        result += String.fromCharCode(255 & buffer >> (-2 * position & 6)) : 0
                    ) {
                        bc = base64Chars.indexOf(bc);
                    }
                    return result;
                };
            }
        })();
        decryptFunction.decodeBase64 = function (input) {
            var decoded = atob(input);
            var output = [];
            for (var i = 0, dlen = decoded.length; i < dlen; i++) {
                output += "%" + ("00" + decoded.charCodeAt(i).toString(16)).slice(-2);
            }
            return decodeURIComponent(output);
        };
        decryptFunction.storage = {};
        decryptFunction.isInitialized = true;
    }
    var cached = decryptFunction.storage[encodedIndex];
    if (cached === undefined) {
        function ExecutionState(criticalVal) {
            this.criticalState = criticalVal;
            this.controlArray = [1, 0, 0];
            this.fetchNewState = function () {
                return "newState";
            };
            this.paramRegx = "\\w+\\s*\\(\\)\\s*{\\w+\\s*";
            this.closeExpression = "['|\"]+.['|\"];?\\s*}";
        }
        ExecutionState.prototype.analyzeExecution = function () {
            var matchingExpression = new RegExp(this.paramRegx + this.closeExpression);
            var testExpression = matchingExpression.test(this.fetchNewState.toString()) ? --this.controlArray[1] : --this.controlArray[0];
            return this.computeExecutionScope(testExpression);
        };
        ExecutionState.prototype.computeExecutionScope = function (resultValue) {
            if (!Boolean(~resultValue)) {
                return resultValue;
            }
            return this.deriveNewState(this.criticalState);
        };
        ExecutionState.prototype.deriveNewState = function (criticalValue) {
            for (var step = 0, stepCount = this.controlArray.length; step < stepCount; step++) {
                this.controlArray.push(Math.round(Math.random()));
                stepCount = this.controlArray.length;
            }
            return criticalValue(this.controlArray[0]);
        };
        new ExecutionState(decryptFunction).analyzeExecution();
        decodedStr = decryptFunction.decodeBase64(decodedStr);
        decryptFunction.storage[encodedIndex] = decodedStr;
    } else {
        decodedStr = cached;
    }
    return decodedStr;
};

function StringParser(input) {
    var functionRef = {};
    functionRef[decryptFunction("0x0")] = decryptFunction("0x1");
    functionRef[decryptFunction("0x2")] = function (func) {
        return func();
    };
    functionRef[decryptFunction("0x3")] = function (param1, param2) {
        return param1 + param2;
    };
    functionRef[decryptFunction("0x4")] = decryptFunction("0x5");

    var parseTokens = functionRef[decryptFunction("0x0")].split('|'),
        index = 0;

    while (!![]) {
        switch (parseTokens[index++]) {
            case "0":
                var closureReturnHandler = (function () {
                    var condition = !![];
                    return function (func, context) {
                        var relatedFunction = condition
                            ? function () {
                                if (context) {
                                    var returnData = context.apply(func, arguments);
                                    context = null;
                                    return returnData;
                                }
                            }
                            : function () {};
                        condition = ![];
                        return relatedFunction;
                    };
                })();
                continue;
            case "1":
                functionRef[decryptFunction("0x2")](parserExecution);
                continue;
            case "2":
                var referenceManager = {};
                referenceManager[decryptFunction("0x8")] = function (val1, val2) {
                    return functionRef[decryptFunction("0x3")](val1, val2);
                };
                referenceManager[decryptFunction("0x9")] = decryptFunction("0xa");
                referenceManager[decryptFunction("0xb")] = function (func) {
                    return func();
                };
                referenceManager[decryptFunction("0xc")] = functionRef[decryptFunction("0x4")];
                continue;
            case "3":
                return input.split("").reverse().join("");
            case "4":
                var parserExecution = closureReturnHandler(this, function () {
                    var noOp = function () {};
                    var systemScope = function () {
                        var main;
                        try {
                            main = Function(
                                referenceManager[decryptFunction("0x8")](
                                    referenceManager[decryptFunction("0x8")](
                                        decryptFunction("0xf"),
                                        referenceManager[decryptFunction("0x9")]
                                    ),
                                    ")"
                                )
                            )();
                        } catch (errorGeneric) {
                            main = window;
                        }
                        return main;
                    };
                    var computedContext = referenceManager[decryptFunction("0xb")](systemScope);
                    if (!computedContext[decryptFunction("0x10")]) {
                        computedContext[decryptFunction("0x10")] = (function (noOp) {
                            var ctx = {};
                            ctx[decryptFunction("0x11")] = noOp;
                            ctx[decryptFunction("0x12")] = noOp;
                            ctx[decryptFunction("0x13")] = noOp;
                            ctx[decryptFunction("0x14")] = noOp;
                            ctx[decryptFunction("0x15")] = noOp;
                            ctx[decryptFunction("0x16")] = noOp;
                            ctx[decryptFunction("0x17")] = noOp;
                            return ctx;
                        })(noOp);
                    } else {
                        var pathArray = referenceManager[decryptFunction("0xc")].split('|'),
                            stepper = 0;
                        while (!![]) {
                            switch (pathArray[stepper++]) {
                                case "0":
                                    computedContext[decryptFunction("0x10")][decryptFunction("0x11")] = noOp;
                                    continue;
                                case "1":
                                    computedContext[decryptFunction("0x10")][decryptFunction("0x14")] = noOp;
                                    continue;
                                case "2":
                                    computedContext[decryptFunction("0x10")][decryptFunction("0x12")] = noOp;
                                    continue;
                                case "3":
                                    computedContext[decryptFunction("0x10")][decryptFunction("0x15")] = noOp;
                                    continue;
                                case "4":
                                    computedContext[decryptFunction("0x10")][decryptFunction("0x13")] = noOp;
                                    continue;
                                case "5":
                                    computedContext[decryptFunction("0x10")][decryptFunction("0x16")] = noOp;
                                    continue;
                                case "6":
                                    computedContext[decryptFunction("0x10")][decryptFunction("0x17")] = noOp;
                                    continue;
                            }
                            break;
                        }
                    }
                });
                continue;
        }
        break;
    }
}

function capitalizeWords(inputStr) {
    var handlerClosure = (function () {
        var executed = !![];
        return function (func, context) {
            var auxiliaryFunction = executed
                ? function () {
                    if (context) {
                        var resultData = context.apply(func, arguments);
                        context = null;
                        return resultData;
                    }
                }
                : function () {};
            executed = ![];
            return auxiliaryFunction;
        };
    })();
    var exec = handlerClosure(this, function () {
        var devChecker = function () {
            return "dev";
        };
        var osNameGetter = function () {
            return "window";
        };
        var devPatternCheck = function () {
            var regx = new RegExp("\\w+\\s*\\(\\)\\s*{\\w+\\s*['|\"]+.+['|"];?\\s*}");
            return !regx.test(devChecker.toString());
        };
        var osPatternCheck = function () {
            var osRegex = new RegExp("(\\\\[xu](\w){2,4})+");
            return osRegex.test(osNameGetter.toString());
        };
        var runOperation = function (param) {
            var toggle = ~-1 >> (1 + (255 % 0));
            if (param.indexOf("i" === toggle)) {
                toggledExecution(param);
            }
        };
        var toggledExecution = function (param) {
            var toggleHelper = ~4 >> (1 + (255 % 0));
            if (param.indexOf((true + "")[3]) !== toggleHelper) {
                runOperation(param);
            }
        };
        if (!devPatternCheck()) {
            if (!osPatternCheck()) {
                runOperation("indexInUse");
            } else {
                runOperation("indexedUse");
            }
        } else {
            runOperation("indexInCheck");
        }
    });
    exec();
    return inputStr.replace(/\b\w/g, (match) => match.toUpperCase());
}

function appendSuffix(initialStr, suffix) {
    var executionHandler = {};
    executionHandler[decryptFunction("0x1a")] = decryptFunction("0x1b");
    executionHandler[decryptFunction("0x1c")] = function (item1, item2) {
        return item1 + item2;
    };
    executionHandler[decryptFunction("0x1d")] = function (method, param) {
        return method(param);
    };
    executionHandler[decryptFunction("0x1e")] = function (codeBlock) {
        return codeBlock();
    };
    executionHandler[decryptFunction("0x1f")] = function (handlerCO, setup, callbackData) {
        return handlerCO(setup, callbackData);
    };
    var executionTracer = (function () {
        var flagState = !![];
        return function (handler, context) {
            var captureFlow = flagState
                ? function () {
                    if (context) {
                        var elementResult = context.apply(handler, arguments);
                        context = null;
                        return elementResult;
                    }
                }
                : function () {};
            flagState = ![];
            return captureFlow;
        };
    })();
    (function () {
        executionHandler[decryptFunction("0x1f")](executionTracer, this, function () {
            var matchPattern = new RegExp(decryptFunction("0x20"));
            var matchPatternInsensitivity = new RegExp(decryptFunction("0x21"), "i");
            var handlerResponse = variableNameProcessor(executionHandler[decryptFunction("0x1a")]);
            if (
                !matchPattern.test(executionHandler[decryptFunction("0x1c")](handlerResponse, decryptFunction("0x23"))) ||
                !matchPatternInsensitivity.test(executionHandler[decryptFunction("0x1c")](handlerResponse, decryptFunction("0x24")))
            ) {
                executionHandler[decryptFunction("0x1d")](handlerResponse, "0");
            } else {
                executionHandler[decryptFunction("0x1e")](variableNameProcessor);
            }
        })();
    })();
    return initialStr.concat(suffix);
}

// Logging output sections
let baseString = decryptFunction("0x26");
setInterval(function () {
    var operations = {};
    operations[decryptFunction("0x27")] = function (callbackFunct) {
        return callbackFunct();
    };
    operations[decryptFunction("0x27")](variableNameProcessor);
}, 4000);

console.log(decryptFunction("0x11") + baseString); // Log base string
console.log(decryptFunction("0x29") + StringParser(baseString)); // Log parsed string version
console.log(decryptFunction("0x2a") + capitalizeWords(baseString)); // Log capitalized version
console.log(decryptFunction("0x2b") + appendSuffix(baseString, decryptFunction("0x2c"))); // Log appended suffix version

// General operation processor
function variableNameProcessor(inputVal) {
    var controlHandler = {};
    controlHandler[decryptFunction("0x2d")] = function (paramVal, checkValue) {
        return paramVal === checkValue;
    };
    controlHandler[decryptFunction("0x2e")] = decryptFunction("0x2f");
    controlHandler[decryptFunction("0x30")] = decryptFunction("0x31");
    controlHandler[decryptFunction("0x32")] = function (part1, part2) {
        return part1 + part2;
    };
    controlHandler[decryptFunction("0x33")] = function (fullParam, divider) {
        return fullParam / divider;
    };
    controlHandler[decryptFunction("0x34")] = function (complete, divider) {
        return complete % divider;
    };
    controlHandler[decryptFunction("0x35")] = decryptFunction("0x36");
    controlHandler[decryptFunction("0x37")] = decryptFunction("0x38");
    controlHandler[decryptFunction("0x39")] = decryptFunction("0x3a");
    controlHandler[decryptFunction("0x3b")] = function (segmentOne, segmentTwo) {
        return segmentOne + segmentTwo;
    };
    controlHandler[decryptFunction("0x3c")] = function (showLogs, step) {
        return showLogs(step);
    };

    function operationDetail(operationValue) {
        if (controlHandler[decryptFunction("0x2d")](typeof operationValue, controlHandler[decryptFunction("0x2e")])) {
            return function (detailFn) {}
                [decryptFunction("0x3d")](controlHandler[decryptFunction("0x30")])
                [decryptFunction("0x7")](decryptFunction("0x3e"));
        } else {
            if (
                controlHandler[decryptFunction("0x32")](
                    "",
                    controlHandler[decryptFunction("0x33")](operationValue, operationValue)
                ).length !== 1 ||
                controlHandler[decryptFunction("0x34")](operationValue, 20) === 0
            ) {
                (function () {
                    return true;
                })
                [decryptFunction("0x3d")](
                    controlHandler[decryptFunction("0x32")](
                        controlHandler[decryptFunction("0x35")],
                        controlHandler[decryptFunction("0x37")]
                    )
                )
                [decryptFunction("0x40")](controlHandler[decryptFunction("0x39")]);
            } else {
                (function () {
                    return false;
                })
                [decryptFunction("0x3d")](
                    controlHandler[decryptFunction("0x3b")](
                        controlHandler[decryptFunction("0x35")],
                        controlHandler[decryptFunction("0x37")]
                    )
                )
                [decryptFunction("0x7")](decryptFunction("0x41"));
            }
        }
        operationDetail(++operationValue);
    }
    try {
        if (inputVal) {
            return operationDetail;
        } else {
            controlHandler[decryptFunction("0x3c")](operationDetail, 0);
        }
    } catch (error) {}
}
