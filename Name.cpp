// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#include "pch.h"
#include "Types.h"

constexpr auto BASE_NAME_DICTIONARY_FILENAME = "name.dict";
constexpr auto APP_DICTIONARY_FILENAME = "app.dict";

template <>
TOKENTYPE GetNameType<SERVICE_STACK>() { return TOKENTYPE::NAME_APP; }

template<>
TOKENTYPE GetNameType<GLOBAL_STACK>() { return TOKENTYPE::NAME_GLOBAL; }

template<>
TOKENTYPE GetNameType<SESSION_STACK>() { return TOKENTYPE::NAME_SESSION; }

template<>
TOKENTYPE GetNameType<SCHEDULER_STACK>() { return TOKENTYPE::NAME_SCHEDULER; }

UINT32 GetNameLength(TOKEN handle)
{
	auto nameType = handle.getMinorType();

	if (nameType == TOKENTYPE::MINOR_GLOBAL)
	{
		return GetNameLength(GlobalStack().dictionary, handle);
	}
	else if (nameType == TOKENTYPE::MINOR_SESSION)
	{
		return GetNameLength(GetCurrentStack<SESSION_STACK>().dictionary, handle);
	}
	else if (nameType == TOKENTYPE::MINOR_APP)
	{
		return GetNameLength(GetCurrentStack<SERVICE_STACK>().dictionary, handle);
	}
	else if (nameType == TOKENTYPE::MINOR_SCHEDULER)
	{
		return GetNameLength(GetCurrentStack<SCHEDULER_STACK>().dictionary, handle);
	}
	else DBGBREAK();
	return 0;
}

int NameToString(TOKEN handle, UINT8 *stringBuffer)
{
	UINT16 name = NAME_INDEX(handle);
	UINT8 variant = VARIANT_INDEX(handle);
	auto nameType = handle.getMinorType();

	if (nameType == TOKENTYPE::MINOR_GLOBAL)
	{
		return NameToString(GlobalStack().dictionary, name, variant, stringBuffer);
	}
	else if (nameType == TOKENTYPE::MINOR_SESSION)
	{
		return NameToString(GetCurrentStack<SESSION_STACK>().dictionary, name, variant, stringBuffer);
	}
	else if (nameType == TOKENTYPE::MINOR_APP)
	{
		return NameToString(GetCurrentStack<SERVICE_STACK>().dictionary, name, variant, stringBuffer);
	}
	else if (nameType == TOKENTYPE::MINOR_SCHEDULER)
	{
		return NameToString(GetCurrentStack<SCHEDULER_STACK>().dictionary, name, variant, stringBuffer);
	}
	else DBGBREAK();
	return 0;
}

USTRING NameToString(TOKEN name)
{
	ASSERT(name.getMajorType() == TOKENTYPE::NAME);
	return GetTempStream().writeName(name);
}
//
//const UINT8 *ns(TOKEN &name)
//{
//	return NameToString(name, STATIC_STRING()).data();
//}

//const UINT8 *ns(INT32 name)
//{
//	TOKEN handle;
//	handle._value = name;
//	return NameToString(handle, STATIC_STRING()).data();
//}

int CompareSortData(SORT_HEADER &sortData, UINT64 header, UINT32 footer)
{
	int result;
	if (sortData.header < header)
	{
		result = -1;
	}
	else if (sortData.header > header)
	{
		result = 1;
	}
	else
	{
		if (sortData.footer < footer)
		{
			result = -1;
		}
		else if (sortData.footer > footer)
		{
			result = 1;
		}
		else
		{
			result = 0;
		}
	}
	return result;
}

TOKEN FindName(USTRING input, bool isCaseSensitive)
{
	return FindName(GlobalStack().dictionary, input, isCaseSensitive);
}

TOKEN CreateName(USTRING input, bool isCaseSensitive)
{
	auto&& parsedName = PARSED_NAME(input, isCaseSensitive);
	return CreateNameInternal(GlobalStack().dictionary, parsedName);
}

bool NameToInt(TOKEN name, INT64 &number)
{
	ASSERT(name.isName());
	auto isSuccessful = false;

	if (IS_LITERAL_NAME(name))
		return false;

	auto value = name.getValue();
	if (value >= NAME_NEG__25.getValue() && value <= NAME_255.getValue())
	{
		number = (value - NAME_NEG__25.getValue()) + INT_NAME_MIN;
		isSuccessful = true;
	}
	else
	{
		auto nameString = NameToString(name);
		number = String.toNumber(nameString);
		isSuccessful = nameString.length() == 0;
	}
	return isSuccessful;
}

TOKEN IntToName(int number)
{
	auto name = Undefined;
	if (number >= -25 && number <= 255)
	{
		name = NAME_HANDLE(NAME_NEG__25.getValue() + (number + 25));
	}
	else
	{
		auto string = TSTRING_BUILDER().writeString(number);
		name = CreateName(string);
	}
	return name;
}


//
//TOKEN NameToNumber(TOKEN name)
//{
//	ASSERT(name.isString());
//	if (name._value >= NAME_NEG_25._value && name._value <= NAME_255._value)
//	{
//		auto intValue = (name._value - NAME_NEG_25._value) + INT_NUM_MIN;
//		return CreateNumberHandle(intValue);
//	}
//	else
//	{
//		INT64 number;
//		return (NameToInt(name, number)) ? CreateNumberHandle(number) : Undefined;
//	}
//}

INT32 KeywordIndex(TOKEN name)
{
	if (IsEmptyString(name))
		return -1;

	for (auto i = 0; i < ARRAYSIZE(KeywordNames); i++)
	{
		if (KeywordNames[i] == name)
			return i;
	}
	return -1;
}


constexpr USTRING EntityStrings[] = {
	"AElig", "Aacute", "Acirc", "Agrave", "Alpha", "Aring", "Atilde", "Auml", "Beta", "Ccedil", "Chi", "Dagger", "Delta",
	"ETH", "Eacute", "Ecirc", "Egrave", "Epsilon", "Eta", "Euml", "Gamma", "Iacute", "Icirc", "Igrave", "Iota", "Iuml",
	"Kappa", "Lambda", "Mu", "Ntilde", "Nu", "OElig", "Oacute", "Ocirc", "Ograve", "Omega", "Omicron", "Oslash", "Otilde",
	"Ouml", "Phi", "Pi", "Prime", "Psi", "Rho", "Scaron", "Sigma", "THORN", "Tau", "Theta", "Uacute", "Ucirc", "Ugrave",
	"Upsilon", "Uuml", "Xi", "Yacute", "Yuml", "Zeta", "aacute", "acirc", "acute", "aelig", "agrave", "alefsym", "alpha",
	"amp", "and", "ang", "apos", "aring", "asymp", "atilde", "auml", "bdquo", "beta", "brvbar", "bull", "cap", "ccedil",
	"cedil", "cent", "chi", "circ", "clubs", "cong", "copy", "crarr", "cup", "curren", "dArr", "dagger", "darr", "deg",
	"delta", "diams", "divide", "eacute", "ecirc", "egrave", "empty", "emsp", "ensp", "epsilon", "equiv", "eta", "eth",
	"euml", "euro", "exist", "fnof", "forall", "frac12", "frac14", "frac34", "frasl", "gamma", "ge", "gt", "hArr", "harr",
	"hearts", "hellip", "iacute", "icirc", "iexcl", "igrave", "image", "infin", "int", "iota", "iquest", "isin", "iuml",
	"kappa", "lArr", "lambda", "lang", "laquo", "larr", "lceil", "ldquo", "le", "lfloor", "lowast", "loz", "lrm", "lsaquo",
	"lsquo", "lt", "macr", "mdash", "micro", "middot", "minus", "mu", "nabla", "nbsp", "ndash", "ne", "ni", "not", "notin",
	"nsub", "ntilde", "nu", "oacute", "ocirc", "oelig", "ograve", "oline", "omega", "omicron", "oplus", "or", "ordf", "ordm",
	"oslash", "otilde", "otimes", "ouml", "para", "part", "permil", "perp", "phi", "pi", "piv", "plusmn", "pound", "prime",
	"prod", "prop", "psi", "quot", "rArr", "radic", "rang", "raquo", "rarr", "rceil", "rdquo", "real", "reg", "rfloor", "rho",
	"rlm", "rsaquo", "rsquo", "sbquo", "scaron", "sdot", "sect", "shy", "sigma", "sigmaf", "sim", "spades", "sub", "sube",
	"sum", "sup", "sup1", "sup2", "sup3", "supe", "szlig", "tau", "there4", "theta", "thetasym", "thinsp", "thorn", "tilde",
	"times", "trade", "uArr", "uacute", "uarr", "ucirc", "ugrave", "uml", "upsih", "upsilon", "uuml", "weierp", "xi",
	"yacute", "yen", "yuml", "zeta", "zwj", "zwnj",
};

constexpr USTRING KeywordStrings[] = { "break", "do", "instanceof", "typeof", "case", "else", "new", "var", "catch", "finally", "return", "void", "continue", "for", "switch", "while", "debugger", "function", "with", "default",
"if", "throw", "delete", "in", "try", "class", "enum", "extends", "super",
"const", "export", "implements", "let", "private", "public", "interface", "package", "protected", "static", "yield", "import" };

constexpr USTRING ElementStrings[] = { "a", "abbr", "address", "all", "area", "article", "aside", "audio", "b", "base", "bdi", "bdo",
"blockquote", "body", "br", "button", "canvas", "caption", "cite", "code", "col", "colgroup", "menuitem", "data", "hgroup",
"datalist", "dd", "del", "details", "dfn", "dialog", "div", "dl", "doc", "dt", "em", "embed", "fieldset", "figcaption",
"figure", "first-child", "last-child", "nth-child", "checked", "disabled", "enabled", "active", "required", "optional", "hover", "focus",
"only-child", "only-of-type", "root", "target", "valid", "invalid", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "head", "header",
"hr", "html", "i", "iframe", "img", "before", "after", "empty", "visited", "center", "comment",
"input", "ins", "kbd", "keygen", "label", "legend", "li", "link", "main", "map", "mark", "menu", "meta", "meter",
"nav", "noscript", "not", "object", "ol", "optgroup", "option", "output", "p", "param", "pre", "progress", "polyline", "q", "rp", "rt",
"ruby", "s", "samp", "script", "section", "select", "small", "source", "span", "strong", "style", "sub", "summary", "svg",
"sup", "table", "tbody", "td", "textarea", "text", "tfoot", "th", "thead", "time", "title", "tr", "track", "u", "ul", "var",
"video", "wbr", "*", "xelem1", "xelem2", "xelem3", "xelem4", "xelem5", "xelem6", "xelem7", "xelem8", "xelem9" };

constexpr USTRING RuntimeStrings[] = { "$", "array", "Array", "ajax", "ajaxStart", "ajaxStop", "ajaxSetup", "ajaxComplete", "ajaxError", "ajaxSuccess", "ajaxSend", "ajaxPrefilter", "ajaxTransport", "arguments", "push", "pop", "length", "document", "regex", "window", "isarray",
"always", "addEventListener", "attachEvent", "removeEventListener", "loading", "loaded", "commpleted", "clone", "parseInt", "parseFloat", "isNaN", "browser", "script", "fn", "bool", "isNumber", "isEmptyObject", "isPlainObject", "isArray", "extend", "expando", "isReady", "noop", "error", "makeArray",
"concat", "join", "noConflict", "reverse", "shift", "slice", "sort", "splice", "unshift", "indexOf", "lastIndexOf", "every", "some", "imagesLoaded", "masonry",
"foreach", "map", "filter", "reduce", "reduceRight", "valueOf", "charAt", "charCodeAt", "localeCompare", "match", "version", "msie", "webkit", "safari", "opera", "mozilla",
"split", "substring", "substr", "toLowerCase", "toLocaleLowerCase", "toUpperCase", "toLocaleUpperCase", "metadata", "dataType", "caller", "callee",
"trim", "null", "MIN_VALUE", "MAX_VALUE", "NaN", "NEGATIVE_INFINITY", "POSITIVE_INFINITY", "toExponential", "toPrecision", "apply", "call", "prototype",
"math", "e", "ln10", "ln2", "log2e", "log10e", "pi", "sqrt2", "sqrt1_2", "abs", "acos", "asin", "atan", "atan2", "ceil", "compatMode", "CSS1Compat",
"cos", "exp", "floor", "log", "max", "min", "pow", "random", "round", "sin", "sqrt", "tan", "year", "month", "date", "attrHooks", "cssHooks", "mouseHooks", "keyHooks",
"now", "parse", "utc", "toDateString", "toTimeString", "toLocaleString", "toLocaleDateString", "toLocaleTimeString", "stringify",
"getTime", "getFullYear", "getUTCFullyear", "getMonth", "getUTCMonth", "getData", "getUTCDate", "getDay", "getUTCDay", "parseJSON", "parseXML", "isFunction",
"getHours", "getUTCHours", "getMinutes", "getUTCMinutes", "getSeconds", "getUTCSeconds", "getMilliSeconds", "getUTCMilliSeconds",
"getTimeZoneOffset", "setTime", "setMilliSeconds", "setUTCMilliseconds", "setSeconds", "setUTCSeconds", "setMinutes",
"setUTCMinutes", "setHours", "setUTCHouse", "setDate", "setUTCDate", "setMonth", "setUTCMonth", "setFullYear", "setUTCFullYear",
"String", "RegExp", "Arguments", "Boolean", "Function", "JSON", "Object", "Number", "src", "widget", "constructor",
"toUTCString", "toISOString", "toJSON", "exec", "test", "source", "global", "ignorecase", "multiline", "lastIndex", "Error",
"name", "message", "true", "false", "add", "index", "each", "is", "children", "andSelf", "find", "parent", "parents", "parentsUntil",
"closest", "siblings", "next", "prev", "nextAll", "prevAll", "nextUntil", "prevUntil", "selector", "context", "jQuery", "jquery",
"toArray", "append", "prepend", "appendTo", "prependTo", "wrap", "wrapAll", "wrapInner", "after", "before", "insertAfter",
"replaceWith", "replaceAll", "remove", "empty", "unwrap", "detach", "attr", "prop", "removeAttr", "removeProp", "addClass", "hasClass", "removeClass",
"toggleClass", "css", "text", "html", "val", "data", "innerHeight", "innerWidth", "offset", "outerHeight", "outerWidth",
"position", "removeData", "bind", "unbind", "one", "live", "die", "delegate", "undelegate",
"trigger", "triggerHandler", "currentTarget", "isDefaultPrevented", "isPropationStopped", "originalEvent", "pageX", "pageY",
"preventDefault", "relatedTarget", "result", "stopImmediatePropagation", "stopPropagation", "target", "timeStamp", "type", "which",
"resize", "click", "dblclick", "focusin", "focusout", "hover", "mousedown", "mouseenter", "mouseleave", "mousemove", "mouseout",
"mouseover", "mouseup", "blur", "change", "focus", "select", "submit", "keydown", "keypress", "keyup", "show", "hide", "toggle",
"animate", "queue", "delay", "all", "keys", "defineProperty", "defineProperties", "getOwnPropertyNames",
"hasOwnProperty", "create", "Math", "Date", "ready", "console", "this", "main", "fadeIn", "fadeOut", "polyfiller", "Modernizr", "amd", "polyfill",
"encodeURI", "encodeURIComponent", "escape", "decodeURI", "decodeURIComponent", "unescape", "isFinite", "browserLanguage",
"getPrototypeOf", "getOwnPropertyDescriptor", "seal", "isSealed", "freeze", "isFrozen", "preventExtensions", "isExtensible", "isPrototypeOf", "isEnumerable", "propertyIsEnumerable", "hasInstance",
"eq", "first", "last", "not", "has", "get", "size", "end", "contents", "load", "defaultView", "grep",
"post", "timeout", "getResponseHeader", "getAllResponseHeaders", "setRequestHeader", "send", "abort", "cancel", "upload", "withCredentials", "status", "statusText",
"hash", "domain", "hostname", "href", "pathname", "port", "protocol", "search", "assign", "reload", "replace",
"appCodeName", "appName", "appVersion", "cookieEnabled", "language", "onLine", "platform", "product", "userAgent", "javaEnabled", "taintEnabled",
"availHeight", "availWidth", "colorDepth", "height", "width", "pixelDepth", "back", "forward", "go",
"adoptNode", "anchors", "applets", "baseURI", "head", "body", "cookie", "createAttribute", "createComment", "createDocumentFragment", "createElement",
"createTextNode", "docType", "documentElement", "documentMode", "documentURI", "domConfig", "forms", "getElementById", "getElementsByName", "getElementsByTagName", "getElementsByClassName",
"images", "implementation", "importNode", "inputEncoding", "lastModified", "links", "normalize", "normalizeDocument",  "readyState", "referrer",
"renameNode", "strictErrorChecking", "URL", "write", "writeln", "querySelectorAll",
"accessKey", "appendChild", "attributes", "childNodes", "className", "clientHeight", "clientWidth", "cloneNode",
"compareDocumentPosition", "dir", "firstChild", "getAttribute", "getAttributeNode", "getFeature", "getUserData",
"hasAttribute", "hasAttributes", "hasChildNodes", "id", "innerHTML", "insertBefore", "isDefaultNamespace", "isEqualNode", "isSameNode",
"isSupported", "lang", "lastChild", "namespaceURI", "nextSibling", "nodeName", "nodeType", "nodeValue", "offsetHeight", "offsetWidth", "offsetLeft", "offsetParent",
"offsetTop", "ownerDocument", "parentNode", "previousSibling", "removeAttribute", "removeAttributeNodes", "chrome",
"removeChild", "replaceChild", "scrollHeight", "scrollLeft", "scrollTop", "scrollWidth", "setAttribute",
"setAttributeNode", "setIdAttribute", "setIdAttributeNode", "setUserData", "style", "tabIndex", "tagName", "textContent", "title",
"toString", "item", "specified", "getNamedItem", "removeNamedItem", "setNamedItem", "navigator", "location", "updatePolyfill",
"undefined", "object", "boolean", "string", "function", "number", "onload", "define", "require", "on", "off", "removeCookie", "expr",
"createPseudo", "url", "success", "validate", "colorbox", "jsTree", "NativeError", "TypeError", "RangeError", "EvalError", "ReferenceError",
"alert", "setInterval", "setTimeout", "setImmediate", "clearInterval", "clearTimeout", "close", "confirm", "createPopup", "moveBy", "moveTo",
"open", "print", "prompt", "resizeBy", "resizeTo", "scroll", "scrollTo", "scrollBy", "stop",
};

constexpr USTRING HttpStrings[] = { "http", "https", "/", "CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "POST", "PUT", "TRACE",
"Accept", "Accept-Charset", "Accept-Encoding", "Sec-WebSocket-Key", "Sec-WebSocket-Extension", "Sec-WebSocket-Accept", "Sec-WebSocket-Protocol", "Sec-WebSocket-Version",
"Age", "Allow", "Accept-Ranges", "Access-Control-Request-Headers", "Access-Control-Request-Method", "Accept-Language", "Accept-Datetime", "Authorization",
"Connection", "Content-Type", "Content-Length","Content-Encoding", "Content-Range", "Content-Language", "Content-Disposition", "Content-Location",
"Content-MD5", "Cache-Control", "Cookie", "Cookie2", "Date", "Max-Age", "Path", "Domain",
"DNT", "Expect", "Host", "Keep-Alive", "Close", "Origin", "Referer", "TE", "Trailer", "Upgrade", "User-Agent", "Via",
"If-Match", "If-Modified-Since", "If-None-Match", "If-Range", "If-Unmomdified-Since", "From", "Pragma",
"Proxy-Authorization", "Range", "Warning", "Set-Cookie", "Server", "Transfer-Encoding",
"Vary", "WWW-Authenticate", "Status", "Last-Modified", "Expires", "ETag", "Proxy-Authenticate", "P3P", "Link", "Location", "Refresh", "Retry-After",
"Proxy-Connection", "localhost", "Session", 
"100", "CONTINUE", "101", "SWITCHING PROTOCOLS", "200", "OK",
"201", "CREATED", "202", "ACCEPTED", "203", "NON AUTHORITAVIVE INFORMATION", "204", "NO CONTENT", "205", "RESET CONTENT",
"300", "MULTIPLE CHOICES", "301", "MOVED PERMANENTLY", "302", "FOUND", "303", "SEE OTHER", "305", "USE PROXY",
"307", "TEMPORARY REDIRECT", "400", "BAD REQUEST", "402", "PAYMENT REQUIRED", "403", "FORBIDDEN", "404", "NOT FOUND",
"405", "METHOD NOT ALLOWED", "406", "NOT ACCEPTABLE", "408", "REQUEST TIMEOUT", "409", "CONFLICT", "410", "GONE",
"411", "LENGTH REQUIRED", "413", "PAYLOAD TOO LARGE", "414", "URI TOO LONG", "415", "UNSUPPORTED MEDIA", "426", "UPGRADE REQUIRED",
"500", "INTERNAL SERVER ERROR", "501", "NOT IMPLEMENTED", "502", "BAD GATEWAY", "503", "SERVICE UNAVAILABLE",
"504", "GATEWAY TIMEOUT", "505", "HTTP VERSION NOT SUPPORTED",

"text/html", "application/json", "application/xhtml+xml", "text/css",
"text/plain", "text/richtext", "text/cache-manifest", "text/vtt", "image/x-xbitmap", "application/postscript", "audio/aiff",
"audio/basic", "audio/wav", "audio/x-wav", "image/gif", "image/pjpeg", "image/jpeg", "image/tiff", "image/vnd.ms-photo",
"image/png", "image/vnd.ms-dds", "image/x-png", "image/x-icon", "image/svg+xml", "image/bmp", "image/x-emf", "image/x-wmf",
"video/avi", "video/mpeg", "application/fractals", "application/octet-stream", "application/pdf",
"application/hta", "application/xml", "audio/x-aiff", "audio/x-pn-realaudio", "image/xbm",
"video/quicktime", "video/x-msvideo", "video/x-sgi-movie", "multipart/x-mixed-replace",  "text/xml",
"application/ttml+xml", "application/ttaf+xml", "application/x-javascript", "text/json", "application/javascript",
};

constexpr USTRING AttributeStrings[] = { "abbr", "accept", "accept-charset", "accesskey", "action", "align", "allowfullscreen", "allowtransparency", "alt", "async",
"autocomplete", "autofocus", "autoplay", "bgcolor", "border", "bordercolor", "border-spacing", "cellspacing", "cellpadding", "challenge", "charset", "checked",
"cite", "class", "cols", "colspan", "command", "content", "contenteditable", "contextmenu", "controls", "coords", "crossorigin", "data",
"datetime", "default", "defer", "dir", "dirname", "disabled", "download", "draggable", "dropzone",
"enctype", "for", "form", "formaction", "formenctype", "formmethod", "formnovalidate", "formtarget", "frameborder", "headers",
"height", "hidden", "high", "href", "hreflang", "hspace", "http-equiv", "icon", "id", "inert", "inputmode", "ismap", "itemid",
"marginheight", "marginwidth", "radio", "visible", "submit", "image", "file",
"itemprop", "itemref", "itemscope", "itemtype", "keytype", "kind", "label", "lang", "list", "longdesc", "loop", "low", "manifest",
"max", "maxlength", "media", "mediagroup", "method", "min", "multiple", "muted", "name", "novalidate", "onabort", "onblur", "oncance", "oncanplay",
"oncanplaythrough", "onchange", "onclick", "onclose", "oncontextmenu", "oncuechange", "ondblclick", "ondrag", "ondragend", "ondragenter", "ondragexit",
"ondragleave", "ondragover", "ondragstart", "ondrop", "ondurationchange", "onemptied", "onended", "onerror", "onfocus",
"oninput", "oninvalid", "onkeydown", "onkeypress", "onkeyup", "onload", "onloadeddata", "onloadedmetadata",
"onloadstart", "onmousedown", "onmouseenter", "onmouseleave", "onmousemove", "onmouseout", "onmouseover",
"onmouseup", "onmousewhee", "onpause", "onplay", "onplaying", "onprogress", "onratechange", "onreset",
"onscroll", "onseeked", "onseeking", "onselect", "onshow", "onsort", "onstalled", "onsubmit", "onsuspend",
"ontimeupdate", "onvolumechange", "onwaiting", "open", "optimum", "password",
"pattern", "placeholder", "poster", "preload", "profile", "property", "radiogroup", "readonly", "rel", "required", "reversed",
"role", "rows", "rowspan", "sandbox", "spellcheck", "scope", "scoped", "scrolling", "seamless", "selected", "shape", "size", "sizes", "span",
"src", "srcdoc", "srclang", "start", "step", "style", "stylesheet", "summary", "tabindex", "target", "text", "textarea", "title", "text/css",
"text/javascript", "translate", "type", "button", "checkbox", "color", "date", "datetime-local", "email", "month", "number", "reset", "tel", "time", "url", "week",
"typemustmatch", "usemap", "username", "value", "vspace", "width", "wrap", "xmlns", "xattr2", "xattr3", "xattr4", "xattr5", "xattr6", "xattr7",
"xattr8", "xattr9" };

constexpr USTRING EventStrings[] = { "abort", "ajaxStart", "ajaxstop", "ajaxComplete", "ajaxError", "ajaxSuccess", "ajaxSend", "ajaxTransport",
"ajaxPrefilter", "afterprint", "beforeprint", "beforeunload", "blur", "cancel", "canplay",
"canplaythrough", "change", "click", "close", "contextmenu", "cuechange", "dblclick", "drag", "dragend",
"dragenter", "dragexit", "dragleave", "dragover", "dragstart", "drop", "durationchange", "emptied", "ended",
"error", "focus", "focusin", "focusout", "fullscreenchange", "fullscreenerror", "hashchange", "input", "invalid", "keydown", "keypress",
"keyup", "load", "loadeddata", "loadedmetadata", "loadstart", "message", "mousedown", "mouseenter", "mouseleave",
"mousemove", "mouseout", "mouseover", "mouseup", "mousewheel", "offline", "online", "pagehide", "pageshow", "pause",
"play", "playing", "popstate", "progress", "ratechange", "reset", "resize", "scroll", "seeked", "seeking", "select",
"show", "sort", "stalled", "storage", "submit", "suspend", "timeupdate", "unload", "volumechange", "waiting",
"yevnt1", "yevnt2", "yevnt3", "yevnt4", "yevnt5", "yevnt6", "yevnt7", "yevnt8", "yevnt9" };

constexpr USTRING StyleStrings[] = { "absolute", "accelerator", "active","after", "american", "arial", "auto", "azimuth", "background", "background-attachment", "background-color",
"background-image", "background-position", "background-position-x", "background-position-y", "background-repeat",
"behavior", "before", "below", "behind", "blink", "block", "bold", "bolder", "border", "border-bottom", "border-bottom-color", "border-bottom-style", "border-bottom-width",
"border-collapse", "border-color", "border-image", "border-left", "border-left-color", "border-left-style", "border-left-width",
"border-right", "border-right-color", "border-right-style", "border-right-width", "border-spacing", "border-style",
"border-top", "border-top-color", "border-top-style", "border-top-width", "border-width", "both", "bottom", "caption", "capitalize", "caption-side", "circle", "checked",
"center", "center-left", "center-right", "close-quote", "clear", "clip", "color", "content", "collapse", "counter-increment", "counter-reset", "cue",
"cursor", "currentColor", "cue-before", "cue-after", "cursive", "direction", "disc", "display", "double", "dashed", "dotted", "disabled", "elevation",
"empty-cells", "empty", "enabled", "fantasy", "far-left", "far-right", "first-child", "filter", "first-of-type", "fixed", "first-letter", "first-line", "float", "focus",
"font", "font-family", "font-size", "font-size-adjust", "font-stretch", "font-style", "font-variant", "font-weight", "groove", "helvetica", "height", "hide", "hidden",
"higher", "hover", "icon", "inside", "inherit", "ime-mode", "include-source", "italic", "inset", "inline", "inline-block", "inline-table", "justify",
"layer-background-color", "layer-background-image", "layout-flow", "layout-grid", "layout-grid-char", "layout-grid-char-spacing", "layout-grid-line",
"layout-grid-mode", "layout-grid-type", "left", "left-side", "leftwards", "letter-spacing", "lang", "last-of-type", "level", "link", "line-break", "lighter",
"line-height", "list-style", "list-item", "list-style-image", "list-style-position", "list-style-type", "lowercase", "last-child",
"lower-roman", "lower-greek", "lower-latin", "margin", "margin-bottom", "medium", "margin-left", "margin-right", "margin-top", "marker-offset",
"marks", "max-height", "max-width", "min-height", "menu", "messagebox", "middle", "min-width", "monospace", "-moz-binding", "-moz-border-radius",
"-moz-border-radius-topleft", "-moz-border-radius-topright", "-moz-border-radius-bottomright", "-moz-border-radius-bottomleft",
"-moz-border-top-colors", "-moz-border-right-colors", "-moz-border-bottom-colors", "-moz-border-left-colors", "only-child",
"-moz-opacity", "-moz-outline", "-moz-outline-color", "-moz-outline-style", "-moz-outline-width", "-moz-user-focus", "nth-child", "nth-last-child",
"nth-of-type", "nth-last-of-type", "-moz-user-input", "-moz-user-modify", "-moz-user-select", "none", "not", "normal", "no-open-quote", "no-repeat", "no-close-quote",
"oblique", "only-of-type", "orphans", "opacity", "outline", "outline-color", "outline-style", "open-quote", "outside", "outline-width", "overflow", "overflow-X",
"overflow-Y", "overline", "outset", "padding", "padding-bottom", "padding-left", "padding-right", "padding-top", "page", "page-break-after", "page-break-before",
"page-break-inside", "pause", "pause-after", "pause-before", "pitch", "pitch-range", "play-during", "position", "quotes", "-replace", "relative", "repeat",
"repeat-x", "repeat-y", "resize", "richness", "ridge", "right", "right-side", "rightwards", "root", "ruby-align", "ruby-overhang", "ruby-position ",
"-set-link-source", "scroll", "separate", "selection", "serif", "sans-serif", "show", "size", "small-caps", "speak", "speak-header", "speak-numeral",
"speak-punctuation", "speech-rate", "stress", "scrollbar-arrow-color", "scrollbar-base-color",
"scrollbar-dark-shadow-color", "scrollbar-face-color", "scrollbar-highlight-color", "scrollbar-shadow-color", "segoe ui", "solid",
"scrollbar-3d-light-color", "scrollbar-track-color", "status-bar", "line-through", "square", "table", "table-layout", "table-rowgroup",
"table-footer-group", "table-header-group", "table-row", "table-column-group", "table-column", "table-cell", "table-caption", "text-align",
"text-align-last", "text-decoration", "text-indent", "text-justify", "text-overflow", "text-shadow", "text-transform", "text-autospace", "text-kashida-space", "target",
"text-underline-position", "thin", "thick", "times", "times new roman", "georgia", "top", "transparent", "underline", "unicode-bidi", "upper-roman", "upper-alpha",
"-use-link-source", "uppercase", "vertical-align", "visibility", "visible", "voice-family", "verdana", "visited", "volume ", "white-space", "widows", "width",
"word-break", "word-spacing", "word-wrap", "writing-mode", "media", "import", "xx-small", "x-small", "small", "large", "x-large", "xx-large",
"100", "200", "300", "400", "500", "600", "700", "800", "900", "!important", "aqua", "black", "blue", "fuchsia", "gray", "green", "lime",
"maroon", "navy", "olive", "orange", "purple", "red", "silver", "teal", "white", "yellow",
"z-index", "zoom", "zstyl1", "zstyl2", "zstyl3", "zstyl4", "zstyl5", "zstyl6", "zstyl7", "zstyl8", "zstyl9" };


constexpr USTRING SdpStrings[] = {
	"video", "audio", "application", "IP4", "IP6", "IN", "BUNDLE", "orient", "end-of-candidates",
	"ptime", "maxptime", 
	"group", "mid", "bundle-only", "rtcp-mux", "rtcp-rsize", "ssrc", "cname", "extmap-allow-mixed", "extmap",
	"msid-semantic", "WMS", "msid", "default", "-", "mslabel", "label", "ssrc-group", "crypto", "candidate",
	"raddr", "rport", "ufrag",  "pwd", "network-id", "fingerprint", "setup", "fmtp",
	"rtpmap", "sctpmap", "rtcp", "ice-ufrag", "ice-pwd", "ice-lite", "ice-options", "sendonly", "recvonly", "rtcp-fb",
	"sendrecv", "inactive", "sctp-port", "max-message-size", "rid", 
	"profile-level-id", "udp", "host", "generation", "network-cost", "typ", "apt", "red", "rtx",
	"nack", "pli", "ulpfec", "srflx", "prflx", "relay", "tcptype", "127.0.0.1", "0.0.0.0", "9", "AS", 
	"name", "author", "description", "version_string", "version", "transports", "transport",
	"session_id", "handle_id", "ping", "pong", "create", "id", "success", "data", "attach", "keepalive",
	"plugin", "token", "opaque_id", "destroy", "janus", "detach", "hangup", "claim", "message", "body", "jsep",
	"type", "trickle", "offer", "answer", "sdp", "ssrcs", "simulcast", "update", "plugindata",
	"ack", "hint", "candidates", "plugins", "status", "timeout", "debug", "timestamps", "colors",
	"request", "response", "transaction", "list_sessions", "add_token", "allow_token", "disallow_token",
	"remove_token", "list_handles", "handle_info", "got-offer", "got-answer", "processing-offer", "starting",
	"ice-restart", "ready", "stopped", "alerts", "all-tickles", "data-channels", "cleaning", "flags",
	"ice-mode", "ice-role", "agent-created", "lite", "full", "controlling", "controlled", "profile",
	"remote", "sdps", "pending-trickles", "queued-packets", "video-rtx", "audio-peer", "video-peer",
	"audio-send", "audio-recv", "video-pt", "video-send", "video-recv", "direction", "audio-pt", "twcc",
	"codecs", "codec", "video-codec", "audio-codec", "base", "rtt", "lost", "lost-by-remote", "jitter-local", "jitter-remote",
	"rtcp_stats", "components", "local-candidates", "remote-candidates", "selected-pair",
	"remote-fingerprint", "remote-fingerprint-hash", "dtls-role", "dtls-state", "retransmissions", "valid",
	"handshake-started", "connected", "audio_packets", "audio_bytes", "video_bytes_lastsec", "video_nacks",
	"do_video_nacks", "video-simulcast-1", "video-simulcast-2", "data_packets", "data_bytes", "event", "sender",
	"debug_level", "stun_server", "server_port", "dtls_timeout", "cert_pem", "cert_key", "cert_pwd", "dtls_mtu",
	"ccm fir", "ccm tmmbr", "ccm tstr", "ccm vbcm", "nack pli", "nack sli", "nack rpsi", "transport cc", "good-remb",
	"level-asymmetry-allowed", "packetization-mode", "profile-level", "opus", "H264", "VP8", "VP9"
};

constexpr USTRING DateStrings[] = {
	"January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December",
	"Jan", "Feb", "Mar", "Apr", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
	"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday",
	"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat",
	"GMT", "AST", "EST", "EDT", "CST", "CDT", "MST", "MDT", "PST", "PDT", "AKST", "AKDT", "HST", "HAST", "HADT", "SST", "SDT", "CHST",
	"1st", "2nd", "3rd", "4th", "5th", "6th", "7th", "8th", "9th", "10th", "11th", "12th", "13th", "14th", "15th", "16th", "17th", "18th", "19th", "20th",
	"21st", "22nd", "23rd", "24th", "25th", "26th", "27th", "28th", "29th", "30th", "31st",
	"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27",
	"28", "29", "30", "31",
	"AM", "PM", "01", "02", "03", "04", "05", "06", "07", "08", "09",
	"1990", "1991", "1992", "1993", "1994", "1995", "1996", "1997", "1998", "1999",
	"2000", "2001", "2002", "2003", "2004", "2005", "2006", "2007", "2008", "2009",
	"2010", "2011", "2012", "2013", "2014", "2015", "2016", "2017", "2018", "2019",
	"2020", "2021", "2022", "2023", "2024", "2025", "2026", "2027", "2028", "2029",
};

//constexpr USTRING StpStrings[] = {
//	"Hostname", "Public Key", "Symmetric Key", "Private Key", "IPv4 Address", "IPv6 Address", "Init", "Init Ack",
//	"SACK", "Shutdown", "Shutdown Ack", "Shutdown Complete", "Heartbeat Request", "Heartbeat Ack", "Abort", "Data",
//	"Message", "Header", "Body", "Object Id", "Time Offset", "GUID", "Hello", "MAC address", "Session Id", "Receive Bandwidth",
//	"Transmit Bandwidth",
//};

constexpr USTRING CryptoStrings[] = {
	"KeyShare", "AES128", "AES256", "ECDH_x25519", "SHA256", "ECDSA", 
};

constexpr USTRING SyncStrings[] = {
	"Init", "Init_Ack", "Data", "Shutdown", "ShutdownAck", "SystemId", "MacAddress", "Destination", "Source",
	"KeyShare", "AES128", "AES256", "ECDH_x25519", "SHA256", "ECDSA",
	"track", "cluster time", "metadata", "frame", "append", "change", "remove", 
};

//constexpr USTRING BrassStrings[] = { "shell", "navigation", };
//
//constexpr USTRING PercentNames[] = { "0", "0.1", "0.01", "0.2", "0.25", "0.3", "0.4", "0.5", "0.75", "1", "2", "3", "4", "5", "6", "7", "8", "9",
//"10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32", "33",
//"34", "35", "36", "37", "38", "39", "40", "41", "42", "43", "44", "45", "46", "47", "48", "49",
//"50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "70", "71", "72", "73",
//"74", "75", "76", "77", "78", "79", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89",
//"90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "99.9", "99.99", "99.999", "100", "110", "200",
//};
//
//constexpr USTRING ScaleStrings[] = {
//	"hour", "minute", "second", "day", "month", "year",
//	"city", "state", "country", "zipcode", "street", "floor", "room", "building",
//	"phone", "phone-area", "phone-exchange", "phone-number",
//	"name", "firstname", "lastname",
//};
//
//constexpr USTRING UnitStrings[] = {
//	"January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December",
//	"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
//	"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday",
//	"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat",
//	"1st", "2nd", "3rd", "4th", "5th", "6th", "7th", "8th", "9th", "10th", "11th", "12th", "13th", "14th", "15th", "16th", "17th", "18th", "19th",
//	"20th", "21st", "22nd", "23rd", "24th", "25th", "26th", "27th", "28th", "29th", "30th", "31st",
//};
//
//constexpr USTRING SchoolStrings[] = {
//	"advisee", "name", "timeFrom", "timeTo", "courseId", "courseName", "room", "day", "email", "studentId", "phone", "subject", "date", "amount", "payment", "inbox",
//	"adviseeList", "paymentInfo", "class", "classSchedule", "messages", "message", "testSchedule", "data", "semester", "studentThumbnail", "charge", "item",
//};
//
//constexpr USTRING NewsAppStrings[] = {
//	"article", "paragraph", "textrun", "comment", "date", "author", "title", "quote", "style", "italic", "hyperlink",
//};
//
//constexpr USTRING CommonEnglishWords[] = {
//
//	"the", "of", "and", "a", "is", "in", "to", "have", "be", "for", "not", "that", "on", "as", "at", "by", "this", "do",
//	"from", "or", "an", "into", "up", "over",
//};

constexpr USTRING NumberStrings[] = { "00", "01", "02", "03", "04", "05", "06", "07", "08", "09",
"500", "600", "700", "750", "800", "900", "1000",
"2500", "3000", "4000", "5000", "6000", "7000", "7500", "8000", "9000", "10000",
"100000", "1000000", "10000000", "100000000", "1000000000" };

constexpr USTRING MkvStrings[] = {
	"EBML", "EBMLVersion", "EBMLReadVersion", "EBMLMaxIdLength", "EBMLMaxSizeLength", "EBMLDocType", "EBMLDocTypeVersion", 
	"EBMLDocTypeReadVersion", "EBMLCrc32", "EBMLVoid", "Segment", "SeekHead", "Info", "Cluster", "Tracks", "Cues", "Attachments", 
	"Chapters", "Tags", "Seek", "SeekID", "SeekPosition", "SegmentUID", "SegmentFilename", 
	"PrevUID", "PrevFilename", "NextUID", "NextFilename", "SegmentFamily", "ChapterTranslate", 
	"TimecodeScale", "Duration", "DateUTC", "Title", "MuxingApp", "WritingApp", "ChapterTranslateEditionUID", 
	"ChapterTranslateCodec", "ChapterTranslateID", "ClusterTimecode", "ClusterSilentTracks", "ClusterPosition", 
	"ClusterPrevSize", "SimpleBlock", "BlockGroup", "EncryptedBlock", "ClusterSilentTrackNumber", 
	"Block", "BlockVirtual", "BlockAdditions", "BlockDuration", "ReferencePriority", "ReferenceBlock", 
	"ReferenceVirtual", "CodecState", "DiscardPadding", "Slices", "ReferenceFrame", "BlockMore", "BlockAddID", 
	"BlockAdditional", "TimeSlice", "SliceLaceNumber", "SliceFrameNumber", "SliceBlockAddID",  "SliceDelay",  
	"SliceDuration", "ReferenceOffset", "ReferenceTimeCode", "TrackEntry", "TrackNumber", "TrackUID", 
	"TrackType", "TrackFlagEnabled", "TrackFlagDefault", "TrackFlagForced", "TrackFlagLacing", "TrackMinCache", 
	"TrackMaxCache", "TrackDefaultDuration", "TrackDefaultDecodedFieldDuration", "TrackTimecodeScale", "TrackOffset", 
	"MaxBlockAdditionID", "TrackName", "TrackLanguage", "LanguageIETF", "CodecID", "CodecPrivate", 
	"CodecName", "TrackAttachmentLink", "CodecSettings", "CodecInfoURL", "CodecDownloadURL", "CodecDecodeAll", 
	"TrackOverlay", "CodecDelay", "SeekPreRoll", "TrackTranslate", "TrackVideo", "TrackAudio", "TrackOperation", 
	"TrickTrackUID", "TrickTrackSegmentUID", "TrickTrackFlag", "TrickMasterTrackUID", "TrickMasterTrackSegmentUID", 
	"ContentEncodings", "TrackTranslateEditionUID", "TrackTranslateCodec", "TrackTranslateTrackID", "VideoFlagInterlaced", 
	"VideoFieldOrder", "VideoStereoMode", "VideoAlphaMode", "OldStereoMode",  "VideoPixelWidth", "VideoPixelHeight", 
	"VideoPixelCropBottom", "VideoPixelCropTop", "VideoPixelCropLeft", "VideoPixelCropRight", "VideoDisplayWidth", 
	"VideoDisplayHeight", "VideoDisplayUnit", "VideoAspectRatio", "VideoColourSpace", "VideoGamma", 
	"VideoFrameRate", "VideoColour", "VideoProjection", "VideoColourMatrix", "VideoBitsPerChannel", "VideoChromaSubsampHorz", 
	"VideoChromaSubsampVert", "VideoCbSubsampHorz", "VideoCbSubsampVert", "VideoChromaSitHorz", "VideoChromaSitVert", 
	"VideoColourRange", "VideoColourTransferCharacter", "VideoColourPrimaries", "VideoColourMaxCLL", "VideoColourMaxFALL", 
	"VideoColourMasterMeta", "VideoRChromaX", "VideoRChromaY", "VideoGChromaX", "VideoGChromaY", "VideoBChromaX", 
	"VideoBChromaY", "VideoWhitePointChromaX", "VideoWhitePointChromaY", "VideoLuminanceMax", "VideoLuminanceMin", 
	"VideoProjectionType", "VideoProjectionPrivate", "VideoProjectionPoseYaw", "VideoProjectionPosePitch", "VideoProjectionPoseRoll", 
	"AudioSamplingFreq", "AudioOutputSamplingFreq", "AudioChannels", "AudioPosition", "AudioBitDepth", "TrackCombinePlanes", 
	"TrackJoinBlocks", "TrackPlane", "TrackPlaneUID", "TrackPlaneType", "TrackJoinUID", "ContentEncoding", 
	"ContentEncodingOrder", "ContentEncodingScope", "ContentEncodingType", "ContentCompression", "ContentEncryption", 
	"ContentCompAlgo", "ContentCompSettings", "ContentEncAlgo", "ContentEncKeyID", "ContentSignature", "ContentSigKeyID", 
	"ContentSigAlgo", "ContentSigHashAlgo", "CuePoint", "CueTime", "CueTrackPositions", "CueTrack", 
	"CueClusterPosition", "CueRelativePosition", "CueDuration", "CueBlockNumber", "CueCodecState", "CueReference", 
	"CueRefTime", "CueRefCluster",  "CueRefNumber",  "CueRefCodecState", "Attached", "FileDescription", "FileName", 
	"MimeType", "FileData", "FileUID", "FileReferral", "FileUsedStartTime", "FileUsedEndTime", "EditionEntry", 
	"EditionUID", "EditionFlagHidden", "EditionFlagDefault", "EditionFlagOrdered", "ChapterAtom", "ChapterUID", 
	"ChapterStringUID", "ChapterTimeStart", "ChapterTimeEnd", "ChapterFlagHidden", "ChapterFlagEnabled", "ChapterSegmentUID", 
	"ChapterSegmentEditionUID", "ChapterPhysicalEquiv", 	"ChapterTrack", "ChapterDisplay", "ChapterProcess", 
	"ChapterTrackNumber", "ChapterString", "ChapterLanguage", "ChapLanguageIETF", "ChapterCountry", "ChapterProcessCodecID", 
	"ChapterProcessPrivate", "ChapterProcessCommand", "ChapterProcessTime", "ChapterProcessData", "Tag", "TagTargets", 
	"TagSimple", "TagTargetTypeValue", "TagTargetType", "TagTrackUID", "TagEditionUID", "TagChapterUID", "TagAttachmentUID", 
	"TagName", "TagLangue", "TagLanguageIETF", "TagDefault", "TagString", "TagBinary", 
	"video", "audio", "subtitle", "V_MPEG4/ISO/AVC", "A_EAC3", "A_OPUS", 
};

struct NAME_PAIR
{
	USTRING name;
	USTRING value;
};

constexpr NAME_PAIR RtpExtNames[] = {
	{ "TOFFSET", "urn:ietf:params:rtp-hdrext:toffset"},
	{ "SENDTIME", "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time"},
	{ "VIDEO_ORIENTATION", "urn:3gpp:video-orientation"},
	{ "CONGESTION_CONTROL", "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"},
	{ "PLAYOUT_DELAY", "http://www.webrtc.org/experiments/rtp-hdrext/playout-delay"},
	{ "VIDEO_CONTENT_TYPE", "http://www.webrtc.org/experiments/rtp-hdrext/video-content-type"},
	{ "VIDEO_TIMING", "http://www.webrtc.org/experiments/rtp-hdrext/video-timing"},
	{ "FRAME_MARKING", "http://tools.ietf.org/html/draft-ietf-avtext-framemarking-07"},
	{ "COLOR_SPACE", "http://www.webrtc.org/experiments/rtp-hdrext/color-space"},
	{ "MID", "urn:ietf:params:rtp-hdrext:sdes:mid"},
	{ "RID", "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id"},
	{ "RRID", "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id"},
	{ "AUDIO_LEVEL", "urn:ietf:params:rtp-hdrext:ssrc-audio-level"},
};

extern void PopulateNames();
void NameInitialize()
{
	PopulateNames();
}

