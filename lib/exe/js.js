var _____WB$wombat$assign$function_____ = function (name) {
    return (self._wb_wombat && self._wb_wombat.local_init && self._wb_wombat.local_init(name)) || self[name];
};
if (!self.__WB_pmw) {
    self.__WB_pmw = function (obj) {
        this.__WB_source = obj;
        return this;
    };
}
{
    let window = _____WB$wombat$assign$function_____("window");
    let self = _____WB$wombat$assign$function_____("self");
    let document = _____WB$wombat$assign$function_____("document");
    let location = _____WB$wombat$assign$function_____("location");
    let top = _____WB$wombat$assign$function_____("top");
    let parent = _____WB$wombat$assign$function_____("parent");
    let frames = _____WB$wombat$assign$function_____("frames");
    let opener = _____WB$wombat$assign$function_____("opener");

    var DOKU_BASE = "/";
    var DOKU_TPL = "/lib/tpl/dokuwiki/";
    var DOKU_COOKIE_PARAM = { path: "/", secure: false };
    var DOKU_UHN = 0;
    var DOKU_UHC = 0;
    LANG = {
        willexpire:
            "Your lock for editing this page is about to expire in a minute.\\nTo avoid conflicts use the preview button to reset the locktimer.",
        notsavedyet: "Unsaved changes will be lost.",
        searchmedia: "Search for files",
        keepopen: "Keep window open on selection",
        hidedetails: "Hide Details",
        mediatitle: "Link settings",
        mediadisplay: "Link type",
        mediaalign: "Alignment",
        mediasize: "Image size",
        mediatarget: "Link target",
        mediaclose: "Close",
        mediainsert: "Insert",
        mediadisplayimg: "Show the image.",
        mediadisplaylnk: "Show only the link.",
        mediasmall: "Small version",
        mediamedium: "Medium version",
        medialarge: "Large version",
        mediaoriginal: "Original version",
        medialnk: "Link to detail page",
        mediadirect: "Direct link to original",
        medianolnk: "No link",
        medianolink: "Do not link the image",
        medialeft: "Align the image on the left.",
        mediaright: "Align the image on the right.",
        mediacenter: "Align the image in the middle.",
        medianoalign: "Use no align.",
        nosmblinks:
            "Linking to Windows shares only works in Microsoft Internet Explorer.\\nYou still can copy and paste the link.",
        linkwiz: "Link Wizard",
        linkto: "Link to:",
        del_confirm: "Really delete selected item(s)?",
        restore_confirm: "Really restore this version?",
        media_diff: "View differences:",
        media_diff_both: "Side by Side",
        media_diff_opacity: "Shine-through",
        media_diff_portions: "Swipe",
        media_select: "Select files\u2026",
        media_upload_btn: "Upload",
        media_done_btn: "Done",
        media_drop: "Drop files here to upload",
        media_cancel: "remove",
        media_overwrt: "Overwrite existing files",
        plugins: [],
    };
    var toolbar = [
        { type: "format", title: "Bold Text", icon: "bold.png", key: "b", open: "**", close: "**", block: false },
        { type: "format", title: "Italic Text", icon: "italic.png", key: "i", open: "//", close: "//", block: false },
        {
            type: "format",
            title: "Underlined Text",
            icon: "underline.png",
            key: "u",
            open: "__",
            close: "__",
            block: false,
        },
        { type: "format", title: "Code Text", icon: "mono.png", key: "c", open: "''", close: "''", block: false },
        {
            type: "format",
            title: "Strike-through Text",
            icon: "strike.png",
            key: "d",
            open: "<del>",
            close: "</del>",
            block: false,
        },
        {
            type: "autohead",
            title: "Same Level Headline",
            icon: "hequal.png",
            key: "8",
            text: "Headline",
            mod: 0,
            block: true,
        },
        {
            type: "autohead",
            title: "Lower Headline",
            icon: "hminus.png",
            key: "9",
            text: "Headline",
            mod: 1,
            block: true,
        },
        {
            type: "autohead",
            title: "Higher Headline",
            icon: "hplus.png",
            key: "0",
            text: "Headline",
            mod: -1,
            block: true,
        },
        {
            type: "picker",
            title: "Select Headline",
            icon: "h.png",
            class: "pk_hl",
            list: [
                {
                    type: "format",
                    title: "Level 1 Headline",
                    icon: "h1.png",
                    key: "1",
                    open: "====== ",
                    close: " ======\\n",
                },
                {
                    type: "format",
                    title: "Level 2 Headline",
                    icon: "h2.png",
                    key: "2",
                    open: "===== ",
                    close: " =====\\n",
                },
                {
                    type: "format",
                    title: "Level 3 Headline",
                    icon: "h3.png",
                    key: "3",
                    open: "==== ",
                    close: " ====\\n",
                },
                { type: "format", title: "Level 4 Headline", icon: "h4.png", key: "4", open: "=== ", close: " ===\\n" },
                { type: "format", title: "Level 5 Headline", icon: "h5.png", key: "5", open: "== ", close: " ==\\n" },
            ],
            block: true,
        },
        { type: "linkwiz", title: "Internal Link", icon: "link.png", key: "l", open: "[[", close: "]]", block: false },
        {
            type: "format",
            title: "External Link",
            icon: "linkextern.png",
            open: "[[",
            close: "]]",
            sample: "http://example.com|External Link",
            block: false,
        },
        {
            type: "formatln",
            title: "Ordered List Item",
            icon: "ol.png",
            open: "  - ",
            close: "",
            key: "-",
            block: true,
        },
        {
            type: "formatln",
            title: "Unordered List Item",
            icon: "ul.png",
            open: "  * ",
            close: "",
            key: ".",
            block: true,
        },
        { type: "insert", title: "Horizontal Rule", icon: "hr.png", insert: "\\n----\\n", block: true },
        {
            type: "mediapopup",
            title: "Add Images and other files (opens in a new window)",
            icon: "image.png",
            url: "lib/exe/mediamanager.php?ns=",
            name: "mediaselect",
            options: "width=750,height=500,left=20,top=20,scrollbars=yes,resizable=yes",
            block: false,
        },
        {
            type: "picker",
            title: "Smileys",
            icon: "smiley.png",
            list: {
                "8-)": "icon_cool.gif",
                "8-O": "icon_eek.gif",
                "8-o": "icon_eek.gif",
                ":-(": "icon_sad.gif",
                ":-)": "icon_smile.gif",
                "=)": "icon_smile2.gif",
                ":-/": "icon_doubt.gif",
                ":-\\": "icon_doubt2.gif",
                ":-?": "icon_confused.gif",
                ":-D": "icon_biggrin.gif",
                ":-P": "icon_razz.gif",
                ":-o": "icon_surprised.gif",
                ":-O": "icon_surprised.gif",
                ":-x": "icon_silenced.gif",
                ":-X": "icon_silenced.gif",
                ":-|": "icon_neutral.gif",
                ";-)": "icon_wink.gif",
                "m(": "facepalm.gif",
                "^_^": "icon_fun.gif",
                ":?:": "icon_question.gif",
                ":!:": "icon_exclaim.gif",
                LOL: "icon_lol.gif",
                FIXME: "fixme.gif",
                DELETEME: "delete.gif",
            },
            icobase: "smileys",
            block: false,
        },
        {
            type: "picker",
            title: "Special Chars",
            icon: "chars.png",
            list: [
                "\u00c0",
                "\u00e0",
                "\u00c1",
                "\u00e1",
                "\u00c2",
                "\u00e2",
                "\u00c3",
                "\u00e3",
                "\u00c4",
                "\u00e4",
                "\u01cd",
                "\u01ce",
                "\u0102",
                "\u0103",
                "\u00c5",
                "\u00e5",
                "\u0100",
                "\u0101",
                "\u0104",
                "\u0105",
                "\u00c6",
                "\u00e6",
                "\u0106",
                "\u0107",
                "\u00c7",
                "\u00e7",
                "\u010c",
                "\u010d",
                "\u0108",
                "\u0109",
                "\u010a",
                "\u010b",
                "\u00d0",
                "\u0111",
                "\u00f0",
                "\u010e",
                "\u010f",
                "\u00c8",
                "\u00e8",
                "\u00c9",
                "\u00e9",
                "\u00ca",
                "\u00ea",
                "\u00cb",
                "\u00eb",
                "\u011a",
                "\u011b",
                "\u0112",
                "\u0113",
                "\u0116",
                "\u0117",
                "\u0118",
                "\u0119",
                "\u0122",
                "\u0123",
                "\u011c",
                "\u011d",
                "\u011e",
                "\u011f",
                "\u0120",
                "\u0121",
                "\u0124",
                "\u0125",
                "\u00cc",
                "\u00ec",
                "\u00cd",
                "\u00ed",
                "\u00ce",
                "\u00ee",
                "\u00cf",
                "\u00ef",
                "\u01cf",
                "\u01d0",
                "\u012a",
                "\u012b",
                "\u0130",
                "\u0131",
                "\u012e",
                "\u012f",
                "\u0134",
                "\u0135",
                "\u0136",
                "\u0137",
                "\u0139",
                "\u013a",
                "\u013b",
                "\u013c",
                "\u013d",
                "\u013e",
                "\u0141",
                "\u0142",
                "\u013f",
                "\u0140",
                "\u0143",
                "\u0144",
                "\u00d1",
                "\u00f1",
                "\u0145",
                "\u0146",
                "\u0147",
                "\u0148",
                "\u00d2",
                "\u00f2",
                "\u00d3",
                "\u00f3",
                "\u00d4",
                "\u00f4",
                "\u00d5",
                "\u00f5",
                "\u00d6",
                "\u00f6",
                "\u01d1",
                "\u01d2",
                "\u014c",
                "\u014d",
                "\u0150",
                "\u0151",
                "\u0152",
                "\u0153",
                "\u00d8",
                "\u00f8",
                "\u0154",
                "\u0155",
                "\u0156",
                "\u0157",
                "\u0158",
                "\u0159",
                "\u015a",
                "\u015b",
                "\u015e",
                "\u015f",
                "\u0160",
                "\u0161",
                "\u015c",
                "\u015d",
                "\u0162",
                "\u0163",
                "\u0164",
                "\u0165",
                "\u00d9",
                "\u00f9",
                "\u00da",
                "\u00fa",
                "\u00db",
                "\u00fb",
                "\u00dc",
                "\u00fc",
                "\u01d3",
                "\u01d4",
                "\u016c",
                "\u016d",
                "\u016a",
                "\u016b",
                "\u016e",
                "\u016f",
                "\u01d6",
                "\u01d8",
                "\u01da",
                "\u01dc",
                "\u0172",
                "\u0173",
                "\u0170",
                "\u0171",
                "\u0174",
                "\u0175",
                "\u00dd",
                "\u00fd",
                "\u0178",
                "\u00ff",
                "\u0176",
                "\u0177",
                "\u0179",
                "\u017a",
                "\u017d",
                "\u017e",
                "\u017b",
                "\u017c",
                "\u00de",
                "\u00fe",
                "\u00df",
                "\u0126",
                "\u0127",
                "\u00bf",
                "\u00a1",
                "\u00a2",
                "\u00a3",
                "\u00a4",
                "\u00a5",
                "\u20ac",
                "\u00a6",
                "\u00a7",
                "\u00aa",
                "\u00ac",
                "\u00af",
                "\u00b0",
                "\u00b1",
                "\u00f7",
                "\u2030",
                "\u00bc",
                "\u00bd",
                "\u00be",
                "\u00b9",
                "\u00b2",
                "\u00b3",
                "\u00b5",
                "\u00b6",
                "\u2020",
                "\u2021",
                "\u00b7",
                "\u2022",
                "\u00ba",
                "\u2200",
                "\u2202",
                "\u2203",
                "\u018f",
                "\u0259",
                "\u2205",
                "\u2207",
                "\u2208",
                "\u2209",
                "\u220b",
                "\u220f",
                "\u2211",
                "\u203e",
                "\u2212",
                "\u2217",
                "\u00d7",
                "\u2044",
                "\u221a",
                "\u221d",
                "\u221e",
                "\u2220",
                "\u2227",
                "\u2228",
                "\u2229",
                "\u222a",
                "\u222b",
                "\u2234",
                "\u223c",
                "\u2245",
                "\u2248",
                "\u2260",
                "\u2261",
                "\u2264",
                "\u2265",
                "\u2282",
                "\u2283",
                "\u2284",
                "\u2286",
                "\u2287",
                "\u2295",
                "\u2297",
                "\u22a5",
                "\u22c5",
                "\u25ca",
                "\u2118",
                "\u2111",
                "\u211c",
                "\u2135",
                "\u2660",
                "\u2663",
                "\u2665",
                "\u2666",
                "\u03b1",
                "\u03b2",
                "\u0393",
                "\u03b3",
                "\u0394",
                "\u03b4",
                "\u03b5",
                "\u03b6",
                "\u03b7",
                "\u0398",
                "\u03b8",
                "\u03b9",
                "\u03ba",
                "\u039b",
                "\u03bb",
                "\u03bc",
                "\u039e",
                "\u03be",
                "\u03a0",
                "\u03c0",
                "\u03c1",
                "\u03a3",
                "\u03c3",
                "\u03a4",
                "\u03c4",
                "\u03c5",
                "\u03a6",
                "\u03c6",
                "\u03c7",
                "\u03a8",
                "\u03c8",
                "\u03a9",
                "\u03c9",
                "\u2605",
                "\u2606",
                "\u260e",
                "\u261a",
                "\u261b",
                "\u261c",
                "\u261d",
                "\u261e",
                "\u261f",
                "\u2639",
                "\u263a",
                "\u2714",
                "\u2718",
                "\u201e",
                "\u201c",
                "\u201d",
                "\u201a",
                "\u2018",
                "\u2019",
                "\u00ab",
                "\u00bb",
                "\u2039",
                "\u203a",
                "\u2014",
                "\u2013",
                "\u2026",
                "\u2190",
                "\u2191",
                "\u2192",
                "\u2193",
                "\u2194",
                "\u21d0",
                "\u21d1",
                "\u21d2",
                "\u21d3",
                "\u21d4",
                "\u00a9",
                "\u2122",
                "\u00ae",
                "\u2032",
                "\u2033",
                "[",
                "]",
                "{",
                "}",
                "~",
                "(",
                ")",
                "%",
                "\u00a7",
                "$",
                "#",
                "|",
                "@",
            ],
            block: false,
        },
        { type: "signature", title: "Insert Signature", icon: "sig.png", key: "y", block: false },
    ];
    /*! jQuery v1.9.1 | (c) 2005, 2012 jQuery Foundation, Inc. | jquery.org/license
//@ sourceMappingURL=jquery.min.map
*/ (function (e, t) {
        var n,
            r,
            i = typeof t,
            o = e.document,
            a = e.location,
            s = e.jQuery,
            u = e.$,
            l = {},
            c = [],
            p = "1.9.1",
            f = c.concat,
            d = c.push,
            h = c.slice,
            g = c.indexOf,
            m = l.toString,
            y = l.hasOwnProperty,
            v = p.trim,
            b = function (e, t) {
                return new b.fn.init(e, t, r);
            },
            x = /[+-]?(?:\d*\.|)\d+(?:[eE][+-]?\d+|)/.source,
            w = /\S+/g,
            T = /^[\s\uFEFF\xA0]+|[\s\uFEFF\xA0]+$/g,
            N = /^(?:(<[\w\W]+>)[^>]*|#([\w-]*))$/,
            C = /^<(\w+)\s*\/?>(?:<\/\1>|)$/,
            k = /^[\],:{}\s]*$/,
            E = /(?:^|:|,)(?:\s*\[)+/g,
            S = /\\(?:["\\\/bfnrt]|u[\da-fA-F]{4})/g,
            A = /"[^"\\\r\n]*"|true|false|null|-?(?:\d+\.|)\d+(?:[eE][+-]?\d+|)/g,
            j = /^-ms-/,
            D = /-([\da-z])/gi,
            L = function (e, t) {
                return t.toUpperCase();
            },
            H = function (e) {
                (o.addEventListener || "load" === e.type || "complete" === o.readyState) && (q(), b.ready());
            },
            q = function () {
                o.addEventListener
                    ? (o.removeEventListener("DOMContentLoaded", H, !1), e.removeEventListener("load", H, !1))
                    : (o.detachEvent("onreadystatechange", H), e.detachEvent("onload", H));
            };
        (b.fn = b.prototype =
            {
                jquery: p,
                constructor: b,
                init: function (e, n, r) {
                    var i, a;
                    if (!e) return this;
                    if ("string" == typeof e) {
                        if (
                            ((i =
                                "<" === e.charAt(0) && ">" === e.charAt(e.length - 1) && e.length >= 3
                                    ? [null, e, null]
                                    : N.exec(e)),
                            !i || (!i[1] && n))
                        )
                            return !n || n.jquery ? (n || r).find(e) : this.constructor(n).find(e);
                        if (i[1]) {
                            if (
                                ((n = n instanceof b ? n[0] : n),
                                b.merge(this, b.parseHTML(i[1], n && n.nodeType ? n.ownerDocument || n : o, !0)),
                                C.test(i[1]) && b.isPlainObject(n))
                            )
                                for (i in n) b.isFunction(this[i]) ? this[i](n[i]) : this.attr(i, n[i]);
                            return this;
                        }
                        if (((a = o.getElementById(i[2])), a && a.parentNode)) {
                            if (a.id !== i[2]) return r.find(e);
                            (this.length = 1), (this[0] = a);
                        }
                        return (this.context = o), (this.selector = e), this;
                    }
                    return e.nodeType
                        ? ((this.context = this[0] = e), (this.length = 1), this)
                        : b.isFunction(e)
                          ? r.ready(e)
                          : (e.selector !== t && ((this.selector = e.selector), (this.context = e.context)),
                            b.makeArray(e, this));
                },
                selector: "",
                length: 0,
                size: function () {
                    return this.length;
                },
                toArray: function () {
                    return h.call(this);
                },
                get: function (e) {
                    return null == e ? this.toArray() : 0 > e ? this[this.length + e] : this[e];
                },
                pushStack: function (e) {
                    var t = b.merge(this.constructor(), e);
                    return (t.prevObject = this), (t.context = this.context), t;
                },
                each: function (e, t) {
                    return b.each(this, e, t);
                },
                ready: function (e) {
                    return b.ready.promise().done(e), this;
                },
                slice: function () {
                    return this.pushStack(h.apply(this, arguments));
                },
                first: function () {
                    return this.eq(0);
                },
                last: function () {
                    return this.eq(-1);
                },
                eq: function (e) {
                    var t = this.length,
                        n = +e + (0 > e ? t : 0);
                    return this.pushStack(n >= 0 && t > n ? [this[n]] : []);
                },
                map: function (e) {
                    return this.pushStack(
                        b.map(this, function (t, n) {
                            return e.call(t, n, t);
                        })
                    );
                },
                end: function () {
                    return this.prevObject || this.constructor(null);
                },
                push: d,
                sort: [].sort,
                splice: [].splice,
            }),
            (b.fn.init.prototype = b.fn),
            (b.extend = b.fn.extend =
                function () {
                    var e,
                        n,
                        r,
                        i,
                        o,
                        a,
                        s = arguments[0] || {},
                        u = 1,
                        l = arguments.length,
                        c = !1;
                    for (
                        "boolean" == typeof s && ((c = s), (s = arguments[1] || {}), (u = 2)),
                            "object" == typeof s || b.isFunction(s) || (s = {}),
                            l === u && ((s = this), --u);
                        l > u;
                        u++
                    )
                        if (null != (o = arguments[u]))
                            for (i in o)
                                (e = s[i]),
                                    (r = o[i]),
                                    s !== r &&
                                        (c && r && (b.isPlainObject(r) || (n = b.isArray(r)))
                                            ? (n
                                                  ? ((n = !1), (a = e && b.isArray(e) ? e : []))
                                                  : (a = e && b.isPlainObject(e) ? e : {}),
                                              (s[i] = b.extend(c, a, r)))
                                            : r !== t && (s[i] = r));
                    return s;
                }),
            b.extend({
                noConflict: function (t) {
                    return e.$ === b && (e.$ = u), t && e.jQuery === b && (e.jQuery = s), b;
                },
                isReady: !1,
                readyWait: 1,
                holdReady: function (e) {
                    e ? b.readyWait++ : b.ready(!0);
                },
                ready: function (e) {
                    if (e === !0 ? !--b.readyWait : !b.isReady) {
                        if (!o.body) return setTimeout(b.ready);
                        (b.isReady = !0),
                            (e !== !0 && --b.readyWait > 0) ||
                                (n.resolveWith(o, [b]), b.fn.trigger && b(o).trigger("ready").off("ready"));
                    }
                },
                isFunction: function (e) {
                    return "function" === b.type(e);
                },
                isArray:
                    Array.isArray ||
                    function (e) {
                        return "array" === b.type(e);
                    },
                isWindow: function (e) {
                    return null != e && e == e.window;
                },
                isNumeric: function (e) {
                    return !isNaN(parseFloat(e)) && isFinite(e);
                },
                type: function (e) {
                    return null == e
                        ? e + ""
                        : "object" == typeof e || "function" == typeof e
                          ? l[m.call(e)] || "object"
                          : typeof e;
                },
                isPlainObject: function (e) {
                    if (!e || "object" !== b.type(e) || e.nodeType || b.isWindow(e)) return !1;
                    try {
                        if (
                            e.constructor &&
                            !y.call(e, "constructor") &&
                            !y.call(e.constructor.prototype, "isPrototypeOf")
                        )
                            return !1;
                    } catch (n) {
                        return !1;
                    }
                    var r;
                    for (r in e);
                    return r === t || y.call(e, r);
                },
                isEmptyObject: function (e) {
                    var t;
                    for (t in e) return !1;
                    return !0;
                },
                error: function (e) {
                    throw Error(e);
                },
                parseHTML: function (e, t, n) {
                    if (!e || "string" != typeof e) return null;
                    "boolean" == typeof t && ((n = t), (t = !1)), (t = t || o);
                    var r = C.exec(e),
                        i = !n && [];
                    return r
                        ? [t.createElement(r[1])]
                        : ((r = b.buildFragment([e], t, i)), i && b(i).remove(), b.merge([], r.childNodes));
                },
                parseJSON: function (n) {
                    return e.JSON && e.JSON.parse
                        ? e.JSON.parse(n)
                        : null === n
                          ? n
                          : "string" == typeof n &&
                              ((n = b.trim(n)), n && k.test(n.replace(S, "@").replace(A, "]").replace(E, "")))
                            ? Function("return " + n)()
                            : (b.error("Invalid JSON: " + n), t);
                },
                parseXML: function (n) {
                    var r, i;
                    if (!n || "string" != typeof n) return null;
                    try {
                        e.DOMParser
                            ? ((i = new DOMParser()), (r = i.parseFromString(n, "text/xml")))
                            : ((r = new ActiveXObject("Microsoft.XMLDOM")), (r.async = "false"), r.loadXML(n));
                    } catch (o) {
                        r = t;
                    }
                    return (
                        (r && r.documentElement && !r.getElementsByTagName("parsererror").length) ||
                            b.error("Invalid XML: " + n),
                        r
                    );
                },
                noop: function () {},
                globalEval: function (t) {
                    t &&
                        b.trim(t) &&
                        (
                            e.execScript ||
                            function (t) {
                                e.eval.call(e, t);
                            }
                        )(t);
                },
                camelCase: function (e) {
                    return e.replace(j, "ms-").replace(D, L);
                },
                nodeName: function (e, t) {
                    return e.nodeName && e.nodeName.toLowerCase() === t.toLowerCase();
                },
                each: function (e, t, n) {
                    var r,
                        i = 0,
                        o = e.length,
                        a = M(e);
                    if (n) {
                        if (a) {
                            for (; o > i; i++) if (((r = t.apply(e[i], n)), r === !1)) break;
                        } else for (i in e) if (((r = t.apply(e[i], n)), r === !1)) break;
                    } else if (a) {
                        for (; o > i; i++) if (((r = t.call(e[i], i, e[i])), r === !1)) break;
                    } else for (i in e) if (((r = t.call(e[i], i, e[i])), r === !1)) break;
                    return e;
                },
                trim:
                    v && !v.call("\ufeff\u00a0")
                        ? function (e) {
                              return null == e ? "" : v.call(e);
                          }
                        : function (e) {
                              return null == e ? "" : (e + "").replace(T, "");
                          },
                makeArray: function (e, t) {
                    var n = t || [];
                    return null != e && (M(Object(e)) ? b.merge(n, "string" == typeof e ? [e] : e) : d.call(n, e)), n;
                },
                inArray: function (e, t, n) {
                    var r;
                    if (t) {
                        if (g) return g.call(t, e, n);
                        for (r = t.length, n = n ? (0 > n ? Math.max(0, r + n) : n) : 0; r > n; n++)
                            if (n in t && t[n] === e) return n;
                    }
                    return -1;
                },
                merge: function (e, n) {
                    var r = n.length,
                        i = e.length,
                        o = 0;
                    if ("number" == typeof r) for (; r > o; o++) e[i++] = n[o];
                    else while (n[o] !== t) e[i++] = n[o++];
                    return (e.length = i), e;
                },
                grep: function (e, t, n) {
                    var r,
                        i = [],
                        o = 0,
                        a = e.length;
                    for (n = !!n; a > o; o++) (r = !!t(e[o], o)), n !== r && i.push(e[o]);
                    return i;
                },
                map: function (e, t, n) {
                    var r,
                        i = 0,
                        o = e.length,
                        a = M(e),
                        s = [];
                    if (a) for (; o > i; i++) (r = t(e[i], i, n)), null != r && (s[s.length] = r);
                    else for (i in e) (r = t(e[i], i, n)), null != r && (s[s.length] = r);
                    return f.apply([], s);
                },
                guid: 1,
                proxy: function (e, n) {
                    var r, i, o;
                    return (
                        "string" == typeof n && ((o = e[n]), (n = e), (e = o)),
                        b.isFunction(e)
                            ? ((r = h.call(arguments, 2)),
                              (i = function () {
                                  return e.apply(n || this, r.concat(h.call(arguments)));
                              }),
                              (i.guid = e.guid = e.guid || b.guid++),
                              i)
                            : t
                    );
                },
                access: function (e, n, r, i, o, a, s) {
                    var u = 0,
                        l = e.length,
                        c = null == r;
                    if ("object" === b.type(r)) {
                        o = !0;
                        for (u in r) b.access(e, n, u, r[u], !0, a, s);
                    } else if (
                        i !== t &&
                        ((o = !0),
                        b.isFunction(i) || (s = !0),
                        c &&
                            (s
                                ? (n.call(e, i), (n = null))
                                : ((c = n),
                                  (n = function (e, t, n) {
                                      return c.call(b(e), n);
                                  }))),
                        n)
                    )
                        for (; l > u; u++) n(e[u], r, s ? i : i.call(e[u], u, n(e[u], r)));
                    return o ? e : c ? n.call(e) : l ? n(e[0], r) : a;
                },
                now: function () {
                    return new Date().getTime();
                },
            }),
            (b.ready.promise = function (t) {
                if (!n)
                    if (((n = b.Deferred()), "complete" === o.readyState)) setTimeout(b.ready);
                    else if (o.addEventListener)
                        o.addEventListener("DOMContentLoaded", H, !1), e.addEventListener("load", H, !1);
                    else {
                        o.attachEvent("onreadystatechange", H), e.attachEvent("onload", H);
                        var r = !1;
                        try {
                            r = null == e.frameElement && o.documentElement;
                        } catch (i) {}
                        r &&
                            r.doScroll &&
                            (function a() {
                                if (!b.isReady) {
                                    try {
                                        r.doScroll("left");
                                    } catch (e) {
                                        return setTimeout(a, 50);
                                    }
                                    q(), b.ready();
                                }
                            })();
                    }
                return n.promise(t);
            }),
            b.each("Boolean Number String Function Array Date RegExp Object Error".split(" "), function (e, t) {
                l["[object " + t + "]"] = t.toLowerCase();
            });
        function M(e) {
            var t = e.length,
                n = b.type(e);
            return b.isWindow(e)
                ? !1
                : 1 === e.nodeType && t
                  ? !0
                  : "array" === n || ("function" !== n && (0 === t || ("number" == typeof t && t > 0 && t - 1 in e)));
        }
        r = b(o);
        var _ = {};
        function F(e) {
            var t = (_[e] = {});
            return (
                b.each(e.match(w) || [], function (e, n) {
                    t[n] = !0;
                }),
                t
            );
        }
        (b.Callbacks = function (e) {
            e = "string" == typeof e ? _[e] || F(e) : b.extend({}, e);
            var n,
                r,
                i,
                o,
                a,
                s,
                u = [],
                l = !e.once && [],
                c = function (t) {
                    for (r = e.memory && t, i = !0, a = s || 0, s = 0, o = u.length, n = !0; u && o > a; a++)
                        if (u[a].apply(t[0], t[1]) === !1 && e.stopOnFalse) {
                            r = !1;
                            break;
                        }
                    (n = !1), u && (l ? l.length && c(l.shift()) : r ? (u = []) : p.disable());
                },
                p = {
                    add: function () {
                        if (u) {
                            var t = u.length;
                            (function i(t) {
                                b.each(t, function (t, n) {
                                    var r = b.type(n);
                                    "function" === r
                                        ? (e.unique && p.has(n)) || u.push(n)
                                        : n && n.length && "string" !== r && i(n);
                                });
                            })(arguments),
                                n ? (o = u.length) : r && ((s = t), c(r));
                        }
                        return this;
                    },
                    remove: function () {
                        return (
                            u &&
                                b.each(arguments, function (e, t) {
                                    var r;
                                    while ((r = b.inArray(t, u, r)) > -1)
                                        u.splice(r, 1), n && (o >= r && o--, a >= r && a--);
                                }),
                            this
                        );
                    },
                    has: function (e) {
                        return e ? b.inArray(e, u) > -1 : !(!u || !u.length);
                    },
                    empty: function () {
                        return (u = []), this;
                    },
                    disable: function () {
                        return (u = l = r = t), this;
                    },
                    disabled: function () {
                        return !u;
                    },
                    lock: function () {
                        return (l = t), r || p.disable(), this;
                    },
                    locked: function () {
                        return !l;
                    },
                    fireWith: function (e, t) {
                        return (
                            (t = t || []),
                            (t = [e, t.slice ? t.slice() : t]),
                            !u || (i && !l) || (n ? l.push(t) : c(t)),
                            this
                        );
                    },
                    fire: function () {
                        return p.fireWith(this, arguments), this;
                    },
                    fired: function () {
                        return !!i;
                    },
                };
            return p;
        }),
            b.extend({
                Deferred: function (e) {
                    var t = [
                            ["resolve", "done", b.Callbacks("once memory"), "resolved"],
                            ["reject", "fail", b.Callbacks("once memory"), "rejected"],
                            ["notify", "progress", b.Callbacks("memory")],
                        ],
                        n = "pending",
                        r = {
                            state: function () {
                                return n;
                            },
                            always: function () {
                                return i.done(arguments).fail(arguments), this;
                            },
                            then: function () {
                                var e = arguments;
                                return b
                                    .Deferred(function (n) {
                                        b.each(t, function (t, o) {
                                            var a = o[0],
                                                s = b.isFunction(e[t]) && e[t];
                                            i[o[1]](function () {
                                                var e = s && s.apply(this, arguments);
                                                e && b.isFunction(e.promise)
                                                    ? e.promise().done(n.resolve).fail(n.reject).progress(n.notify)
                                                    : n[a + "With"](
                                                          this === r ? n.promise() : this,
                                                          s ? [e] : arguments
                                                      );
                                            });
                                        }),
                                            (e = null);
                                    })
                                    .promise();
                            },
                            promise: function (e) {
                                return null != e ? b.extend(e, r) : r;
                            },
                        },
                        i = {};
                    return (
                        (r.pipe = r.then),
                        b.each(t, function (e, o) {
                            var a = o[2],
                                s = o[3];
                            (r[o[1]] = a.add),
                                s &&
                                    a.add(
                                        function () {
                                            n = s;
                                        },
                                        t[1 ^ e][2].disable,
                                        t[2][2].lock
                                    ),
                                (i[o[0]] = function () {
                                    return i[o[0] + "With"](this === i ? r : this, arguments), this;
                                }),
                                (i[o[0] + "With"] = a.fireWith);
                        }),
                        r.promise(i),
                        e && e.call(i, i),
                        i
                    );
                },
                when: function (e) {
                    var t = 0,
                        n = h.call(arguments),
                        r = n.length,
                        i = 1 !== r || (e && b.isFunction(e.promise)) ? r : 0,
                        o = 1 === i ? e : b.Deferred(),
                        a = function (e, t, n) {
                            return function (r) {
                                (t[e] = this),
                                    (n[e] = arguments.length > 1 ? h.call(arguments) : r),
                                    n === s ? o.notifyWith(t, n) : --i || o.resolveWith(t, n);
                            };
                        },
                        s,
                        u,
                        l;
                    if (r > 1)
                        for (s = Array(r), u = Array(r), l = Array(r); r > t; t++)
                            n[t] && b.isFunction(n[t].promise)
                                ? n[t]
                                      .promise()
                                      .done(a(t, l, n))
                                      .fail(o.reject)
                                      .progress(a(t, u, s))
                                : --i;
                    return i || o.resolveWith(l, n), o.promise();
                },
            }),
            (b.support = (function () {
                var t,
                    n,
                    r,
                    a,
                    s,
                    u,
                    l,
                    c,
                    p,
                    f,
                    d = o.createElement("div");
                if (
                    (d.setAttribute("className", "t"),
                    (d.innerHTML = "  <link/><table></table><a href='/a'>a</a><input type='checkbox'/>"),
                    (n = d.getElementsByTagName("*")),
                    (r = d.getElementsByTagName("a")[0]),
                    !n || !r || !n.length)
                )
                    return {};
                (s = o.createElement("select")),
                    (l = s.appendChild(o.createElement("option"))),
                    (a = d.getElementsByTagName("input")[0]),
                    (r.style.cssText = "top:1px;float:left;opacity:.5"),
                    (t = {
                        getSetAttribute: "t" !== d.className,
                        leadingWhitespace: 3 === d.firstChild.nodeType,
                        tbody: !d.getElementsByTagName("tbody").length,
                        htmlSerialize: !!d.getElementsByTagName("link").length,
                        style: /top/.test(r.getAttribute("style")),
                        hrefNormalized: "/a" === r.getAttribute("href"),
                        opacity: /^0.5/.test(r.style.opacity),
                        cssFloat: !!r.style.cssFloat,
                        checkOn: !!a.value,
                        optSelected: l.selected,
                        enctype: !!o.createElement("form").enctype,
                        html5Clone: "<:nav></:nav>" !== o.createElement("nav").cloneNode(!0).outerHTML,
                        boxModel: "CSS1Compat" === o.compatMode,
                        deleteExpando: !0,
                        noCloneEvent: !0,
                        inlineBlockNeedsLayout: !1,
                        shrinkWrapBlocks: !1,
                        reliableMarginRight: !0,
                        boxSizingReliable: !0,
                        pixelPosition: !1,
                    }),
                    (a.checked = !0),
                    (t.noCloneChecked = a.cloneNode(!0).checked),
                    (s.disabled = !0),
                    (t.optDisabled = !l.disabled);
                try {
                    delete d.test;
                } catch (h) {
                    t.deleteExpando = !1;
                }
                (a = o.createElement("input")),
                    a.setAttribute("value", ""),
                    (t.input = "" === a.getAttribute("value")),
                    (a.value = "t"),
                    a.setAttribute("type", "radio"),
                    (t.radioValue = "t" === a.value),
                    a.setAttribute("checked", "t"),
                    a.setAttribute("name", "t"),
                    (u = o.createDocumentFragment()),
                    u.appendChild(a),
                    (t.appendChecked = a.checked),
                    (t.checkClone = u.cloneNode(!0).cloneNode(!0).lastChild.checked),
                    d.attachEvent &&
                        (d.attachEvent("onclick", function () {
                            t.noCloneEvent = !1;
                        }),
                        d.cloneNode(!0).click());
                for (f in { submit: !0, change: !0, focusin: !0 })
                    d.setAttribute((c = "on" + f), "t"), (t[f + "Bubbles"] = c in e || d.attributes[c].expando === !1);
                return (
                    (d.style.backgroundClip = "content-box"),
                    (d.cloneNode(!0).style.backgroundClip = ""),
                    (t.clearCloneStyle = "content-box" === d.style.backgroundClip),
                    b(function () {
                        var n,
                            r,
                            a,
                            s =
                                "padding:0;margin:0;border:0;display:block;box-sizing:content-box;-moz-box-sizing:content-box;-webkit-box-sizing:content-box;",
                            u = o.getElementsByTagName("body")[0];
                        u &&
                            ((n = o.createElement("div")),
                            (n.style.cssText =
                                "border:0;width:0;height:0;position:absolute;top:0;left:-9999px;margin-top:1px"),
                            u.appendChild(n).appendChild(d),
                            (d.innerHTML = "<table><tr><td></td><td>t</td></tr></table>"),
                            (a = d.getElementsByTagName("td")),
                            (a[0].style.cssText = "padding:0;margin:0;border:0;display:none"),
                            (p = 0 === a[0].offsetHeight),
                            (a[0].style.display = ""),
                            (a[1].style.display = "none"),
                            (t.reliableHiddenOffsets = p && 0 === a[0].offsetHeight),
                            (d.innerHTML = ""),
                            (d.style.cssText =
                                "box-sizing:border-box;-moz-box-sizing:border-box;-webkit-box-sizing:border-box;padding:1px;border:1px;display:block;width:4px;margin-top:1%;position:absolute;top:1%;"),
                            (t.boxSizing = 4 === d.offsetWidth),
                            (t.doesNotIncludeMarginInBodyOffset = 1 !== u.offsetTop),
                            e.getComputedStyle &&
                                ((t.pixelPosition = "1%" !== (e.getComputedStyle(d, null) || {}).top),
                                (t.boxSizingReliable =
                                    "4px" === (e.getComputedStyle(d, null) || { width: "4px" }).width),
                                (r = d.appendChild(o.createElement("div"))),
                                (r.style.cssText = d.style.cssText = s),
                                (r.style.marginRight = r.style.width = "0"),
                                (d.style.width = "1px"),
                                (t.reliableMarginRight = !parseFloat((e.getComputedStyle(r, null) || {}).marginRight))),
                            typeof d.style.zoom !== i &&
                                ((d.innerHTML = ""),
                                (d.style.cssText = s + "width:1px;padding:1px;display:inline;zoom:1"),
                                (t.inlineBlockNeedsLayout = 3 === d.offsetWidth),
                                (d.style.display = "block"),
                                (d.innerHTML = "<div></div>"),
                                (d.firstChild.style.width = "5px"),
                                (t.shrinkWrapBlocks = 3 !== d.offsetWidth),
                                t.inlineBlockNeedsLayout && (u.style.zoom = 1)),
                            u.removeChild(n),
                            (n = d = a = r = null));
                    }),
                    (n = s = u = l = r = a = null),
                    t
                );
            })());
        var O = /(?:\{[\s\S]*\}|\[[\s\S]*\])$/,
            B = /([A-Z])/g;
        function P(e, n, r, i) {
            if (b.acceptData(e)) {
                var o,
                    a,
                    s = b.expando,
                    u = "string" == typeof n,
                    l = e.nodeType,
                    p = l ? b.cache : e,
                    f = l ? e[s] : e[s] && s;
                if ((f && p[f] && (i || p[f].data)) || !u || r !== t)
                    return (
                        f || (l ? (e[s] = f = c.pop() || b.guid++) : (f = s)),
                        p[f] || ((p[f] = {}), l || (p[f].toJSON = b.noop)),
                        ("object" == typeof n || "function" == typeof n) &&
                            (i ? (p[f] = b.extend(p[f], n)) : (p[f].data = b.extend(p[f].data, n))),
                        (o = p[f]),
                        i || (o.data || (o.data = {}), (o = o.data)),
                        r !== t && (o[b.camelCase(n)] = r),
                        u ? ((a = o[n]), null == a && (a = o[b.camelCase(n)])) : (a = o),
                        a
                    );
            }
        }
        function R(e, t, n) {
            if (b.acceptData(e)) {
                var r,
                    i,
                    o,
                    a = e.nodeType,
                    s = a ? b.cache : e,
                    u = a ? e[b.expando] : b.expando;
                if (s[u]) {
                    if (t && (o = n ? s[u] : s[u].data)) {
                        b.isArray(t)
                            ? (t = t.concat(b.map(t, b.camelCase)))
                            : t in o
                              ? (t = [t])
                              : ((t = b.camelCase(t)), (t = t in o ? [t] : t.split(" ")));
                        for (r = 0, i = t.length; i > r; r++) delete o[t[r]];
                        if (!(n ? $ : b.isEmptyObject)(o)) return;
                    }
                    (n || (delete s[u].data, $(s[u]))) &&
                        (a
                            ? b.cleanData([e], !0)
                            : b.support.deleteExpando || s != s.window
                              ? delete s[u]
                              : (s[u] = null));
                }
            }
        }
        b.extend({
            cache: {},
            expando: "jQuery" + (p + Math.random()).replace(/\D/g, ""),
            noData: { embed: !0, object: "clsid:D27CDB6E-AE6D-11cf-96B8-444553540000", applet: !0 },
            hasData: function (e) {
                return (e = e.nodeType ? b.cache[e[b.expando]] : e[b.expando]), !!e && !$(e);
            },
            data: function (e, t, n) {
                return P(e, t, n);
            },
            removeData: function (e, t) {
                return R(e, t);
            },
            _data: function (e, t, n) {
                return P(e, t, n, !0);
            },
            _removeData: function (e, t) {
                return R(e, t, !0);
            },
            acceptData: function (e) {
                if (e.nodeType && 1 !== e.nodeType && 9 !== e.nodeType) return !1;
                var t = e.nodeName && b.noData[e.nodeName.toLowerCase()];
                return !t || (t !== !0 && e.getAttribute("classid") === t);
            },
        }),
            b.fn.extend({
                data: function (e, n) {
                    var r,
                        i,
                        o = this[0],
                        a = 0,
                        s = null;
                    if (e === t) {
                        if (this.length && ((s = b.data(o)), 1 === o.nodeType && !b._data(o, "parsedAttrs"))) {
                            for (r = o.attributes; r.length > a; a++)
                                (i = r[a].name), i.indexOf("data-") || ((i = b.camelCase(i.slice(5))), W(o, i, s[i]));
                            b._data(o, "parsedAttrs", !0);
                        }
                        return s;
                    }
                    return "object" == typeof e
                        ? this.each(function () {
                              b.data(this, e);
                          })
                        : b.access(
                              this,
                              function (n) {
                                  return n === t
                                      ? o
                                          ? W(o, e, b.data(o, e))
                                          : null
                                      : (this.each(function () {
                                            b.data(this, e, n);
                                        }),
                                        t);
                              },
                              null,
                              n,
                              arguments.length > 1,
                              null,
                              !0
                          );
                },
                removeData: function (e) {
                    return this.each(function () {
                        b.removeData(this, e);
                    });
                },
            });
        function W(e, n, r) {
            if (r === t && 1 === e.nodeType) {
                var i = "data-" + n.replace(B, "-$1").toLowerCase();
                if (((r = e.getAttribute(i)), "string" == typeof r)) {
                    try {
                        r =
                            "true" === r
                                ? !0
                                : "false" === r
                                  ? !1
                                  : "null" === r
                                    ? null
                                    : +r + "" === r
                                      ? +r
                                      : O.test(r)
                                        ? b.parseJSON(r)
                                        : r;
                    } catch (o) {}
                    b.data(e, n, r);
                } else r = t;
            }
            return r;
        }
        function $(e) {
            var t;
            for (t in e) if (("data" !== t || !b.isEmptyObject(e[t])) && "toJSON" !== t) return !1;
            return !0;
        }
        b.extend({
            queue: function (e, n, r) {
                var i;
                return e
                    ? ((n = (n || "fx") + "queue"),
                      (i = b._data(e, n)),
                      r && (!i || b.isArray(r) ? (i = b._data(e, n, b.makeArray(r))) : i.push(r)),
                      i || [])
                    : t;
            },
            dequeue: function (e, t) {
                t = t || "fx";
                var n = b.queue(e, t),
                    r = n.length,
                    i = n.shift(),
                    o = b._queueHooks(e, t),
                    a = function () {
                        b.dequeue(e, t);
                    };
                "inprogress" === i && ((i = n.shift()), r--),
                    (o.cur = i),
                    i && ("fx" === t && n.unshift("inprogress"), delete o.stop, i.call(e, a, o)),
                    !r && o && o.empty.fire();
            },
            _queueHooks: function (e, t) {
                var n = t + "queueHooks";
                return (
                    b._data(e, n) ||
                    b._data(e, n, {
                        empty: b.Callbacks("once memory").add(function () {
                            b._removeData(e, t + "queue"), b._removeData(e, n);
                        }),
                    })
                );
            },
        }),
            b.fn.extend({
                queue: function (e, n) {
                    var r = 2;
                    return (
                        "string" != typeof e && ((n = e), (e = "fx"), r--),
                        r > arguments.length
                            ? b.queue(this[0], e)
                            : n === t
                              ? this
                              : this.each(function () {
                                    var t = b.queue(this, e, n);
                                    b._queueHooks(this, e), "fx" === e && "inprogress" !== t[0] && b.dequeue(this, e);
                                })
                    );
                },
                dequeue: function (e) {
                    return this.each(function () {
                        b.dequeue(this, e);
                    });
                },
                delay: function (e, t) {
                    return (
                        (e = b.fx ? b.fx.speeds[e] || e : e),
                        (t = t || "fx"),
                        this.queue(t, function (t, n) {
                            var r = setTimeout(t, e);
                            n.stop = function () {
                                clearTimeout(r);
                            };
                        })
                    );
                },
                clearQueue: function (e) {
                    return this.queue(e || "fx", []);
                },
                promise: function (e, n) {
                    var r,
                        i = 1,
                        o = b.Deferred(),
                        a = this,
                        s = this.length,
                        u = function () {
                            --i || o.resolveWith(a, [a]);
                        };
                    "string" != typeof e && ((n = e), (e = t)), (e = e || "fx");
                    while (s--) (r = b._data(a[s], e + "queueHooks")), r && r.empty && (i++, r.empty.add(u));
                    return u(), o.promise(n);
                },
            });
        var I,
            z,
            X = /[\t\r\n]/g,
            U = /\r/g,
            V = /^(?:input|select|textarea|button|object)$/i,
            Y = /^(?:a|area)$/i,
            J =
                /^(?:checked|selected|autofocus|autoplay|async|controls|defer|disabled|hidden|loop|multiple|open|readonly|required|scoped)$/i,
            G = /^(?:checked|selected)$/i,
            Q = b.support.getSetAttribute,
            K = b.support.input;
        b.fn.extend({
            attr: function (e, t) {
                return b.access(this, b.attr, e, t, arguments.length > 1);
            },
            removeAttr: function (e) {
                return this.each(function () {
                    b.removeAttr(this, e);
                });
            },
            prop: function (e, t) {
                return b.access(this, b.prop, e, t, arguments.length > 1);
            },
            removeProp: function (e) {
                return (
                    (e = b.propFix[e] || e),
                    this.each(function () {
                        try {
                            (this[e] = t), delete this[e];
                        } catch (n) {}
                    })
                );
            },
            addClass: function (e) {
                var t,
                    n,
                    r,
                    i,
                    o,
                    a = 0,
                    s = this.length,
                    u = "string" == typeof e && e;
                if (b.isFunction(e))
                    return this.each(function (t) {
                        b(this).addClass(e.call(this, t, this.className));
                    });
                if (u)
                    for (t = (e || "").match(w) || []; s > a; a++)
                        if (
                            ((n = this[a]),
                            (r = 1 === n.nodeType && (n.className ? (" " + n.className + " ").replace(X, " ") : " ")))
                        ) {
                            o = 0;
                            while ((i = t[o++])) 0 > r.indexOf(" " + i + " ") && (r += i + " ");
                            n.className = b.trim(r);
                        }
                return this;
            },
            removeClass: function (e) {
                var t,
                    n,
                    r,
                    i,
                    o,
                    a = 0,
                    s = this.length,
                    u = 0 === arguments.length || ("string" == typeof e && e);
                if (b.isFunction(e))
                    return this.each(function (t) {
                        b(this).removeClass(e.call(this, t, this.className));
                    });
                if (u)
                    for (t = (e || "").match(w) || []; s > a; a++)
                        if (
                            ((n = this[a]),
                            (r = 1 === n.nodeType && (n.className ? (" " + n.className + " ").replace(X, " ") : "")))
                        ) {
                            o = 0;
                            while ((i = t[o++]))
                                while (r.indexOf(" " + i + " ") >= 0) r = r.replace(" " + i + " ", " ");
                            n.className = e ? b.trim(r) : "";
                        }
                return this;
            },
            toggleClass: function (e, t) {
                var n = typeof e,
                    r = "boolean" == typeof t;
                return b.isFunction(e)
                    ? this.each(function (n) {
                          b(this).toggleClass(e.call(this, n, this.className, t), t);
                      })
                    : this.each(function () {
                          if ("string" === n) {
                              var o,
                                  a = 0,
                                  s = b(this),
                                  u = t,
                                  l = e.match(w) || [];
                              while ((o = l[a++])) (u = r ? u : !s.hasClass(o)), s[u ? "addClass" : "removeClass"](o);
                          } else
                              (n === i || "boolean" === n) &&
                                  (this.className && b._data(this, "__className__", this.className),
                                  (this.className =
                                      this.className || e === !1 ? "" : b._data(this, "__className__") || ""));
                      });
            },
            hasClass: function (e) {
                var t = " " + e + " ",
                    n = 0,
                    r = this.length;
                for (; r > n; n++)
                    if (1 === this[n].nodeType && (" " + this[n].className + " ").replace(X, " ").indexOf(t) >= 0)
                        return !0;
                return !1;
            },
            val: function (e) {
                var n,
                    r,
                    i,
                    o = this[0];
                {
                    if (arguments.length)
                        return (
                            (i = b.isFunction(e)),
                            this.each(function (n) {
                                var o,
                                    a = b(this);
                                1 === this.nodeType &&
                                    ((o = i ? e.call(this, n, a.val()) : e),
                                    null == o
                                        ? (o = "")
                                        : "number" == typeof o
                                          ? (o += "")
                                          : b.isArray(o) &&
                                            (o = b.map(o, function (e) {
                                                return null == e ? "" : e + "";
                                            })),
                                    (r = b.valHooks[this.type] || b.valHooks[this.nodeName.toLowerCase()]),
                                    (r && "set" in r && r.set(this, o, "value") !== t) || (this.value = o));
                            })
                        );
                    if (o)
                        return (
                            (r = b.valHooks[o.type] || b.valHooks[o.nodeName.toLowerCase()]),
                            r && "get" in r && (n = r.get(o, "value")) !== t
                                ? n
                                : ((n = o.value), "string" == typeof n ? n.replace(U, "") : null == n ? "" : n)
                        );
                }
            },
        }),
            b.extend({
                valHooks: {
                    option: {
                        get: function (e) {
                            var t = e.attributes.value;
                            return !t || t.specified ? e.value : e.text;
                        },
                    },
                    select: {
                        get: function (e) {
                            var t,
                                n,
                                r = e.options,
                                i = e.selectedIndex,
                                o = "select-one" === e.type || 0 > i,
                                a = o ? null : [],
                                s = o ? i + 1 : r.length,
                                u = 0 > i ? s : o ? i : 0;
                            for (; s > u; u++)
                                if (
                                    ((n = r[u]),
                                    !(
                                        (!n.selected && u !== i) ||
                                        (b.support.optDisabled ? n.disabled : null !== n.getAttribute("disabled")) ||
                                        (n.parentNode.disabled && b.nodeName(n.parentNode, "optgroup"))
                                    ))
                                ) {
                                    if (((t = b(n).val()), o)) return t;
                                    a.push(t);
                                }
                            return a;
                        },
                        set: function (e, t) {
                            var n = b.makeArray(t);
                            return (
                                b(e)
                                    .find("option")
                                    .each(function () {
                                        this.selected = b.inArray(b(this).val(), n) >= 0;
                                    }),
                                n.length || (e.selectedIndex = -1),
                                n
                            );
                        },
                    },
                },
                attr: function (e, n, r) {
                    var o,
                        a,
                        s,
                        u = e.nodeType;
                    if (e && 3 !== u && 8 !== u && 2 !== u)
                        return typeof e.getAttribute === i
                            ? b.prop(e, n, r)
                            : ((a = 1 !== u || !b.isXMLDoc(e)),
                              a && ((n = n.toLowerCase()), (o = b.attrHooks[n] || (J.test(n) ? z : I))),
                              r === t
                                  ? o && a && "get" in o && null !== (s = o.get(e, n))
                                      ? s
                                      : (typeof e.getAttribute !== i && (s = e.getAttribute(n)), null == s ? t : s)
                                  : null !== r
                                    ? o && a && "set" in o && (s = o.set(e, r, n)) !== t
                                        ? s
                                        : (e.setAttribute(n, r + ""), r)
                                    : (b.removeAttr(e, n), t));
                },
                removeAttr: function (e, t) {
                    var n,
                        r,
                        i = 0,
                        o = t && t.match(w);
                    if (o && 1 === e.nodeType)
                        while ((n = o[i++]))
                            (r = b.propFix[n] || n),
                                J.test(n)
                                    ? !Q && G.test(n)
                                        ? (e[b.camelCase("default-" + n)] = e[r] = !1)
                                        : (e[r] = !1)
                                    : b.attr(e, n, ""),
                                e.removeAttribute(Q ? n : r);
                },
                attrHooks: {
                    type: {
                        set: function (e, t) {
                            if (!b.support.radioValue && "radio" === t && b.nodeName(e, "input")) {
                                var n = e.value;
                                return e.setAttribute("type", t), n && (e.value = n), t;
                            }
                        },
                    },
                },
                propFix: {
                    tabindex: "tabIndex",
                    readonly: "readOnly",
                    for: "htmlFor",
                    class: "className",
                    maxlength: "maxLength",
                    cellspacing: "cellSpacing",
                    cellpadding: "cellPadding",
                    rowspan: "rowSpan",
                    colspan: "colSpan",
                    usemap: "useMap",
                    frameborder: "frameBorder",
                    contenteditable: "contentEditable",
                },
                prop: function (e, n, r) {
                    var i,
                        o,
                        a,
                        s = e.nodeType;
                    if (e && 3 !== s && 8 !== s && 2 !== s)
                        return (
                            (a = 1 !== s || !b.isXMLDoc(e)),
                            a && ((n = b.propFix[n] || n), (o = b.propHooks[n])),
                            r !== t
                                ? o && "set" in o && (i = o.set(e, r, n)) !== t
                                    ? i
                                    : (e[n] = r)
                                : o && "get" in o && null !== (i = o.get(e, n))
                                  ? i
                                  : e[n]
                        );
                },
                propHooks: {
                    tabIndex: {
                        get: function (e) {
                            var n = e.getAttributeNode("tabindex");
                            return n && n.specified
                                ? parseInt(n.value, 10)
                                : V.test(e.nodeName) || (Y.test(e.nodeName) && e.href)
                                  ? 0
                                  : t;
                        },
                    },
                },
            }),
            (z = {
                get: function (e, n) {
                    var r = b.prop(e, n),
                        i = "boolean" == typeof r && e.getAttribute(n),
                        o =
                            "boolean" == typeof r
                                ? K && Q
                                    ? null != i
                                    : G.test(n)
                                      ? e[b.camelCase("default-" + n)]
                                      : !!i
                                : e.getAttributeNode(n);
                    return o && o.value !== !1 ? n.toLowerCase() : t;
                },
                set: function (e, t, n) {
                    return (
                        t === !1
                            ? b.removeAttr(e, n)
                            : (K && Q) || !G.test(n)
                              ? e.setAttribute((!Q && b.propFix[n]) || n, n)
                              : (e[b.camelCase("default-" + n)] = e[n] = !0),
                        n
                    );
                },
            }),
            (K && Q) ||
                (b.attrHooks.value = {
                    get: function (e, n) {
                        var r = e.getAttributeNode(n);
                        return b.nodeName(e, "input") ? e.defaultValue : r && r.specified ? r.value : t;
                    },
                    set: function (e, n, r) {
                        return b.nodeName(e, "input") ? ((e.defaultValue = n), t) : I && I.set(e, n, r);
                    },
                }),
            Q ||
                ((I = b.valHooks.button =
                    {
                        get: function (e, n) {
                            var r = e.getAttributeNode(n);
                            return r && ("id" === n || "name" === n || "coords" === n ? "" !== r.value : r.specified)
                                ? r.value
                                : t;
                        },
                        set: function (e, n, r) {
                            var i = e.getAttributeNode(r);
                            return (
                                i || e.setAttributeNode((i = e.ownerDocument.createAttribute(r))),
                                (i.value = n += ""),
                                "value" === r || n === e.getAttribute(r) ? n : t
                            );
                        },
                    }),
                (b.attrHooks.contenteditable = {
                    get: I.get,
                    set: function (e, t, n) {
                        I.set(e, "" === t ? !1 : t, n);
                    },
                }),
                b.each(["width", "height"], function (e, n) {
                    b.attrHooks[n] = b.extend(b.attrHooks[n], {
                        set: function (e, r) {
                            return "" === r ? (e.setAttribute(n, "auto"), r) : t;
                        },
                    });
                })),
            b.support.hrefNormalized ||
                (b.each(["href", "src", "width", "height"], function (e, n) {
                    b.attrHooks[n] = b.extend(b.attrHooks[n], {
                        get: function (e) {
                            var r = e.getAttribute(n, 2);
                            return null == r ? t : r;
                        },
                    });
                }),
                b.each(["href", "src"], function (e, t) {
                    b.propHooks[t] = {
                        get: function (e) {
                            return e.getAttribute(t, 4);
                        },
                    };
                })),
            b.support.style ||
                (b.attrHooks.style = {
                    get: function (e) {
                        return e.style.cssText || t;
                    },
                    set: function (e, t) {
                        return (e.style.cssText = t + "");
                    },
                }),
            b.support.optSelected ||
                (b.propHooks.selected = b.extend(b.propHooks.selected, {
                    get: function (e) {
                        var t = e.parentNode;
                        return t && (t.selectedIndex, t.parentNode && t.parentNode.selectedIndex), null;
                    },
                })),
            b.support.enctype || (b.propFix.enctype = "encoding"),
            b.support.checkOn ||
                b.each(["radio", "checkbox"], function () {
                    b.valHooks[this] = {
                        get: function (e) {
                            return null === e.getAttribute("value") ? "on" : e.value;
                        },
                    };
                }),
            b.each(["radio", "checkbox"], function () {
                b.valHooks[this] = b.extend(b.valHooks[this], {
                    set: function (e, n) {
                        return b.isArray(n) ? (e.checked = b.inArray(b(e).val(), n) >= 0) : t;
                    },
                });
            });
        var Z = /^(?:input|select|textarea)$/i,
            et = /^key/,
            tt = /^(?:mouse|contextmenu)|click/,
            nt = /^(?:focusinfocus|focusoutblur)$/,
            rt = /^([^.]*)(?:\.(.+)|)$/;
        function it() {
            return !0;
        }
        function ot() {
            return !1;
        }
        (b.event = {
            global: {},
            add: function (e, n, r, o, a) {
                var s,
                    u,
                    l,
                    c,
                    p,
                    f,
                    d,
                    h,
                    g,
                    m,
                    y,
                    v = b._data(e);
                if (v) {
                    r.handler && ((c = r), (r = c.handler), (a = c.selector)),
                        r.guid || (r.guid = b.guid++),
                        (u = v.events) || (u = v.events = {}),
                        (f = v.handle) ||
                            ((f = v.handle =
                                function (e) {
                                    return typeof b === i || (e && b.event.triggered === e.type)
                                        ? t
                                        : b.event.dispatch.apply(f.elem, arguments);
                                }),
                            (f.elem = e)),
                        (n = (n || "").match(w) || [""]),
                        (l = n.length);
                    while (l--)
                        (s = rt.exec(n[l]) || []),
                            (g = y = s[1]),
                            (m = (s[2] || "").split(".").sort()),
                            (p = b.event.special[g] || {}),
                            (g = (a ? p.delegateType : p.bindType) || g),
                            (p = b.event.special[g] || {}),
                            (d = b.extend(
                                {
                                    type: g,
                                    origType: y,
                                    data: o,
                                    handler: r,
                                    guid: r.guid,
                                    selector: a,
                                    needsContext: a && b.expr.match.needsContext.test(a),
                                    namespace: m.join("."),
                                },
                                c
                            )),
                            (h = u[g]) ||
                                ((h = u[g] = []),
                                (h.delegateCount = 0),
                                (p.setup && p.setup.call(e, o, m, f) !== !1) ||
                                    (e.addEventListener
                                        ? e.addEventListener(g, f, !1)
                                        : e.attachEvent && e.attachEvent("on" + g, f))),
                            p.add && (p.add.call(e, d), d.handler.guid || (d.handler.guid = r.guid)),
                            a ? h.splice(h.delegateCount++, 0, d) : h.push(d),
                            (b.event.global[g] = !0);
                    e = null;
                }
            },
            remove: function (e, t, n, r, i) {
                var o,
                    a,
                    s,
                    u,
                    l,
                    c,
                    p,
                    f,
                    d,
                    h,
                    g,
                    m = b.hasData(e) && b._data(e);
                if (m && (c = m.events)) {
                    (t = (t || "").match(w) || [""]), (l = t.length);
                    while (l--)
                        if (((s = rt.exec(t[l]) || []), (d = g = s[1]), (h = (s[2] || "").split(".").sort()), d)) {
                            (p = b.event.special[d] || {}),
                                (d = (r ? p.delegateType : p.bindType) || d),
                                (f = c[d] || []),
                                (s = s[2] && RegExp("(^|\\.)" + h.join("\\.(?:.*\\.|)") + "(\\.|$)")),
                                (u = o = f.length);
                            while (o--)
                                (a = f[o]),
                                    (!i && g !== a.origType) ||
                                        (n && n.guid !== a.guid) ||
                                        (s && !s.test(a.namespace)) ||
                                        (r && r !== a.selector && ("**" !== r || !a.selector)) ||
                                        (f.splice(o, 1),
                                        a.selector && f.delegateCount--,
                                        p.remove && p.remove.call(e, a));
                            u &&
                                !f.length &&
                                ((p.teardown && p.teardown.call(e, h, m.handle) !== !1) ||
                                    b.removeEvent(e, d, m.handle),
                                delete c[d]);
                        } else for (d in c) b.event.remove(e, d + t[l], n, r, !0);
                    b.isEmptyObject(c) && (delete m.handle, b._removeData(e, "events"));
                }
            },
            trigger: function (n, r, i, a) {
                var s,
                    u,
                    l,
                    c,
                    p,
                    f,
                    d,
                    h = [i || o],
                    g = y.call(n, "type") ? n.type : n,
                    m = y.call(n, "namespace") ? n.namespace.split(".") : [];
                if (
                    ((l = f = i = i || o),
                    3 !== i.nodeType &&
                        8 !== i.nodeType &&
                        !nt.test(g + b.event.triggered) &&
                        (g.indexOf(".") >= 0 && ((m = g.split(".")), (g = m.shift()), m.sort()),
                        (u = 0 > g.indexOf(":") && "on" + g),
                        (n = n[b.expando] ? n : new b.Event(g, "object" == typeof n && n)),
                        (n.isTrigger = !0),
                        (n.namespace = m.join(".")),
                        (n.namespace_re = n.namespace ? RegExp("(^|\\.)" + m.join("\\.(?:.*\\.|)") + "(\\.|$)") : null),
                        (n.result = t),
                        n.target || (n.target = i),
                        (r = null == r ? [n] : b.makeArray(r, [n])),
                        (p = b.event.special[g] || {}),
                        a || !p.trigger || p.trigger.apply(i, r) !== !1))
                ) {
                    if (!a && !p.noBubble && !b.isWindow(i)) {
                        for (c = p.delegateType || g, nt.test(c + g) || (l = l.parentNode); l; l = l.parentNode)
                            h.push(l), (f = l);
                        f === (i.ownerDocument || o) && h.push(f.defaultView || f.parentWindow || e);
                    }
                    d = 0;
                    while ((l = h[d++]) && !n.isPropagationStopped())
                        (n.type = d > 1 ? c : p.bindType || g),
                            (s = (b._data(l, "events") || {})[n.type] && b._data(l, "handle")),
                            s && s.apply(l, r),
                            (s = u && l[u]),
                            s && b.acceptData(l) && s.apply && s.apply(l, r) === !1 && n.preventDefault();
                    if (
                        ((n.type = g),
                        !(
                            a ||
                            n.isDefaultPrevented() ||
                            (p._default && p._default.apply(i.ownerDocument, r) !== !1) ||
                            ("click" === g && b.nodeName(i, "a")) ||
                            !b.acceptData(i) ||
                            !u ||
                            !i[g] ||
                            b.isWindow(i)
                        ))
                    ) {
                        (f = i[u]), f && (i[u] = null), (b.event.triggered = g);
                        try {
                            i[g]();
                        } catch (v) {}
                        (b.event.triggered = t), f && (i[u] = f);
                    }
                    return n.result;
                }
            },
            dispatch: function (e) {
                e = b.event.fix(e);
                var n,
                    r,
                    i,
                    o,
                    a,
                    s = [],
                    u = h.call(arguments),
                    l = (b._data(this, "events") || {})[e.type] || [],
                    c = b.event.special[e.type] || {};
                if (((u[0] = e), (e.delegateTarget = this), !c.preDispatch || c.preDispatch.call(this, e) !== !1)) {
                    (s = b.event.handlers.call(this, e, l)), (n = 0);
                    while ((o = s[n++]) && !e.isPropagationStopped()) {
                        (e.currentTarget = o.elem), (a = 0);
                        while ((i = o.handlers[a++]) && !e.isImmediatePropagationStopped())
                            (!e.namespace_re || e.namespace_re.test(i.namespace)) &&
                                ((e.handleObj = i),
                                (e.data = i.data),
                                (r = ((b.event.special[i.origType] || {}).handle || i.handler).apply(o.elem, u)),
                                r !== t && (e.result = r) === !1 && (e.preventDefault(), e.stopPropagation()));
                    }
                    return c.postDispatch && c.postDispatch.call(this, e), e.result;
                }
            },
            handlers: function (e, n) {
                var r,
                    i,
                    o,
                    a,
                    s = [],
                    u = n.delegateCount,
                    l = e.target;
                if (u && l.nodeType && (!e.button || "click" !== e.type))
                    for (; l != this; l = l.parentNode || this)
                        if (1 === l.nodeType && (l.disabled !== !0 || "click" !== e.type)) {
                            for (o = [], a = 0; u > a; a++)
                                (i = n[a]),
                                    (r = i.selector + " "),
                                    o[r] === t &&
                                        (o[r] = i.needsContext
                                            ? b(r, this).index(l) >= 0
                                            : b.find(r, this, null, [l]).length),
                                    o[r] && o.push(i);
                            o.length && s.push({ elem: l, handlers: o });
                        }
                return n.length > u && s.push({ elem: this, handlers: n.slice(u) }), s;
            },
            fix: function (e) {
                if (e[b.expando]) return e;
                var t,
                    n,
                    r,
                    i = e.type,
                    a = e,
                    s = this.fixHooks[i];
                s || (this.fixHooks[i] = s = tt.test(i) ? this.mouseHooks : et.test(i) ? this.keyHooks : {}),
                    (r = s.props ? this.props.concat(s.props) : this.props),
                    (e = new b.Event(a)),
                    (t = r.length);
                while (t--) (n = r[t]), (e[n] = a[n]);
                return (
                    e.target || (e.target = a.srcElement || o),
                    3 === e.target.nodeType && (e.target = e.target.parentNode),
                    (e.metaKey = !!e.metaKey),
                    s.filter ? s.filter(e, a) : e
                );
            },
            props: "altKey bubbles cancelable ctrlKey currentTarget eventPhase metaKey relatedTarget shiftKey target timeStamp view which".split(
                " "
            ),
            fixHooks: {},
            keyHooks: {
                props: "char charCode key keyCode".split(" "),
                filter: function (e, t) {
                    return null == e.which && (e.which = null != t.charCode ? t.charCode : t.keyCode), e;
                },
            },
            mouseHooks: {
                props: "button buttons clientX clientY fromElement offsetX offsetY pageX pageY screenX screenY toElement".split(
                    " "
                ),
                filter: function (e, n) {
                    var r,
                        i,
                        a,
                        s = n.button,
                        u = n.fromElement;
                    return (
                        null == e.pageX &&
                            null != n.clientX &&
                            ((i = e.target.ownerDocument || o),
                            (a = i.documentElement),
                            (r = i.body),
                            (e.pageX =
                                n.clientX +
                                ((a && a.scrollLeft) || (r && r.scrollLeft) || 0) -
                                ((a && a.clientLeft) || (r && r.clientLeft) || 0)),
                            (e.pageY =
                                n.clientY +
                                ((a && a.scrollTop) || (r && r.scrollTop) || 0) -
                                ((a && a.clientTop) || (r && r.clientTop) || 0))),
                        !e.relatedTarget && u && (e.relatedTarget = u === e.target ? n.toElement : u),
                        e.which || s === t || (e.which = 1 & s ? 1 : 2 & s ? 3 : 4 & s ? 2 : 0),
                        e
                    );
                },
            },
            special: {
                load: { noBubble: !0 },
                click: {
                    trigger: function () {
                        return b.nodeName(this, "input") && "checkbox" === this.type && this.click
                            ? (this.click(), !1)
                            : t;
                    },
                },
                focus: {
                    trigger: function () {
                        if (this !== o.activeElement && this.focus)
                            try {
                                return this.focus(), !1;
                            } catch (e) {}
                    },
                    delegateType: "focusin",
                },
                blur: {
                    trigger: function () {
                        return this === o.activeElement && this.blur ? (this.blur(), !1) : t;
                    },
                    delegateType: "focusout",
                },
                beforeunload: {
                    postDispatch: function (e) {
                        e.result !== t && (e.originalEvent.returnValue = e.result);
                    },
                },
            },
            simulate: function (e, t, n, r) {
                var i = b.extend(new b.Event(), n, { type: e, isSimulated: !0, originalEvent: {} });
                r ? b.event.trigger(i, null, t) : b.event.dispatch.call(t, i),
                    i.isDefaultPrevented() && n.preventDefault();
            },
        }),
            (b.removeEvent = o.removeEventListener
                ? function (e, t, n) {
                      e.removeEventListener && e.removeEventListener(t, n, !1);
                  }
                : function (e, t, n) {
                      var r = "on" + t;
                      e.detachEvent && (typeof e[r] === i && (e[r] = null), e.detachEvent(r, n));
                  }),
            (b.Event = function (e, n) {
                return this instanceof b.Event
                    ? (e && e.type
                          ? ((this.originalEvent = e),
                            (this.type = e.type),
                            (this.isDefaultPrevented =
                                e.defaultPrevented ||
                                e.returnValue === !1 ||
                                (e.getPreventDefault && e.getPreventDefault())
                                    ? it
                                    : ot))
                          : (this.type = e),
                      n && b.extend(this, n),
                      (this.timeStamp = (e && e.timeStamp) || b.now()),
                      (this[b.expando] = !0),
                      t)
                    : new b.Event(e, n);
            }),
            (b.Event.prototype = {
                isDefaultPrevented: ot,
                isPropagationStopped: ot,
                isImmediatePropagationStopped: ot,
                preventDefault: function () {
                    var e = this.originalEvent;
                    (this.isDefaultPrevented = it), e && (e.preventDefault ? e.preventDefault() : (e.returnValue = !1));
                },
                stopPropagation: function () {
                    var e = this.originalEvent;
                    (this.isPropagationStopped = it),
                        e && (e.stopPropagation && e.stopPropagation(), (e.cancelBubble = !0));
                },
                stopImmediatePropagation: function () {
                    (this.isImmediatePropagationStopped = it), this.stopPropagation();
                },
            }),
            b.each({ mouseenter: "mouseover", mouseleave: "mouseout" }, function (e, t) {
                b.event.special[e] = {
                    delegateType: t,
                    bindType: t,
                    handle: function (e) {
                        var n,
                            r = this,
                            i = e.relatedTarget,
                            o = e.handleObj;
                        return (
                            (!i || (i !== r && !b.contains(r, i))) &&
                                ((e.type = o.origType), (n = o.handler.apply(this, arguments)), (e.type = t)),
                            n
                        );
                    },
                };
            }),
            b.support.submitBubbles ||
                (b.event.special.submit = {
                    setup: function () {
                        return b.nodeName(this, "form")
                            ? !1
                            : (b.event.add(this, "click._submit keypress._submit", function (e) {
                                  var n = e.target,
                                      r = b.nodeName(n, "input") || b.nodeName(n, "button") ? n.form : t;
                                  r &&
                                      !b._data(r, "submitBubbles") &&
                                      (b.event.add(r, "submit._submit", function (e) {
                                          e._submit_bubble = !0;
                                      }),
                                      b._data(r, "submitBubbles", !0));
                              }),
                              t);
                    },
                    postDispatch: function (e) {
                        e._submit_bubble &&
                            (delete e._submit_bubble,
                            this.parentNode && !e.isTrigger && b.event.simulate("submit", this.parentNode, e, !0));
                    },
                    teardown: function () {
                        return b.nodeName(this, "form") ? !1 : (b.event.remove(this, "._submit"), t);
                    },
                }),
            b.support.changeBubbles ||
                (b.event.special.change = {
                    setup: function () {
                        return Z.test(this.nodeName)
                            ? (("checkbox" === this.type || "radio" === this.type) &&
                                  (b.event.add(this, "propertychange._change", function (e) {
                                      "checked" === e.originalEvent.propertyName && (this._just_changed = !0);
                                  }),
                                  b.event.add(this, "click._change", function (e) {
                                      this._just_changed && !e.isTrigger && (this._just_changed = !1),
                                          b.event.simulate("change", this, e, !0);
                                  })),
                              !1)
                            : (b.event.add(this, "beforeactivate._change", function (e) {
                                  var t = e.target;
                                  Z.test(t.nodeName) &&
                                      !b._data(t, "changeBubbles") &&
                                      (b.event.add(t, "change._change", function (e) {
                                          !this.parentNode ||
                                              e.isSimulated ||
                                              e.isTrigger ||
                                              b.event.simulate("change", this.parentNode, e, !0);
                                      }),
                                      b._data(t, "changeBubbles", !0));
                              }),
                              t);
                    },
                    handle: function (e) {
                        var n = e.target;
                        return this !== n ||
                            e.isSimulated ||
                            e.isTrigger ||
                            ("radio" !== n.type && "checkbox" !== n.type)
                            ? e.handleObj.handler.apply(this, arguments)
                            : t;
                    },
                    teardown: function () {
                        return b.event.remove(this, "._change"), !Z.test(this.nodeName);
                    },
                }),
            b.support.focusinBubbles ||
                b.each({ focus: "focusin", blur: "focusout" }, function (e, t) {
                    var n = 0,
                        r = function (e) {
                            b.event.simulate(t, e.target, b.event.fix(e), !0);
                        };
                    b.event.special[t] = {
                        setup: function () {
                            0 === n++ && o.addEventListener(e, r, !0);
                        },
                        teardown: function () {
                            0 === --n && o.removeEventListener(e, r, !0);
                        },
                    };
                }),
            b.fn.extend({
                on: function (e, n, r, i, o) {
                    var a, s;
                    if ("object" == typeof e) {
                        "string" != typeof n && ((r = r || n), (n = t));
                        for (a in e) this.on(a, n, r, e[a], o);
                        return this;
                    }
                    if (
                        (null == r && null == i
                            ? ((i = n), (r = n = t))
                            : null == i && ("string" == typeof n ? ((i = r), (r = t)) : ((i = r), (r = n), (n = t))),
                        i === !1)
                    )
                        i = ot;
                    else if (!i) return this;
                    return (
                        1 === o &&
                            ((s = i),
                            (i = function (e) {
                                return b().off(e), s.apply(this, arguments);
                            }),
                            (i.guid = s.guid || (s.guid = b.guid++))),
                        this.each(function () {
                            b.event.add(this, e, i, r, n);
                        })
                    );
                },
                one: function (e, t, n, r) {
                    return this.on(e, t, n, r, 1);
                },
                off: function (e, n, r) {
                    var i, o;
                    if (e && e.preventDefault && e.handleObj)
                        return (
                            (i = e.handleObj),
                            b(e.delegateTarget).off(
                                i.namespace ? i.origType + "." + i.namespace : i.origType,
                                i.selector,
                                i.handler
                            ),
                            this
                        );
                    if ("object" == typeof e) {
                        for (o in e) this.off(o, n, e[o]);
                        return this;
                    }
                    return (
                        (n === !1 || "function" == typeof n) && ((r = n), (n = t)),
                        r === !1 && (r = ot),
                        this.each(function () {
                            b.event.remove(this, e, r, n);
                        })
                    );
                },
                bind: function (e, t, n) {
                    return this.on(e, null, t, n);
                },
                unbind: function (e, t) {
                    return this.off(e, null, t);
                },
                delegate: function (e, t, n, r) {
                    return this.on(t, e, n, r);
                },
                undelegate: function (e, t, n) {
                    return 1 === arguments.length ? this.off(e, "**") : this.off(t, e || "**", n);
                },
                trigger: function (e, t) {
                    return this.each(function () {
                        b.event.trigger(e, t, this);
                    });
                },
                triggerHandler: function (e, n) {
                    var r = this[0];
                    return r ? b.event.trigger(e, n, r, !0) : t;
                },
            }),
            (function (e, t) {
                var n,
                    r,
                    i,
                    o,
                    a,
                    s,
                    u,
                    l,
                    c,
                    p,
                    f,
                    d,
                    h,
                    g,
                    m,
                    y,
                    v,
                    x = "sizzle" + -new Date(),
                    w = e.document,
                    T = {},
                    N = 0,
                    C = 0,
                    k = it(),
                    E = it(),
                    S = it(),
                    A = typeof t,
                    j = 1 << 31,
                    D = [],
                    L = D.pop,
                    H = D.push,
                    q = D.slice,
                    M =
                        D.indexOf ||
                        function (e) {
                            var t = 0,
                                n = this.length;
                            for (; n > t; t++) if (this[t] === e) return t;
                            return -1;
                        },
                    _ = "[\\x20\\t\\r\\n\\f]",
                    F = "(?:\\\\.|[\\w-]|[^\\x00-\\xa0])+",
                    O = F.replace("w", "w#"),
                    B = "([*^$|!~]?=)",
                    P =
                        "\\[" +
                        _ +
                        "*(" +
                        F +
                        ")" +
                        _ +
                        "*(?:" +
                        B +
                        _ +
                        "*(?:(['\"])((?:\\\\.|[^\\\\])*?)\\3|(" +
                        O +
                        ")|)|)" +
                        _ +
                        "*\\]",
                    R =
                        ":(" +
                        F +
                        ")(?:\\(((['\"])((?:\\\\.|[^\\\\])*?)\\3|((?:\\\\.|[^\\\\()[\\]]|" +
                        P.replace(3, 8) +
                        ")*)|.*)\\)|)",
                    W = RegExp("^" + _ + "+|((?:^|[^\\\\])(?:\\\\.)*)" + _ + "+$", "g"),
                    $ = RegExp("^" + _ + "*," + _ + "*"),
                    I = RegExp("^" + _ + "*([\\x20\\t\\r\\n\\f>+~])" + _ + "*"),
                    z = RegExp(R),
                    X = RegExp("^" + O + "$"),
                    U = {
                        ID: RegExp("^#(" + F + ")"),
                        CLASS: RegExp("^\\.(" + F + ")"),
                        NAME: RegExp("^\\[name=['\"]?(" + F + ")['\"]?\\]"),
                        TAG: RegExp("^(" + F.replace("w", "w*") + ")"),
                        ATTR: RegExp("^" + P),
                        PSEUDO: RegExp("^" + R),
                        CHILD: RegExp(
                            "^:(only|first|last|nth|nth-last)-(child|of-type)(?:\\(" +
                                _ +
                                "*(even|odd|(([+-]|)(\\d*)n|)" +
                                _ +
                                "*(?:([+-]|)" +
                                _ +
                                "*(\\d+)|))" +
                                _ +
                                "*\\)|)",
                            "i"
                        ),
                        needsContext: RegExp(
                            "^" +
                                _ +
                                "*[>+~]|:(even|odd|eq|gt|lt|nth|first|last)(?:\\(" +
                                _ +
                                "*((?:-\\d)?\\d*)" +
                                _ +
                                "*\\)|)(?=[^-]|$)",
                            "i"
                        ),
                    },
                    V = /[\x20\t\r\n\f]*[+~]/,
                    Y = /^[^{]+\{\s*\[native code/,
                    J = /^(?:#([\w-]+)|(\w+)|\.([\w-]+))$/,
                    G = /^(?:input|select|textarea|button)$/i,
                    Q = /^h\d$/i,
                    K = /'|\\/g,
                    Z = /\=[\x20\t\r\n\f]*([^'"\]]*)[\x20\t\r\n\f]*\]/g,
                    et = /\\([\da-fA-F]{1,6}[\x20\t\r\n\f]?|.)/g,
                    tt = function (e, t) {
                        var n = "0x" + t - 65536;
                        return n !== n
                            ? t
                            : 0 > n
                              ? String.fromCharCode(n + 65536)
                              : String.fromCharCode(55296 | (n >> 10), 56320 | (1023 & n));
                    };
                try {
                    q.call(w.documentElement.childNodes, 0)[0].nodeType;
                } catch (nt) {
                    q = function (e) {
                        var t,
                            n = [];
                        while ((t = this[e++])) n.push(t);
                        return n;
                    };
                }
                function rt(e) {
                    return Y.test(e + "");
                }
                function it() {
                    var e,
                        t = [];
                    return (e = function (n, r) {
                        return t.push((n += " ")) > i.cacheLength && delete e[t.shift()], (e[n] = r);
                    });
                }
                function ot(e) {
                    return (e[x] = !0), e;
                }
                function at(e) {
                    var t = p.createElement("div");
                    try {
                        return e(t);
                    } catch (n) {
                        return !1;
                    } finally {
                        t = null;
                    }
                }
                function st(e, t, n, r) {
                    var i, o, a, s, u, l, f, g, m, v;
                    if (
                        ((t ? t.ownerDocument || t : w) !== p && c(t),
                        (t = t || p),
                        (n = n || []),
                        !e || "string" != typeof e)
                    )
                        return n;
                    if (1 !== (s = t.nodeType) && 9 !== s) return [];
                    if (!d && !r) {
                        if ((i = J.exec(e)))
                            if ((a = i[1])) {
                                if (9 === s) {
                                    if (((o = t.getElementById(a)), !o || !o.parentNode)) return n;
                                    if (o.id === a) return n.push(o), n;
                                } else if (
                                    t.ownerDocument &&
                                    (o = t.ownerDocument.getElementById(a)) &&
                                    y(t, o) &&
                                    o.id === a
                                )
                                    return n.push(o), n;
                            } else {
                                if (i[2]) return H.apply(n, q.call(t.getElementsByTagName(e), 0)), n;
                                if ((a = i[3]) && T.getByClassName && t.getElementsByClassName)
                                    return H.apply(n, q.call(t.getElementsByClassName(a), 0)), n;
                            }
                        if (T.qsa && !h.test(e)) {
                            if (
                                ((f = !0),
                                (g = x),
                                (m = t),
                                (v = 9 === s && e),
                                1 === s && "object" !== t.nodeName.toLowerCase())
                            ) {
                                (l = ft(e)),
                                    (f = t.getAttribute("id")) ? (g = f.replace(K, "\\$&")) : t.setAttribute("id", g),
                                    (g = "[id='" + g + "'] "),
                                    (u = l.length);
                                while (u--) l[u] = g + dt(l[u]);
                                (m = (V.test(e) && t.parentNode) || t), (v = l.join(","));
                            }
                            if (v)
                                try {
                                    return H.apply(n, q.call(m.querySelectorAll(v), 0)), n;
                                } catch (b) {
                                } finally {
                                    f || t.removeAttribute("id");
                                }
                        }
                    }
                    return wt(e.replace(W, "$1"), t, n, r);
                }
                (a = st.isXML =
                    function (e) {
                        var t = e && (e.ownerDocument || e).documentElement;
                        return t ? "HTML" !== t.nodeName : !1;
                    }),
                    (c = st.setDocument =
                        function (e) {
                            var n = e ? e.ownerDocument || e : w;
                            return n !== p && 9 === n.nodeType && n.documentElement
                                ? ((p = n),
                                  (f = n.documentElement),
                                  (d = a(n)),
                                  (T.tagNameNoComments = at(function (e) {
                                      return e.appendChild(n.createComment("")), !e.getElementsByTagName("*").length;
                                  })),
                                  (T.attributes = at(function (e) {
                                      e.innerHTML = "<select></select>";
                                      var t = typeof e.lastChild.getAttribute("multiple");
                                      return "boolean" !== t && "string" !== t;
                                  })),
                                  (T.getByClassName = at(function (e) {
                                      return (
                                          (e.innerHTML = "<div class='hidden e'></div><div class='hidden'></div>"),
                                          e.getElementsByClassName && e.getElementsByClassName("e").length
                                              ? ((e.lastChild.className = "e"),
                                                2 === e.getElementsByClassName("e").length)
                                              : !1
                                      );
                                  })),
                                  (T.getByName = at(function (e) {
                                      (e.id = x + 0),
                                          (e.innerHTML = "<a name='" + x + "'></a><div name='" + x + "'></div>"),
                                          f.insertBefore(e, f.firstChild);
                                      var t =
                                          n.getElementsByName &&
                                          n.getElementsByName(x).length === 2 + n.getElementsByName(x + 0).length;
                                      return (T.getIdNotName = !n.getElementById(x)), f.removeChild(e), t;
                                  })),
                                  (i.attrHandle = at(function (e) {
                                      return (
                                          (e.innerHTML = "<a href='#'></a>"),
                                          e.firstChild &&
                                              typeof e.firstChild.getAttribute !== A &&
                                              "#" === e.firstChild.getAttribute("href")
                                      );
                                  })
                                      ? {}
                                      : {
                                            href: function (e) {
                                                return e.getAttribute("href", 2);
                                            },
                                            type: function (e) {
                                                return e.getAttribute("type");
                                            },
                                        }),
                                  T.getIdNotName
                                      ? ((i.find.ID = function (e, t) {
                                            if (typeof t.getElementById !== A && !d) {
                                                var n = t.getElementById(e);
                                                return n && n.parentNode ? [n] : [];
                                            }
                                        }),
                                        (i.filter.ID = function (e) {
                                            var t = e.replace(et, tt);
                                            return function (e) {
                                                return e.getAttribute("id") === t;
                                            };
                                        }))
                                      : ((i.find.ID = function (e, n) {
                                            if (typeof n.getElementById !== A && !d) {
                                                var r = n.getElementById(e);
                                                return r
                                                    ? r.id === e ||
                                                      (typeof r.getAttributeNode !== A &&
                                                          r.getAttributeNode("id").value === e)
                                                        ? [r]
                                                        : t
                                                    : [];
                                            }
                                        }),
                                        (i.filter.ID = function (e) {
                                            var t = e.replace(et, tt);
                                            return function (e) {
                                                var n = typeof e.getAttributeNode !== A && e.getAttributeNode("id");
                                                return n && n.value === t;
                                            };
                                        })),
                                  (i.find.TAG = T.tagNameNoComments
                                      ? function (e, n) {
                                            return typeof n.getElementsByTagName !== A ? n.getElementsByTagName(e) : t;
                                        }
                                      : function (e, t) {
                                            var n,
                                                r = [],
                                                i = 0,
                                                o = t.getElementsByTagName(e);
                                            if ("*" === e) {
                                                while ((n = o[i++])) 1 === n.nodeType && r.push(n);
                                                return r;
                                            }
                                            return o;
                                        }),
                                  (i.find.NAME =
                                      T.getByName &&
                                      function (e, n) {
                                          return typeof n.getElementsByName !== A ? n.getElementsByName(name) : t;
                                      }),
                                  (i.find.CLASS =
                                      T.getByClassName &&
                                      function (e, n) {
                                          return typeof n.getElementsByClassName === A || d
                                              ? t
                                              : n.getElementsByClassName(e);
                                      }),
                                  (g = []),
                                  (h = [":focus"]),
                                  (T.qsa = rt(n.querySelectorAll)) &&
                                      (at(function (e) {
                                          (e.innerHTML = "<select><option selected=''></option></select>"),
                                              e.querySelectorAll("[selected]").length ||
                                                  h.push(
                                                      "\\[" +
                                                          _ +
                                                          "*(?:checked|disabled|ismap|multiple|readonly|selected|value)"
                                                  ),
                                              e.querySelectorAll(":checked").length || h.push(":checked");
                                      }),
                                      at(function (e) {
                                          (e.innerHTML = "<input type='hidden' i=''/>"),
                                              e.querySelectorAll("[i^='']").length &&
                                                  h.push("[*^$]=" + _ + "*(?:\"\"|'')"),
                                              e.querySelectorAll(":enabled").length || h.push(":enabled", ":disabled"),
                                              e.querySelectorAll("*,:x"),
                                              h.push(",.*:");
                                      })),
                                  (T.matchesSelector = rt(
                                      (m =
                                          f.matchesSelector ||
                                          f.mozMatchesSelector ||
                                          f.webkitMatchesSelector ||
                                          f.oMatchesSelector ||
                                          f.msMatchesSelector)
                                  )) &&
                                      at(function (e) {
                                          (T.disconnectedMatch = m.call(e, "div")),
                                              m.call(e, "[s!='']:x"),
                                              g.push("!=", R);
                                      }),
                                  (h = RegExp(h.join("|"))),
                                  (g = RegExp(g.join("|"))),
                                  (y =
                                      rt(f.contains) || f.compareDocumentPosition
                                          ? function (e, t) {
                                                var n = 9 === e.nodeType ? e.documentElement : e,
                                                    r = t && t.parentNode;
                                                return (
                                                    e === r ||
                                                    !(
                                                        !r ||
                                                        1 !== r.nodeType ||
                                                        !(n.contains
                                                            ? n.contains(r)
                                                            : e.compareDocumentPosition &&
                                                              16 & e.compareDocumentPosition(r))
                                                    )
                                                );
                                            }
                                          : function (e, t) {
                                                if (t) while ((t = t.parentNode)) if (t === e) return !0;
                                                return !1;
                                            }),
                                  (v = f.compareDocumentPosition
                                      ? function (e, t) {
                                            var r;
                                            return e === t
                                                ? ((u = !0), 0)
                                                : (r =
                                                        t.compareDocumentPosition &&
                                                        e.compareDocumentPosition &&
                                                        e.compareDocumentPosition(t))
                                                  ? 1 & r || (e.parentNode && 11 === e.parentNode.nodeType)
                                                      ? e === n || y(w, e)
                                                          ? -1
                                                          : t === n || y(w, t)
                                                            ? 1
                                                            : 0
                                                      : 4 & r
                                                        ? -1
                                                        : 1
                                                  : e.compareDocumentPosition
                                                    ? -1
                                                    : 1;
                                        }
                                      : function (e, t) {
                                            var r,
                                                i = 0,
                                                o = e.parentNode,
                                                a = t.parentNode,
                                                s = [e],
                                                l = [t];
                                            if (e === t) return (u = !0), 0;
                                            if (!o || !a) return e === n ? -1 : t === n ? 1 : o ? -1 : a ? 1 : 0;
                                            if (o === a) return ut(e, t);
                                            r = e;
                                            while ((r = r.parentNode)) s.unshift(r);
                                            r = t;
                                            while ((r = r.parentNode)) l.unshift(r);
                                            while (s[i] === l[i]) i++;
                                            return i ? ut(s[i], l[i]) : s[i] === w ? -1 : l[i] === w ? 1 : 0;
                                        }),
                                  (u = !1),
                                  [0, 0].sort(v),
                                  (T.detectDuplicates = u),
                                  p)
                                : p;
                        }),
                    (st.matches = function (e, t) {
                        return st(e, null, null, t);
                    }),
                    (st.matchesSelector = function (e, t) {
                        if (
                            ((e.ownerDocument || e) !== p && c(e),
                            (t = t.replace(Z, "='$1']")),
                            !(!T.matchesSelector || d || (g && g.test(t)) || h.test(t)))
                        )
                            try {
                                var n = m.call(e, t);
                                if (n || T.disconnectedMatch || (e.document && 11 !== e.document.nodeType)) return n;
                            } catch (r) {}
                        return st(t, p, null, [e]).length > 0;
                    }),
                    (st.contains = function (e, t) {
                        return (e.ownerDocument || e) !== p && c(e), y(e, t);
                    }),
                    (st.attr = function (e, t) {
                        var n;
                        return (
                            (e.ownerDocument || e) !== p && c(e),
                            d || (t = t.toLowerCase()),
                            (n = i.attrHandle[t])
                                ? n(e)
                                : d || T.attributes
                                  ? e.getAttribute(t)
                                  : ((n = e.getAttributeNode(t)) || e.getAttribute(t)) && e[t] === !0
                                    ? t
                                    : n && n.specified
                                      ? n.value
                                      : null
                        );
                    }),
                    (st.error = function (e) {
                        throw Error("Syntax error, unrecognized expression: " + e);
                    }),
                    (st.uniqueSort = function (e) {
                        var t,
                            n = [],
                            r = 1,
                            i = 0;
                        if (((u = !T.detectDuplicates), e.sort(v), u)) {
                            for (; (t = e[r]); r++) t === e[r - 1] && (i = n.push(r));
                            while (i--) e.splice(n[i], 1);
                        }
                        return e;
                    });
                function ut(e, t) {
                    var n = t && e,
                        r = n && (~t.sourceIndex || j) - (~e.sourceIndex || j);
                    if (r) return r;
                    if (n) while ((n = n.nextSibling)) if (n === t) return -1;
                    return e ? 1 : -1;
                }
                function lt(e) {
                    return function (t) {
                        var n = t.nodeName.toLowerCase();
                        return "input" === n && t.type === e;
                    };
                }
                function ct(e) {
                    return function (t) {
                        var n = t.nodeName.toLowerCase();
                        return ("input" === n || "button" === n) && t.type === e;
                    };
                }
                function pt(e) {
                    return ot(function (t) {
                        return (
                            (t = +t),
                            ot(function (n, r) {
                                var i,
                                    o = e([], n.length, t),
                                    a = o.length;
                                while (a--) n[(i = o[a])] && (n[i] = !(r[i] = n[i]));
                            })
                        );
                    });
                }
                (o = st.getText =
                    function (e) {
                        var t,
                            n = "",
                            r = 0,
                            i = e.nodeType;
                        if (i) {
                            if (1 === i || 9 === i || 11 === i) {
                                if ("string" == typeof e.textContent) return e.textContent;
                                for (e = e.firstChild; e; e = e.nextSibling) n += o(e);
                            } else if (3 === i || 4 === i) return e.nodeValue;
                        } else for (; (t = e[r]); r++) n += o(t);
                        return n;
                    }),
                    (i = st.selectors =
                        {
                            cacheLength: 50,
                            createPseudo: ot,
                            match: U,
                            find: {},
                            relative: {
                                ">": { dir: "parentNode", first: !0 },
                                " ": { dir: "parentNode" },
                                "+": { dir: "previousSibling", first: !0 },
                                "~": { dir: "previousSibling" },
                            },
                            preFilter: {
                                ATTR: function (e) {
                                    return (
                                        (e[1] = e[1].replace(et, tt)),
                                        (e[3] = (e[4] || e[5] || "").replace(et, tt)),
                                        "~=" === e[2] && (e[3] = " " + e[3] + " "),
                                        e.slice(0, 4)
                                    );
                                },
                                CHILD: function (e) {
                                    return (
                                        (e[1] = e[1].toLowerCase()),
                                        "nth" === e[1].slice(0, 3)
                                            ? (e[3] || st.error(e[0]),
                                              (e[4] = +(e[4]
                                                  ? e[5] + (e[6] || 1)
                                                  : 2 * ("even" === e[3] || "odd" === e[3]))),
                                              (e[5] = +(e[7] + e[8] || "odd" === e[3])))
                                            : e[3] && st.error(e[0]),
                                        e
                                    );
                                },
                                PSEUDO: function (e) {
                                    var t,
                                        n = !e[5] && e[2];
                                    return U.CHILD.test(e[0])
                                        ? null
                                        : (e[4]
                                              ? (e[2] = e[4])
                                              : n &&
                                                z.test(n) &&
                                                (t = ft(n, !0)) &&
                                                (t = n.indexOf(")", n.length - t) - n.length) &&
                                                ((e[0] = e[0].slice(0, t)), (e[2] = n.slice(0, t))),
                                          e.slice(0, 3));
                                },
                            },
                            filter: {
                                TAG: function (e) {
                                    return "*" === e
                                        ? function () {
                                              return !0;
                                          }
                                        : ((e = e.replace(et, tt).toLowerCase()),
                                          function (t) {
                                              return t.nodeName && t.nodeName.toLowerCase() === e;
                                          });
                                },
                                CLASS: function (e) {
                                    var t = k[e + " "];
                                    return (
                                        t ||
                                        ((t = RegExp("(^|" + _ + ")" + e + "(" + _ + "|$)")) &&
                                            k(e, function (e) {
                                                return t.test(
                                                    e.className ||
                                                        (typeof e.getAttribute !== A && e.getAttribute("class")) ||
                                                        ""
                                                );
                                            }))
                                    );
                                },
                                ATTR: function (e, t, n) {
                                    return function (r) {
                                        var i = st.attr(r, e);
                                        return null == i
                                            ? "!=" === t
                                            : t
                                              ? ((i += ""),
                                                "=" === t
                                                    ? i === n
                                                    : "!=" === t
                                                      ? i !== n
                                                      : "^=" === t
                                                        ? n && 0 === i.indexOf(n)
                                                        : "*=" === t
                                                          ? n && i.indexOf(n) > -1
                                                          : "$=" === t
                                                            ? n && i.slice(-n.length) === n
                                                            : "~=" === t
                                                              ? (" " + i + " ").indexOf(n) > -1
                                                              : "|=" === t
                                                                ? i === n || i.slice(0, n.length + 1) === n + "-"
                                                                : !1)
                                              : !0;
                                    };
                                },
                                CHILD: function (e, t, n, r, i) {
                                    var o = "nth" !== e.slice(0, 3),
                                        a = "last" !== e.slice(-4),
                                        s = "of-type" === t;
                                    return 1 === r && 0 === i
                                        ? function (e) {
                                              return !!e.parentNode;
                                          }
                                        : function (t, n, u) {
                                              var l,
                                                  c,
                                                  p,
                                                  f,
                                                  d,
                                                  h,
                                                  g = o !== a ? "nextSibling" : "previousSibling",
                                                  m = t.parentNode,
                                                  y = s && t.nodeName.toLowerCase(),
                                                  v = !u && !s;
                                              if (m) {
                                                  if (o) {
                                                      while (g) {
                                                          p = t;
                                                          while ((p = p[g]))
                                                              if (s ? p.nodeName.toLowerCase() === y : 1 === p.nodeType)
                                                                  return !1;
                                                          h = g = "only" === e && !h && "nextSibling";
                                                      }
                                                      return !0;
                                                  }
                                                  if (((h = [a ? m.firstChild : m.lastChild]), a && v)) {
                                                      (c = m[x] || (m[x] = {})),
                                                          (l = c[e] || []),
                                                          (d = l[0] === N && l[1]),
                                                          (f = l[0] === N && l[2]),
                                                          (p = d && m.childNodes[d]);
                                                      while ((p = (++d && p && p[g]) || (f = d = 0) || h.pop()))
                                                          if (1 === p.nodeType && ++f && p === t) {
                                                              c[e] = [N, d, f];
                                                              break;
                                                          }
                                                  } else if (v && (l = (t[x] || (t[x] = {}))[e]) && l[0] === N)
                                                      f = l[1];
                                                  else
                                                      while ((p = (++d && p && p[g]) || (f = d = 0) || h.pop()))
                                                          if (
                                                              (s ? p.nodeName.toLowerCase() === y : 1 === p.nodeType) &&
                                                              ++f &&
                                                              (v && ((p[x] || (p[x] = {}))[e] = [N, f]), p === t)
                                                          )
                                                              break;
                                                  return (f -= i), f === r || (0 === f % r && f / r >= 0);
                                              }
                                          };
                                },
                                PSEUDO: function (e, t) {
                                    var n,
                                        r =
                                            i.pseudos[e] ||
                                            i.setFilters[e.toLowerCase()] ||
                                            st.error("unsupported pseudo: " + e);
                                    return r[x]
                                        ? r(t)
                                        : r.length > 1
                                          ? ((n = [e, e, "", t]),
                                            i.setFilters.hasOwnProperty(e.toLowerCase())
                                                ? ot(function (e, n) {
                                                      var i,
                                                          o = r(e, t),
                                                          a = o.length;
                                                      while (a--) (i = M.call(e, o[a])), (e[i] = !(n[i] = o[a]));
                                                  })
                                                : function (e) {
                                                      return r(e, 0, n);
                                                  })
                                          : r;
                                },
                            },
                            pseudos: {
                                not: ot(function (e) {
                                    var t = [],
                                        n = [],
                                        r = s(e.replace(W, "$1"));
                                    return r[x]
                                        ? ot(function (e, t, n, i) {
                                              var o,
                                                  a = r(e, null, i, []),
                                                  s = e.length;
                                              while (s--) (o = a[s]) && (e[s] = !(t[s] = o));
                                          })
                                        : function (e, i, o) {
                                              return (t[0] = e), r(t, null, o, n), !n.pop();
                                          };
                                }),
                                has: ot(function (e) {
                                    return function (t) {
                                        return st(e, t).length > 0;
                                    };
                                }),
                                contains: ot(function (e) {
                                    return function (t) {
                                        return (t.textContent || t.innerText || o(t)).indexOf(e) > -1;
                                    };
                                }),
                                lang: ot(function (e) {
                                    return (
                                        X.test(e || "") || st.error("unsupported lang: " + e),
                                        (e = e.replace(et, tt).toLowerCase()),
                                        function (t) {
                                            var n;
                                            do
                                                if (
                                                    (n = d
                                                        ? t.getAttribute("xml:lang") || t.getAttribute("lang")
                                                        : t.lang)
                                                )
                                                    return (n = n.toLowerCase()), n === e || 0 === n.indexOf(e + "-");
                                            while ((t = t.parentNode) && 1 === t.nodeType);
                                            return !1;
                                        }
                                    );
                                }),
                                target: function (t) {
                                    var n = e.location && e.location.hash;
                                    return n && n.slice(1) === t.id;
                                },
                                root: function (e) {
                                    return e === f;
                                },
                                focus: function (e) {
                                    return (
                                        e === p.activeElement &&
                                        (!p.hasFocus || p.hasFocus()) &&
                                        !!(e.type || e.href || ~e.tabIndex)
                                    );
                                },
                                enabled: function (e) {
                                    return e.disabled === !1;
                                },
                                disabled: function (e) {
                                    return e.disabled === !0;
                                },
                                checked: function (e) {
                                    var t = e.nodeName.toLowerCase();
                                    return ("input" === t && !!e.checked) || ("option" === t && !!e.selected);
                                },
                                selected: function (e) {
                                    return e.parentNode && e.parentNode.selectedIndex, e.selected === !0;
                                },
                                empty: function (e) {
                                    for (e = e.firstChild; e; e = e.nextSibling)
                                        if (e.nodeName > "@" || 3 === e.nodeType || 4 === e.nodeType) return !1;
                                    return !0;
                                },
                                parent: function (e) {
                                    return !i.pseudos.empty(e);
                                },
                                header: function (e) {
                                    return Q.test(e.nodeName);
                                },
                                input: function (e) {
                                    return G.test(e.nodeName);
                                },
                                button: function (e) {
                                    var t = e.nodeName.toLowerCase();
                                    return ("input" === t && "button" === e.type) || "button" === t;
                                },
                                text: function (e) {
                                    var t;
                                    return (
                                        "input" === e.nodeName.toLowerCase() &&
                                        "text" === e.type &&
                                        (null == (t = e.getAttribute("type")) || t.toLowerCase() === e.type)
                                    );
                                },
                                first: pt(function () {
                                    return [0];
                                }),
                                last: pt(function (e, t) {
                                    return [t - 1];
                                }),
                                eq: pt(function (e, t, n) {
                                    return [0 > n ? n + t : n];
                                }),
                                even: pt(function (e, t) {
                                    var n = 0;
                                    for (; t > n; n += 2) e.push(n);
                                    return e;
                                }),
                                odd: pt(function (e, t) {
                                    var n = 1;
                                    for (; t > n; n += 2) e.push(n);
                                    return e;
                                }),
                                lt: pt(function (e, t, n) {
                                    var r = 0 > n ? n + t : n;
                                    for (; --r >= 0; ) e.push(r);
                                    return e;
                                }),
                                gt: pt(function (e, t, n) {
                                    var r = 0 > n ? n + t : n;
                                    for (; t > ++r; ) e.push(r);
                                    return e;
                                }),
                            },
                        });
                for (n in { radio: !0, checkbox: !0, file: !0, password: !0, image: !0 }) i.pseudos[n] = lt(n);
                for (n in { submit: !0, reset: !0 }) i.pseudos[n] = ct(n);
                function ft(e, t) {
                    var n,
                        r,
                        o,
                        a,
                        s,
                        u,
                        l,
                        c = E[e + " "];
                    if (c) return t ? 0 : c.slice(0);
                    (s = e), (u = []), (l = i.preFilter);
                    while (s) {
                        (!n || (r = $.exec(s))) && (r && (s = s.slice(r[0].length) || s), u.push((o = []))),
                            (n = !1),
                            (r = I.exec(s)) &&
                                ((n = r.shift()),
                                o.push({ value: n, type: r[0].replace(W, " ") }),
                                (s = s.slice(n.length)));
                        for (a in i.filter)
                            !(r = U[a].exec(s)) ||
                                (l[a] && !(r = l[a](r))) ||
                                ((n = r.shift()), o.push({ value: n, type: a, matches: r }), (s = s.slice(n.length)));
                        if (!n) break;
                    }
                    return t ? s.length : s ? st.error(e) : E(e, u).slice(0);
                }
                function dt(e) {
                    var t = 0,
                        n = e.length,
                        r = "";
                    for (; n > t; t++) r += e[t].value;
                    return r;
                }
                function ht(e, t, n) {
                    var i = t.dir,
                        o = n && "parentNode" === i,
                        a = C++;
                    return t.first
                        ? function (t, n, r) {
                              while ((t = t[i])) if (1 === t.nodeType || o) return e(t, n, r);
                          }
                        : function (t, n, s) {
                              var u,
                                  l,
                                  c,
                                  p = N + " " + a;
                              if (s) {
                                  while ((t = t[i])) if ((1 === t.nodeType || o) && e(t, n, s)) return !0;
                              } else
                                  while ((t = t[i]))
                                      if (1 === t.nodeType || o)
                                          if (((c = t[x] || (t[x] = {})), (l = c[i]) && l[0] === p)) {
                                              if ((u = l[1]) === !0 || u === r) return u === !0;
                                          } else if (((l = c[i] = [p]), (l[1] = e(t, n, s) || r), l[1] === !0))
                                              return !0;
                          };
                }
                function gt(e) {
                    return e.length > 1
                        ? function (t, n, r) {
                              var i = e.length;
                              while (i--) if (!e[i](t, n, r)) return !1;
                              return !0;
                          }
                        : e[0];
                }
                function mt(e, t, n, r, i) {
                    var o,
                        a = [],
                        s = 0,
                        u = e.length,
                        l = null != t;
                    for (; u > s; s++) (o = e[s]) && (!n || n(o, r, i)) && (a.push(o), l && t.push(s));
                    return a;
                }
                function yt(e, t, n, r, i, o) {
                    return (
                        r && !r[x] && (r = yt(r)),
                        i && !i[x] && (i = yt(i, o)),
                        ot(function (o, a, s, u) {
                            var l,
                                c,
                                p,
                                f = [],
                                d = [],
                                h = a.length,
                                g = o || xt(t || "*", s.nodeType ? [s] : s, []),
                                m = !e || (!o && t) ? g : mt(g, f, e, s, u),
                                y = n ? (i || (o ? e : h || r) ? [] : a) : m;
                            if ((n && n(m, y, s, u), r)) {
                                (l = mt(y, d)), r(l, [], s, u), (c = l.length);
                                while (c--) (p = l[c]) && (y[d[c]] = !(m[d[c]] = p));
                            }
                            if (o) {
                                if (i || e) {
                                    if (i) {
                                        (l = []), (c = y.length);
                                        while (c--) (p = y[c]) && l.push((m[c] = p));
                                        i(null, (y = []), l, u);
                                    }
                                    c = y.length;
                                    while (c--)
                                        (p = y[c]) && (l = i ? M.call(o, p) : f[c]) > -1 && (o[l] = !(a[l] = p));
                                }
                            } else (y = mt(y === a ? y.splice(h, y.length) : y)), i ? i(null, a, y, u) : H.apply(a, y);
                        })
                    );
                }
                function vt(e) {
                    var t,
                        n,
                        r,
                        o = e.length,
                        a = i.relative[e[0].type],
                        s = a || i.relative[" "],
                        u = a ? 1 : 0,
                        c = ht(
                            function (e) {
                                return e === t;
                            },
                            s,
                            !0
                        ),
                        p = ht(
                            function (e) {
                                return M.call(t, e) > -1;
                            },
                            s,
                            !0
                        ),
                        f = [
                            function (e, n, r) {
                                return (!a && (r || n !== l)) || ((t = n).nodeType ? c(e, n, r) : p(e, n, r));
                            },
                        ];
                    for (; o > u; u++)
                        if ((n = i.relative[e[u].type])) f = [ht(gt(f), n)];
                        else {
                            if (((n = i.filter[e[u].type].apply(null, e[u].matches)), n[x])) {
                                for (r = ++u; o > r; r++) if (i.relative[e[r].type]) break;
                                return yt(
                                    u > 1 && gt(f),
                                    u > 1 && dt(e.slice(0, u - 1)).replace(W, "$1"),
                                    n,
                                    r > u && vt(e.slice(u, r)),
                                    o > r && vt((e = e.slice(r))),
                                    o > r && dt(e)
                                );
                            }
                            f.push(n);
                        }
                    return gt(f);
                }
                function bt(e, t) {
                    var n = 0,
                        o = t.length > 0,
                        a = e.length > 0,
                        s = function (s, u, c, f, d) {
                            var h,
                                g,
                                m,
                                y = [],
                                v = 0,
                                b = "0",
                                x = s && [],
                                w = null != d,
                                T = l,
                                C = s || (a && i.find.TAG("*", (d && u.parentNode) || u)),
                                k = (N += null == T ? 1 : Math.random() || 0.1);
                            for (w && ((l = u !== p && u), (r = n)); null != (h = C[b]); b++) {
                                if (a && h) {
                                    g = 0;
                                    while ((m = e[g++]))
                                        if (m(h, u, c)) {
                                            f.push(h);
                                            break;
                                        }
                                    w && ((N = k), (r = ++n));
                                }
                                o && ((h = !m && h) && v--, s && x.push(h));
                            }
                            if (((v += b), o && b !== v)) {
                                g = 0;
                                while ((m = t[g++])) m(x, y, u, c);
                                if (s) {
                                    if (v > 0) while (b--) x[b] || y[b] || (y[b] = L.call(f));
                                    y = mt(y);
                                }
                                H.apply(f, y), w && !s && y.length > 0 && v + t.length > 1 && st.uniqueSort(f);
                            }
                            return w && ((N = k), (l = T)), x;
                        };
                    return o ? ot(s) : s;
                }
                s = st.compile = function (e, t) {
                    var n,
                        r = [],
                        i = [],
                        o = S[e + " "];
                    if (!o) {
                        t || (t = ft(e)), (n = t.length);
                        while (n--) (o = vt(t[n])), o[x] ? r.push(o) : i.push(o);
                        o = S(e, bt(i, r));
                    }
                    return o;
                };
                function xt(e, t, n) {
                    var r = 0,
                        i = t.length;
                    for (; i > r; r++) st(e, t[r], n);
                    return n;
                }
                function wt(e, t, n, r) {
                    var o,
                        a,
                        u,
                        l,
                        c,
                        p = ft(e);
                    if (!r && 1 === p.length) {
                        if (
                            ((a = p[0] = p[0].slice(0)),
                            a.length > 2 && "ID" === (u = a[0]).type && 9 === t.nodeType && !d && i.relative[a[1].type])
                        ) {
                            if (((t = i.find.ID(u.matches[0].replace(et, tt), t)[0]), !t)) return n;
                            e = e.slice(a.shift().value.length);
                        }
                        o = U.needsContext.test(e) ? 0 : a.length;
                        while (o--) {
                            if (((u = a[o]), i.relative[(l = u.type)])) break;
                            if (
                                (c = i.find[l]) &&
                                (r = c(u.matches[0].replace(et, tt), (V.test(a[0].type) && t.parentNode) || t))
                            ) {
                                if ((a.splice(o, 1), (e = r.length && dt(a)), !e)) return H.apply(n, q.call(r, 0)), n;
                                break;
                            }
                        }
                    }
                    return s(e, p)(r, t, d, n, V.test(e)), n;
                }
                i.pseudos.nth = i.pseudos.eq;
                function Tt() {}
                (i.filters = Tt.prototype = i.pseudos),
                    (i.setFilters = new Tt()),
                    c(),
                    (st.attr = b.attr),
                    (b.find = st),
                    (b.expr = st.selectors),
                    (b.expr[":"] = b.expr.pseudos),
                    (b.unique = st.uniqueSort),
                    (b.text = st.getText),
                    (b.isXMLDoc = st.isXML),
                    (b.contains = st.contains);
            })(e);
        var at = /Until$/,
            st = /^(?:parents|prev(?:Until|All))/,
            ut = /^.[^:#\[\.,]*$/,
            lt = b.expr.match.needsContext,
            ct = { children: !0, contents: !0, next: !0, prev: !0 };
        b.fn.extend({
            find: function (e) {
                var t,
                    n,
                    r,
                    i = this.length;
                if ("string" != typeof e)
                    return (
                        (r = this),
                        this.pushStack(
                            b(e).filter(function () {
                                for (t = 0; i > t; t++) if (b.contains(r[t], this)) return !0;
                            })
                        )
                    );
                for (n = [], t = 0; i > t; t++) b.find(e, this[t], n);
                return (
                    (n = this.pushStack(i > 1 ? b.unique(n) : n)),
                    (n.selector = (this.selector ? this.selector + " " : "") + e),
                    n
                );
            },
            has: function (e) {
                var t,
                    n = b(e, this),
                    r = n.length;
                return this.filter(function () {
                    for (t = 0; r > t; t++) if (b.contains(this, n[t])) return !0;
                });
            },
            not: function (e) {
                return this.pushStack(ft(this, e, !1));
            },
            filter: function (e) {
                return this.pushStack(ft(this, e, !0));
            },
            is: function (e) {
                return (
                    !!e &&
                    ("string" == typeof e
                        ? lt.test(e)
                            ? b(e, this.context).index(this[0]) >= 0
                            : b.filter(e, this).length > 0
                        : this.filter(e).length > 0)
                );
            },
            closest: function (e, t) {
                var n,
                    r = 0,
                    i = this.length,
                    o = [],
                    a = lt.test(e) || "string" != typeof e ? b(e, t || this.context) : 0;
                for (; i > r; r++) {
                    n = this[r];
                    while (n && n.ownerDocument && n !== t && 11 !== n.nodeType) {
                        if (a ? a.index(n) > -1 : b.find.matchesSelector(n, e)) {
                            o.push(n);
                            break;
                        }
                        n = n.parentNode;
                    }
                }
                return this.pushStack(o.length > 1 ? b.unique(o) : o);
            },
            index: function (e) {
                return e
                    ? "string" == typeof e
                        ? b.inArray(this[0], b(e))
                        : b.inArray(e.jquery ? e[0] : e, this)
                    : this[0] && this[0].parentNode
                      ? this.first().prevAll().length
                      : -1;
            },
            add: function (e, t) {
                var n = "string" == typeof e ? b(e, t) : b.makeArray(e && e.nodeType ? [e] : e),
                    r = b.merge(this.get(), n);
                return this.pushStack(b.unique(r));
            },
            addBack: function (e) {
                return this.add(null == e ? this.prevObject : this.prevObject.filter(e));
            },
        }),
            (b.fn.andSelf = b.fn.addBack);
        function pt(e, t) {
            do e = e[t];
            while (e && 1 !== e.nodeType);
            return e;
        }
        b.each(
            {
                parent: function (e) {
                    var t = e.parentNode;
                    return t && 11 !== t.nodeType ? t : null;
                },
                parents: function (e) {
                    return b.dir(e, "parentNode");
                },
                parentsUntil: function (e, t, n) {
                    return b.dir(e, "parentNode", n);
                },
                next: function (e) {
                    return pt(e, "nextSibling");
                },
                prev: function (e) {
                    return pt(e, "previousSibling");
                },
                nextAll: function (e) {
                    return b.dir(e, "nextSibling");
                },
                prevAll: function (e) {
                    return b.dir(e, "previousSibling");
                },
                nextUntil: function (e, t, n) {
                    return b.dir(e, "nextSibling", n);
                },
                prevUntil: function (e, t, n) {
                    return b.dir(e, "previousSibling", n);
                },
                siblings: function (e) {
                    return b.sibling((e.parentNode || {}).firstChild, e);
                },
                children: function (e) {
                    return b.sibling(e.firstChild);
                },
                contents: function (e) {
                    return b.nodeName(e, "iframe")
                        ? e.contentDocument || e.contentWindow.document
                        : b.merge([], e.childNodes);
                },
            },
            function (e, t) {
                b.fn[e] = function (n, r) {
                    var i = b.map(this, t, n);
                    return (
                        at.test(e) || (r = n),
                        r && "string" == typeof r && (i = b.filter(r, i)),
                        (i = this.length > 1 && !ct[e] ? b.unique(i) : i),
                        this.length > 1 && st.test(e) && (i = i.reverse()),
                        this.pushStack(i)
                    );
                };
            }
        ),
            b.extend({
                filter: function (e, t, n) {
                    return (
                        n && (e = ":not(" + e + ")"),
                        1 === t.length ? (b.find.matchesSelector(t[0], e) ? [t[0]] : []) : b.find.matches(e, t)
                    );
                },
                dir: function (e, n, r) {
                    var i = [],
                        o = e[n];
                    while (o && 9 !== o.nodeType && (r === t || 1 !== o.nodeType || !b(o).is(r)))
                        1 === o.nodeType && i.push(o), (o = o[n]);
                    return i;
                },
                sibling: function (e, t) {
                    var n = [];
                    for (; e; e = e.nextSibling) 1 === e.nodeType && e !== t && n.push(e);
                    return n;
                },
            });
        function ft(e, t, n) {
            if (((t = t || 0), b.isFunction(t)))
                return b.grep(e, function (e, r) {
                    var i = !!t.call(e, r, e);
                    return i === n;
                });
            if (t.nodeType)
                return b.grep(e, function (e) {
                    return (e === t) === n;
                });
            if ("string" == typeof t) {
                var r = b.grep(e, function (e) {
                    return 1 === e.nodeType;
                });
                if (ut.test(t)) return b.filter(t, r, !n);
                t = b.filter(t, r);
            }
            return b.grep(e, function (e) {
                return b.inArray(e, t) >= 0 === n;
            });
        }
        function dt(e) {
            var t = ht.split("|"),
                n = e.createDocumentFragment();
            if (n.createElement) while (t.length) n.createElement(t.pop());
            return n;
        }
        var ht =
                "abbr|article|aside|audio|bdi|canvas|data|datalist|details|figcaption|figure|footer|header|hgroup|mark|meter|nav|output|progress|section|summary|time|video",
            gt = / jQuery\d+="(?:null|\d+)"/g,
            mt = RegExp("<(?:" + ht + ")[\\s/>]", "i"),
            yt = /^\s+/,
            vt = /<(?!area|br|col|embed|hr|img|input|link|meta|param)(([\w:]+)[^>]*)\/>/gi,
            bt = /<([\w:]+)/,
            xt = /<tbody/i,
            wt = /<|&#?\w+;/,
            Tt = /<(?:script|style|link)/i,
            Nt = /^(?:checkbox|radio)$/i,
            Ct = /checked\s*(?:[^=]|=\s*.checked.)/i,
            kt = /^$|\/(?:java|ecma)script/i,
            Et = /^true\/(.*)/,
            St = /^\s*<!(?:\[CDATA\[|--)|(?:\]\]|--)>\s*$/g,
            At = {
                option: [1, "<select multiple='multiple'>", "</select>"],
                legend: [1, "<fieldset>", "</fieldset>"],
                area: [1, "<map>", "</map>"],
                param: [1, "<object>", "</object>"],
                thead: [1, "<table>", "</table>"],
                tr: [2, "<table><tbody>", "</tbody></table>"],
                col: [2, "<table><tbody></tbody><colgroup>", "</colgroup></table>"],
                td: [3, "<table><tbody><tr>", "</tr></tbody></table>"],
                _default: b.support.htmlSerialize ? [0, "", ""] : [1, "X<div>", "</div>"],
            },
            jt = dt(o),
            Dt = jt.appendChild(o.createElement("div"));
        (At.optgroup = At.option),
            (At.tbody = At.tfoot = At.colgroup = At.caption = At.thead),
            (At.th = At.td),
            b.fn.extend({
                text: function (e) {
                    return b.access(
                        this,
                        function (e) {
                            return e === t
                                ? b.text(this)
                                : this.empty().append(((this[0] && this[0].ownerDocument) || o).createTextNode(e));
                        },
                        null,
                        e,
                        arguments.length
                    );
                },
                wrapAll: function (e) {
                    if (b.isFunction(e))
                        return this.each(function (t) {
                            b(this).wrapAll(e.call(this, t));
                        });
                    if (this[0]) {
                        var t = b(e, this[0].ownerDocument).eq(0).clone(!0);
                        this[0].parentNode && t.insertBefore(this[0]),
                            t
                                .map(function () {
                                    var e = this;
                                    while (e.firstChild && 1 === e.firstChild.nodeType) e = e.firstChild;
                                    return e;
                                })
                                .append(this);
                    }
                    return this;
                },
                wrapInner: function (e) {
                    return b.isFunction(e)
                        ? this.each(function (t) {
                              b(this).wrapInner(e.call(this, t));
                          })
                        : this.each(function () {
                              var t = b(this),
                                  n = t.contents();
                              n.length ? n.wrapAll(e) : t.append(e);
                          });
                },
                wrap: function (e) {
                    var t = b.isFunction(e);
                    return this.each(function (n) {
                        b(this).wrapAll(t ? e.call(this, n) : e);
                    });
                },
                unwrap: function () {
                    return this.parent()
                        .each(function () {
                            b.nodeName(this, "body") || b(this).replaceWith(this.childNodes);
                        })
                        .end();
                },
                append: function () {
                    return this.domManip(arguments, !0, function (e) {
                        (1 === this.nodeType || 11 === this.nodeType || 9 === this.nodeType) && this.appendChild(e);
                    });
                },
                prepend: function () {
                    return this.domManip(arguments, !0, function (e) {
                        (1 === this.nodeType || 11 === this.nodeType || 9 === this.nodeType) &&
                            this.insertBefore(e, this.firstChild);
                    });
                },
                before: function () {
                    return this.domManip(arguments, !1, function (e) {
                        this.parentNode && this.parentNode.insertBefore(e, this);
                    });
                },
                after: function () {
                    return this.domManip(arguments, !1, function (e) {
                        this.parentNode && this.parentNode.insertBefore(e, this.nextSibling);
                    });
                },
                remove: function (e, t) {
                    var n,
                        r = 0;
                    for (; null != (n = this[r]); r++)
                        (!e || b.filter(e, [n]).length > 0) &&
                            (t || 1 !== n.nodeType || b.cleanData(Ot(n)),
                            n.parentNode &&
                                (t && b.contains(n.ownerDocument, n) && Mt(Ot(n, "script")),
                                n.parentNode.removeChild(n)));
                    return this;
                },
                empty: function () {
                    var e,
                        t = 0;
                    for (; null != (e = this[t]); t++) {
                        1 === e.nodeType && b.cleanData(Ot(e, !1));
                        while (e.firstChild) e.removeChild(e.firstChild);
                        e.options && b.nodeName(e, "select") && (e.options.length = 0);
                    }
                    return this;
                },
                clone: function (e, t) {
                    return (
                        (e = null == e ? !1 : e),
                        (t = null == t ? e : t),
                        this.map(function () {
                            return b.clone(this, e, t);
                        })
                    );
                },
                html: function (e) {
                    return b.access(
                        this,
                        function (e) {
                            var n = this[0] || {},
                                r = 0,
                                i = this.length;
                            if (e === t) return 1 === n.nodeType ? n.innerHTML.replace(gt, "") : t;
                            if (
                                !(
                                    "string" != typeof e ||
                                    Tt.test(e) ||
                                    (!b.support.htmlSerialize && mt.test(e)) ||
                                    (!b.support.leadingWhitespace && yt.test(e)) ||
                                    At[(bt.exec(e) || ["", ""])[1].toLowerCase()]
                                )
                            ) {
                                e = e.replace(vt, "<$1></$2>");
                                try {
                                    for (; i > r; r++)
                                        (n = this[r] || {}),
                                            1 === n.nodeType && (b.cleanData(Ot(n, !1)), (n.innerHTML = e));
                                    n = 0;
                                } catch (o) {}
                            }
                            n && this.empty().append(e);
                        },
                        null,
                        e,
                        arguments.length
                    );
                },
                replaceWith: function (e) {
                    var t = b.isFunction(e);
                    return (
                        t || "string" == typeof e || (e = b(e).not(this).detach()),
                        this.domManip([e], !0, function (e) {
                            var t = this.nextSibling,
                                n = this.parentNode;
                            n && (b(this).remove(), n.insertBefore(e, t));
                        })
                    );
                },
                detach: function (e) {
                    return this.remove(e, !0);
                },
                domManip: function (e, n, r) {
                    e = f.apply([], e);
                    var i,
                        o,
                        a,
                        s,
                        u,
                        l,
                        c = 0,
                        p = this.length,
                        d = this,
                        h = p - 1,
                        g = e[0],
                        m = b.isFunction(g);
                    if (m || (!(1 >= p || "string" != typeof g || b.support.checkClone) && Ct.test(g)))
                        return this.each(function (i) {
                            var o = d.eq(i);
                            m && (e[0] = g.call(this, i, n ? o.html() : t)), o.domManip(e, n, r);
                        });
                    if (
                        p &&
                        ((l = b.buildFragment(e, this[0].ownerDocument, !1, this)),
                        (i = l.firstChild),
                        1 === l.childNodes.length && (l = i),
                        i)
                    ) {
                        for (n = n && b.nodeName(i, "tr"), s = b.map(Ot(l, "script"), Ht), a = s.length; p > c; c++)
                            (o = l),
                                c !== h && ((o = b.clone(o, !0, !0)), a && b.merge(s, Ot(o, "script"))),
                                r.call(n && b.nodeName(this[c], "table") ? Lt(this[c], "tbody") : this[c], o, c);
                        if (a)
                            for (u = s[s.length - 1].ownerDocument, b.map(s, qt), c = 0; a > c; c++)
                                (o = s[c]),
                                    kt.test(o.type || "") &&
                                        !b._data(o, "globalEval") &&
                                        b.contains(u, o) &&
                                        (o.src
                                            ? b.ajax({
                                                  url: o.src,
                                                  type: "GET",
                                                  dataType: "script",
                                                  async: !1,
                                                  global: !1,
                                                  throws: !0,
                                              })
                                            : b.globalEval(
                                                  (o.text || o.textContent || o.innerHTML || "").replace(St, "")
                                              ));
                        l = i = null;
                    }
                    return this;
                },
            });
        function Lt(e, t) {
            return e.getElementsByTagName(t)[0] || e.appendChild(e.ownerDocument.createElement(t));
        }
        function Ht(e) {
            var t = e.getAttributeNode("type");
            return (e.type = (t && t.specified) + "/" + e.type), e;
        }
        function qt(e) {
            var t = Et.exec(e.type);
            return t ? (e.type = t[1]) : e.removeAttribute("type"), e;
        }
        function Mt(e, t) {
            var n,
                r = 0;
            for (; null != (n = e[r]); r++) b._data(n, "globalEval", !t || b._data(t[r], "globalEval"));
        }
        function _t(e, t) {
            if (1 === t.nodeType && b.hasData(e)) {
                var n,
                    r,
                    i,
                    o = b._data(e),
                    a = b._data(t, o),
                    s = o.events;
                if (s) {
                    delete a.handle, (a.events = {});
                    for (n in s) for (r = 0, i = s[n].length; i > r; r++) b.event.add(t, n, s[n][r]);
                }
                a.data && (a.data = b.extend({}, a.data));
            }
        }
        function Ft(e, t) {
            var n, r, i;
            if (1 === t.nodeType) {
                if (((n = t.nodeName.toLowerCase()), !b.support.noCloneEvent && t[b.expando])) {
                    i = b._data(t);
                    for (r in i.events) b.removeEvent(t, r, i.handle);
                    t.removeAttribute(b.expando);
                }
                "script" === n && t.text !== e.text
                    ? ((Ht(t).text = e.text), qt(t))
                    : "object" === n
                      ? (t.parentNode && (t.outerHTML = e.outerHTML),
                        b.support.html5Clone && e.innerHTML && !b.trim(t.innerHTML) && (t.innerHTML = e.innerHTML))
                      : "input" === n && Nt.test(e.type)
                        ? ((t.defaultChecked = t.checked = e.checked), t.value !== e.value && (t.value = e.value))
                        : "option" === n
                          ? (t.defaultSelected = t.selected = e.defaultSelected)
                          : ("input" === n || "textarea" === n) && (t.defaultValue = e.defaultValue);
            }
        }
        b.each(
            {
                appendTo: "append",
                prependTo: "prepend",
                insertBefore: "before",
                insertAfter: "after",
                replaceAll: "replaceWith",
            },
            function (e, t) {
                b.fn[e] = function (e) {
                    var n,
                        r = 0,
                        i = [],
                        o = b(e),
                        a = o.length - 1;
                    for (; a >= r; r++) (n = r === a ? this : this.clone(!0)), b(o[r])[t](n), d.apply(i, n.get());
                    return this.pushStack(i);
                };
            }
        );
        function Ot(e, n) {
            var r,
                o,
                a = 0,
                s =
                    typeof e.getElementsByTagName !== i
                        ? e.getElementsByTagName(n || "*")
                        : typeof e.querySelectorAll !== i
                          ? e.querySelectorAll(n || "*")
                          : t;
            if (!s)
                for (s = [], r = e.childNodes || e; null != (o = r[a]); a++)
                    !n || b.nodeName(o, n) ? s.push(o) : b.merge(s, Ot(o, n));
            return n === t || (n && b.nodeName(e, n)) ? b.merge([e], s) : s;
        }
        function Bt(e) {
            Nt.test(e.type) && (e.defaultChecked = e.checked);
        }
        b.extend({
            clone: function (e, t, n) {
                var r,
                    i,
                    o,
                    a,
                    s,
                    u = b.contains(e.ownerDocument, e);
                if (
                    (b.support.html5Clone || b.isXMLDoc(e) || !mt.test("<" + e.nodeName + ">")
                        ? (o = e.cloneNode(!0))
                        : ((Dt.innerHTML = e.outerHTML), Dt.removeChild((o = Dt.firstChild))),
                    !(
                        (b.support.noCloneEvent && b.support.noCloneChecked) ||
                        (1 !== e.nodeType && 11 !== e.nodeType) ||
                        b.isXMLDoc(e)
                    ))
                )
                    for (r = Ot(o), s = Ot(e), a = 0; null != (i = s[a]); ++a) r[a] && Ft(i, r[a]);
                if (t)
                    if (n) for (s = s || Ot(e), r = r || Ot(o), a = 0; null != (i = s[a]); a++) _t(i, r[a]);
                    else _t(e, o);
                return (r = Ot(o, "script")), r.length > 0 && Mt(r, !u && Ot(e, "script")), (r = s = i = null), o;
            },
            buildFragment: function (e, t, n, r) {
                var i,
                    o,
                    a,
                    s,
                    u,
                    l,
                    c,
                    p = e.length,
                    f = dt(t),
                    d = [],
                    h = 0;
                for (; p > h; h++)
                    if (((o = e[h]), o || 0 === o))
                        if ("object" === b.type(o)) b.merge(d, o.nodeType ? [o] : o);
                        else if (wt.test(o)) {
                            (s = s || f.appendChild(t.createElement("div"))),
                                (u = (bt.exec(o) || ["", ""])[1].toLowerCase()),
                                (c = At[u] || At._default),
                                (s.innerHTML = c[1] + o.replace(vt, "<$1></$2>") + c[2]),
                                (i = c[0]);
                            while (i--) s = s.lastChild;
                            if (
                                (!b.support.leadingWhitespace && yt.test(o) && d.push(t.createTextNode(yt.exec(o)[0])),
                                !b.support.tbody)
                            ) {
                                (o =
                                    "table" !== u || xt.test(o)
                                        ? "<table>" !== c[1] || xt.test(o)
                                            ? 0
                                            : s
                                        : s.firstChild),
                                    (i = o && o.childNodes.length);
                                while (i--)
                                    b.nodeName((l = o.childNodes[i]), "tbody") &&
                                        !l.childNodes.length &&
                                        o.removeChild(l);
                            }
                            b.merge(d, s.childNodes), (s.textContent = "");
                            while (s.firstChild) s.removeChild(s.firstChild);
                            s = f.lastChild;
                        } else d.push(t.createTextNode(o));
                s && f.removeChild(s), b.support.appendChecked || b.grep(Ot(d, "input"), Bt), (h = 0);
                while ((o = d[h++]))
                    if (
                        (!r || -1 === b.inArray(o, r)) &&
                        ((a = b.contains(o.ownerDocument, o)), (s = Ot(f.appendChild(o), "script")), a && Mt(s), n)
                    ) {
                        i = 0;
                        while ((o = s[i++])) kt.test(o.type || "") && n.push(o);
                    }
                return (s = null), f;
            },
            cleanData: function (e, t) {
                var n,
                    r,
                    o,
                    a,
                    s = 0,
                    u = b.expando,
                    l = b.cache,
                    p = b.support.deleteExpando,
                    f = b.event.special;
                for (; null != (n = e[s]); s++)
                    if ((t || b.acceptData(n)) && ((o = n[u]), (a = o && l[o]))) {
                        if (a.events) for (r in a.events) f[r] ? b.event.remove(n, r) : b.removeEvent(n, r, a.handle);
                        l[o] &&
                            (delete l[o],
                            p ? delete n[u] : typeof n.removeAttribute !== i ? n.removeAttribute(u) : (n[u] = null),
                            c.push(o));
                    }
            },
        });
        var Pt,
            Rt,
            Wt,
            $t = /alpha\([^)]*\)/i,
            It = /opacity\s*=\s*([^)]*)/,
            zt = /^(top|right|bottom|left)$/,
            Xt = /^(none|table(?!-c[ea]).+)/,
            Ut = /^margin/,
            Vt = RegExp("^(" + x + ")(.*)$", "i"),
            Yt = RegExp("^(" + x + ")(?!px)[a-z%]+$", "i"),
            Jt = RegExp("^([+-])=(" + x + ")", "i"),
            Gt = { BODY: "block" },
            Qt = { position: "absolute", visibility: "hidden", display: "block" },
            Kt = { letterSpacing: 0, fontWeight: 400 },
            Zt = ["Top", "Right", "Bottom", "Left"],
            en = ["Webkit", "O", "Moz", "ms"];
        function tn(e, t) {
            if (t in e) return t;
            var n = t.charAt(0).toUpperCase() + t.slice(1),
                r = t,
                i = en.length;
            while (i--) if (((t = en[i] + n), t in e)) return t;
            return r;
        }
        function nn(e, t) {
            return (e = t || e), "none" === b.css(e, "display") || !b.contains(e.ownerDocument, e);
        }
        function rn(e, t) {
            var n,
                r,
                i,
                o = [],
                a = 0,
                s = e.length;
            for (; s > a; a++)
                (r = e[a]),
                    r.style &&
                        ((o[a] = b._data(r, "olddisplay")),
                        (n = r.style.display),
                        t
                            ? (o[a] || "none" !== n || (r.style.display = ""),
                              "" === r.style.display && nn(r) && (o[a] = b._data(r, "olddisplay", un(r.nodeName))))
                            : o[a] ||
                              ((i = nn(r)),
                              ((n && "none" !== n) || !i) && b._data(r, "olddisplay", i ? n : b.css(r, "display"))));
            for (a = 0; s > a; a++)
                (r = e[a]),
                    r.style &&
                        ((t && "none" !== r.style.display && "" !== r.style.display) ||
                            (r.style.display = t ? o[a] || "" : "none"));
            return e;
        }
        b.fn.extend({
            css: function (e, n) {
                return b.access(
                    this,
                    function (e, n, r) {
                        var i,
                            o,
                            a = {},
                            s = 0;
                        if (b.isArray(n)) {
                            for (o = Rt(e), i = n.length; i > s; s++) a[n[s]] = b.css(e, n[s], !1, o);
                            return a;
                        }
                        return r !== t ? b.style(e, n, r) : b.css(e, n);
                    },
                    e,
                    n,
                    arguments.length > 1
                );
            },
            show: function () {
                return rn(this, !0);
            },
            hide: function () {
                return rn(this);
            },
            toggle: function (e) {
                var t = "boolean" == typeof e;
                return this.each(function () {
                    (t ? e : nn(this)) ? b(this).show() : b(this).hide();
                });
            },
        }),
            b.extend({
                cssHooks: {
                    opacity: {
                        get: function (e, t) {
                            if (t) {
                                var n = Wt(e, "opacity");
                                return "" === n ? "1" : n;
                            }
                        },
                    },
                },
                cssNumber: {
                    columnCount: !0,
                    fillOpacity: !0,
                    fontWeight: !0,
                    lineHeight: !0,
                    opacity: !0,
                    orphans: !0,
                    widows: !0,
                    zIndex: !0,
                    zoom: !0,
                },
                cssProps: { float: b.support.cssFloat ? "cssFloat" : "styleFloat" },
                style: function (e, n, r, i) {
                    if (e && 3 !== e.nodeType && 8 !== e.nodeType && e.style) {
                        var o,
                            a,
                            s,
                            u = b.camelCase(n),
                            l = e.style;
                        if (
                            ((n = b.cssProps[u] || (b.cssProps[u] = tn(l, u))),
                            (s = b.cssHooks[n] || b.cssHooks[u]),
                            r === t)
                        )
                            return s && "get" in s && (o = s.get(e, !1, i)) !== t ? o : l[n];
                        if (
                            ((a = typeof r),
                            "string" === a &&
                                (o = Jt.exec(r)) &&
                                ((r = (o[1] + 1) * o[2] + parseFloat(b.css(e, n))), (a = "number")),
                            !(
                                null == r ||
                                ("number" === a && isNaN(r)) ||
                                ("number" !== a || b.cssNumber[u] || (r += "px"),
                                b.support.clearCloneStyle ||
                                    "" !== r ||
                                    0 !== n.indexOf("background") ||
                                    (l[n] = "inherit"),
                                s && "set" in s && (r = s.set(e, r, i)) === t)
                            ))
                        )
                            try {
                                l[n] = r;
                            } catch (c) {}
                    }
                },
                css: function (e, n, r, i) {
                    var o,
                        a,
                        s,
                        u = b.camelCase(n);
                    return (
                        (n = b.cssProps[u] || (b.cssProps[u] = tn(e.style, u))),
                        (s = b.cssHooks[n] || b.cssHooks[u]),
                        s && "get" in s && (a = s.get(e, !0, r)),
                        a === t && (a = Wt(e, n, i)),
                        "normal" === a && n in Kt && (a = Kt[n]),
                        "" === r || r ? ((o = parseFloat(a)), r === !0 || b.isNumeric(o) ? o || 0 : a) : a
                    );
                },
                swap: function (e, t, n, r) {
                    var i,
                        o,
                        a = {};
                    for (o in t) (a[o] = e.style[o]), (e.style[o] = t[o]);
                    i = n.apply(e, r || []);
                    for (o in t) e.style[o] = a[o];
                    return i;
                },
            }),
            e.getComputedStyle
                ? ((Rt = function (t) {
                      return e.getComputedStyle(t, null);
                  }),
                  (Wt = function (e, n, r) {
                      var i,
                          o,
                          a,
                          s = r || Rt(e),
                          u = s ? s.getPropertyValue(n) || s[n] : t,
                          l = e.style;
                      return (
                          s &&
                              ("" !== u || b.contains(e.ownerDocument, e) || (u = b.style(e, n)),
                              Yt.test(u) &&
                                  Ut.test(n) &&
                                  ((i = l.width),
                                  (o = l.minWidth),
                                  (a = l.maxWidth),
                                  (l.minWidth = l.maxWidth = l.width = u),
                                  (u = s.width),
                                  (l.width = i),
                                  (l.minWidth = o),
                                  (l.maxWidth = a))),
                          u
                      );
                  }))
                : o.documentElement.currentStyle &&
                  ((Rt = function (e) {
                      return e.currentStyle;
                  }),
                  (Wt = function (e, n, r) {
                      var i,
                          o,
                          a,
                          s = r || Rt(e),
                          u = s ? s[n] : t,
                          l = e.style;
                      return (
                          null == u && l && l[n] && (u = l[n]),
                          Yt.test(u) &&
                              !zt.test(n) &&
                              ((i = l.left),
                              (o = e.runtimeStyle),
                              (a = o && o.left),
                              a && (o.left = e.currentStyle.left),
                              (l.left = "fontSize" === n ? "1em" : u),
                              (u = l.pixelLeft + "px"),
                              (l.left = i),
                              a && (o.left = a)),
                          "" === u ? "auto" : u
                      );
                  }));
        function on(e, t, n) {
            var r = Vt.exec(t);
            return r ? Math.max(0, r[1] - (n || 0)) + (r[2] || "px") : t;
        }
        function an(e, t, n, r, i) {
            var o = n === (r ? "border" : "content") ? 4 : "width" === t ? 1 : 0,
                a = 0;
            for (; 4 > o; o += 2)
                "margin" === n && (a += b.css(e, n + Zt[o], !0, i)),
                    r
                        ? ("content" === n && (a -= b.css(e, "padding" + Zt[o], !0, i)),
                          "margin" !== n && (a -= b.css(e, "border" + Zt[o] + "Width", !0, i)))
                        : ((a += b.css(e, "padding" + Zt[o], !0, i)),
                          "padding" !== n && (a += b.css(e, "border" + Zt[o] + "Width", !0, i)));
            return a;
        }
        function sn(e, t, n) {
            var r = !0,
                i = "width" === t ? e.offsetWidth : e.offsetHeight,
                o = Rt(e),
                a = b.support.boxSizing && "border-box" === b.css(e, "boxSizing", !1, o);
            if (0 >= i || null == i) {
                if (((i = Wt(e, t, o)), (0 > i || null == i) && (i = e.style[t]), Yt.test(i))) return i;
                (r = a && (b.support.boxSizingReliable || i === e.style[t])), (i = parseFloat(i) || 0);
            }
            return i + an(e, t, n || (a ? "border" : "content"), r, o) + "px";
        }
        function un(e) {
            var t = o,
                n = Gt[e];
            return (
                n ||
                    ((n = ln(e, t)),
                    ("none" !== n && n) ||
                        ((Pt = (
                            Pt ||
                            b("<iframe frameborder='0' width='0' height='0'/>").css(
                                "cssText",
                                "display:block !important"
                            )
                        ).appendTo(t.documentElement)),
                        (t = (Pt[0].contentWindow || Pt[0].contentDocument).document),
                        t.write("<!doctype html><html><body>"),
                        t.close(),
                        (n = ln(e, t)),
                        Pt.detach()),
                    (Gt[e] = n)),
                n
            );
        }
        function ln(e, t) {
            var n = b(t.createElement(e)).appendTo(t.body),
                r = b.css(n[0], "display");
            return n.remove(), r;
        }
        b.each(["height", "width"], function (e, n) {
            b.cssHooks[n] = {
                get: function (e, r, i) {
                    return r
                        ? 0 === e.offsetWidth && Xt.test(b.css(e, "display"))
                            ? b.swap(e, Qt, function () {
                                  return sn(e, n, i);
                              })
                            : sn(e, n, i)
                        : t;
                },
                set: function (e, t, r) {
                    var i = r && Rt(e);
                    return on(
                        e,
                        t,
                        r ? an(e, n, r, b.support.boxSizing && "border-box" === b.css(e, "boxSizing", !1, i), i) : 0
                    );
                },
            };
        }),
            b.support.opacity ||
                (b.cssHooks.opacity = {
                    get: function (e, t) {
                        return It.test((t && e.currentStyle ? e.currentStyle.filter : e.style.filter) || "")
                            ? 0.01 * parseFloat(RegExp.$1) + ""
                            : t
                              ? "1"
                              : "";
                    },
                    set: function (e, t) {
                        var n = e.style,
                            r = e.currentStyle,
                            i = b.isNumeric(t) ? "alpha(opacity=" + 100 * t + ")" : "",
                            o = (r && r.filter) || n.filter || "";
                        (n.zoom = 1),
                            ((t >= 1 || "" === t) &&
                                "" === b.trim(o.replace($t, "")) &&
                                n.removeAttribute &&
                                (n.removeAttribute("filter"), "" === t || (r && !r.filter))) ||
                                (n.filter = $t.test(o) ? o.replace($t, i) : o + " " + i);
                    },
                }),
            b(function () {
                b.support.reliableMarginRight ||
                    (b.cssHooks.marginRight = {
                        get: function (e, n) {
                            return n ? b.swap(e, { display: "inline-block" }, Wt, [e, "marginRight"]) : t;
                        },
                    }),
                    !b.support.pixelPosition &&
                        b.fn.position &&
                        b.each(["top", "left"], function (e, n) {
                            b.cssHooks[n] = {
                                get: function (e, r) {
                                    return r ? ((r = Wt(e, n)), Yt.test(r) ? b(e).position()[n] + "px" : r) : t;
                                },
                            };
                        });
            }),
            b.expr &&
                b.expr.filters &&
                ((b.expr.filters.hidden = function (e) {
                    return (
                        (0 >= e.offsetWidth && 0 >= e.offsetHeight) ||
                        (!b.support.reliableHiddenOffsets &&
                            "none" === ((e.style && e.style.display) || b.css(e, "display")))
                    );
                }),
                (b.expr.filters.visible = function (e) {
                    return !b.expr.filters.hidden(e);
                })),
            b.each({ margin: "", padding: "", border: "Width" }, function (e, t) {
                (b.cssHooks[e + t] = {
                    expand: function (n) {
                        var r = 0,
                            i = {},
                            o = "string" == typeof n ? n.split(" ") : [n];
                        for (; 4 > r; r++) i[e + Zt[r] + t] = o[r] || o[r - 2] || o[0];
                        return i;
                    },
                }),
                    Ut.test(e) || (b.cssHooks[e + t].set = on);
            });
        var cn = /%20/g,
            pn = /\[\]$/,
            fn = /\r?\n/g,
            dn = /^(?:submit|button|image|reset|file)$/i,
            hn = /^(?:input|select|textarea|keygen)/i;
        b.fn.extend({
            serialize: function () {
                return b.param(this.serializeArray());
            },
            serializeArray: function () {
                return this.map(function () {
                    var e = b.prop(this, "elements");
                    return e ? b.makeArray(e) : this;
                })
                    .filter(function () {
                        var e = this.type;
                        return (
                            this.name &&
                            !b(this).is(":disabled") &&
                            hn.test(this.nodeName) &&
                            !dn.test(e) &&
                            (this.checked || !Nt.test(e))
                        );
                    })
                    .map(function (e, t) {
                        var n = b(this).val();
                        return null == n
                            ? null
                            : b.isArray(n)
                              ? b.map(n, function (e) {
                                    return { name: t.name, value: e.replace(fn, "\r\n") };
                                })
                              : { name: t.name, value: n.replace(fn, "\r\n") };
                    })
                    .get();
            },
        }),
            (b.param = function (e, n) {
                var r,
                    i = [],
                    o = function (e, t) {
                        (t = b.isFunction(t) ? t() : null == t ? "" : t),
                            (i[i.length] = encodeURIComponent(e) + "=" + encodeURIComponent(t));
                    };
                if (
                    (n === t && (n = b.ajaxSettings && b.ajaxSettings.traditional),
                    b.isArray(e) || (e.jquery && !b.isPlainObject(e)))
                )
                    b.each(e, function () {
                        o(this.name, this.value);
                    });
                else for (r in e) gn(r, e[r], n, o);
                return i.join("&").replace(cn, "+");
            });
        function gn(e, t, n, r) {
            var i;
            if (b.isArray(t))
                b.each(t, function (t, i) {
                    n || pn.test(e) ? r(e, i) : gn(e + "[" + ("object" == typeof i ? t : "") + "]", i, n, r);
                });
            else if (n || "object" !== b.type(t)) r(e, t);
            else for (i in t) gn(e + "[" + i + "]", t[i], n, r);
        }
        b.each(
            "blur focus focusin focusout load resize scroll unload click dblclick mousedown mouseup mousemove mouseover mouseout mouseenter mouseleave change select submit keydown keypress keyup error contextmenu".split(
                " "
            ),
            function (e, t) {
                b.fn[t] = function (e, n) {
                    return arguments.length > 0 ? this.on(t, null, e, n) : this.trigger(t);
                };
            }
        ),
            (b.fn.hover = function (e, t) {
                return this.mouseenter(e).mouseleave(t || e);
            });
        var mn,
            yn,
            vn = b.now(),
            bn = /\?/,
            xn = /#.*$/,
            wn = /([?&])_=[^&]*/,
            Tn = /^(.*?):[ \t]*([^\r\n]*)\r?$/gm,
            Nn = /^(?:about|app|app-storage|.+-extension|file|res|widget):$/,
            Cn = /^(?:GET|HEAD)$/,
            kn = /^\/\//,
            En = /^([\w.+-]+:)(?:\/\/([^\/?#:]*)(?::(\d+)|)|)/,
            Sn = b.fn.load,
            An = {},
            jn = {},
            Dn = "*/".concat("*");
        try {
            yn = a.href;
        } catch (Ln) {
            (yn = o.createElement("a")), (yn.href = ""), (yn = yn.href);
        }
        mn = En.exec(yn.toLowerCase()) || [];
        function Hn(e) {
            return function (t, n) {
                "string" != typeof t && ((n = t), (t = "*"));
                var r,
                    i = 0,
                    o = t.toLowerCase().match(w) || [];
                if (b.isFunction(n))
                    while ((r = o[i++]))
                        "+" === r[0]
                            ? ((r = r.slice(1) || "*"), (e[r] = e[r] || []).unshift(n))
                            : (e[r] = e[r] || []).push(n);
            };
        }
        function qn(e, n, r, i) {
            var o = {},
                a = e === jn;
            function s(u) {
                var l;
                return (
                    (o[u] = !0),
                    b.each(e[u] || [], function (e, u) {
                        var c = u(n, r, i);
                        return "string" != typeof c || a || o[c]
                            ? a
                                ? !(l = c)
                                : t
                            : (n.dataTypes.unshift(c), s(c), !1);
                    }),
                    l
                );
            }
            return s(n.dataTypes[0]) || (!o["*"] && s("*"));
        }
        function Mn(e, n) {
            var r,
                i,
                o = b.ajaxSettings.flatOptions || {};
            for (i in n) n[i] !== t && ((o[i] ? e : r || (r = {}))[i] = n[i]);
            return r && b.extend(!0, e, r), e;
        }
        (b.fn.load = function (e, n, r) {
            if ("string" != typeof e && Sn) return Sn.apply(this, arguments);
            var i,
                o,
                a,
                s = this,
                u = e.indexOf(" ");
            return (
                u >= 0 && ((i = e.slice(u, e.length)), (e = e.slice(0, u))),
                b.isFunction(n) ? ((r = n), (n = t)) : n && "object" == typeof n && (a = "POST"),
                s.length > 0 &&
                    b
                        .ajax({ url: e, type: a, dataType: "html", data: n })
                        .done(function (e) {
                            (o = arguments), s.html(i ? b("<div>").append(b.parseHTML(e)).find(i) : e);
                        })
                        .complete(
                            r &&
                                function (e, t) {
                                    s.each(r, o || [e.responseText, t, e]);
                                }
                        ),
                this
            );
        }),
            b.each(["ajaxStart", "ajaxStop", "ajaxComplete", "ajaxError", "ajaxSuccess", "ajaxSend"], function (e, t) {
                b.fn[t] = function (e) {
                    return this.on(t, e);
                };
            }),
            b.each(["get", "post"], function (e, n) {
                b[n] = function (e, r, i, o) {
                    return (
                        b.isFunction(r) && ((o = o || i), (i = r), (r = t)),
                        b.ajax({ url: e, type: n, dataType: o, data: r, success: i })
                    );
                };
            }),
            b.extend({
                active: 0,
                lastModified: {},
                etag: {},
                ajaxSettings: {
                    url: yn,
                    type: "GET",
                    isLocal: Nn.test(mn[1]),
                    global: !0,
                    processData: !0,
                    async: !0,
                    contentType: "application/x-www-form-urlencoded; charset=UTF-8",
                    accepts: {
                        "*": Dn,
                        text: "text/plain",
                        html: "text/html",
                        xml: "application/xml, text/xml",
                        json: "application/json, text/javascript",
                    },
                    contents: { xml: /xml/, html: /html/, json: /json/ },
                    responseFields: { xml: "responseXML", text: "responseText" },
                    converters: {
                        "* text": e.String,
                        "text html": !0,
                        "text json": b.parseJSON,
                        "text xml": b.parseXML,
                    },
                    flatOptions: { url: !0, context: !0 },
                },
                ajaxSetup: function (e, t) {
                    return t ? Mn(Mn(e, b.ajaxSettings), t) : Mn(b.ajaxSettings, e);
                },
                ajaxPrefilter: Hn(An),
                ajaxTransport: Hn(jn),
                ajax: function (e, n) {
                    "object" == typeof e && ((n = e), (e = t)), (n = n || {});
                    var r,
                        i,
                        o,
                        a,
                        s,
                        u,
                        l,
                        c,
                        p = b.ajaxSetup({}, n),
                        f = p.context || p,
                        d = p.context && (f.nodeType || f.jquery) ? b(f) : b.event,
                        h = b.Deferred(),
                        g = b.Callbacks("once memory"),
                        m = p.statusCode || {},
                        y = {},
                        v = {},
                        x = 0,
                        T = "canceled",
                        N = {
                            readyState: 0,
                            getResponseHeader: function (e) {
                                var t;
                                if (2 === x) {
                                    if (!c) {
                                        c = {};
                                        while ((t = Tn.exec(a))) c[t[1].toLowerCase()] = t[2];
                                    }
                                    t = c[e.toLowerCase()];
                                }
                                return null == t ? null : t;
                            },
                            getAllResponseHeaders: function () {
                                return 2 === x ? a : null;
                            },
                            setRequestHeader: function (e, t) {
                                var n = e.toLowerCase();
                                return x || ((e = v[n] = v[n] || e), (y[e] = t)), this;
                            },
                            overrideMimeType: function (e) {
                                return x || (p.mimeType = e), this;
                            },
                            statusCode: function (e) {
                                var t;
                                if (e)
                                    if (2 > x) for (t in e) m[t] = [m[t], e[t]];
                                    else N.always(e[N.status]);
                                return this;
                            },
                            abort: function (e) {
                                var t = e || T;
                                return l && l.abort(t), k(0, t), this;
                            },
                        };
                    if (
                        ((h.promise(N).complete = g.add),
                        (N.success = N.done),
                        (N.error = N.fail),
                        (p.url = ((e || p.url || yn) + "").replace(xn, "").replace(kn, mn[1] + "//")),
                        (p.type = n.method || n.type || p.method || p.type),
                        (p.dataTypes = b
                            .trim(p.dataType || "*")
                            .toLowerCase()
                            .match(w) || [""]),
                        null == p.crossDomain &&
                            ((r = En.exec(p.url.toLowerCase())),
                            (p.crossDomain = !(
                                !r ||
                                (r[1] === mn[1] &&
                                    r[2] === mn[2] &&
                                    (r[3] || ("http:" === r[1] ? 80 : 443)) ==
                                        (mn[3] || ("http:" === mn[1] ? 80 : 443)))
                            ))),
                        p.data &&
                            p.processData &&
                            "string" != typeof p.data &&
                            (p.data = b.param(p.data, p.traditional)),
                        qn(An, p, n, N),
                        2 === x)
                    )
                        return N;
                    (u = p.global),
                        u && 0 === b.active++ && b.event.trigger("ajaxStart"),
                        (p.type = p.type.toUpperCase()),
                        (p.hasContent = !Cn.test(p.type)),
                        (o = p.url),
                        p.hasContent ||
                            (p.data && ((o = p.url += (bn.test(o) ? "&" : "?") + p.data), delete p.data),
                            p.cache === !1 &&
                                (p.url = wn.test(o)
                                    ? o.replace(wn, "$1_=" + vn++)
                                    : o + (bn.test(o) ? "&" : "?") + "_=" + vn++)),
                        p.ifModified &&
                            (b.lastModified[o] && N.setRequestHeader("If-Modified-Since", b.lastModified[o]),
                            b.etag[o] && N.setRequestHeader("If-None-Match", b.etag[o])),
                        ((p.data && p.hasContent && p.contentType !== !1) || n.contentType) &&
                            N.setRequestHeader("Content-Type", p.contentType),
                        N.setRequestHeader(
                            "Accept",
                            p.dataTypes[0] && p.accepts[p.dataTypes[0]]
                                ? p.accepts[p.dataTypes[0]] + ("*" !== p.dataTypes[0] ? ", " + Dn + "; q=0.01" : "")
                                : p.accepts["*"]
                        );
                    for (i in p.headers) N.setRequestHeader(i, p.headers[i]);
                    if (p.beforeSend && (p.beforeSend.call(f, N, p) === !1 || 2 === x)) return N.abort();
                    T = "abort";
                    for (i in { success: 1, error: 1, complete: 1 }) N[i](p[i]);
                    if ((l = qn(jn, p, n, N))) {
                        (N.readyState = 1),
                            u && d.trigger("ajaxSend", [N, p]),
                            p.async &&
                                p.timeout > 0 &&
                                (s = setTimeout(function () {
                                    N.abort("timeout");
                                }, p.timeout));
                        try {
                            (x = 1), l.send(y, k);
                        } catch (C) {
                            if (!(2 > x)) throw C;
                            k(-1, C);
                        }
                    } else k(-1, "No Transport");
                    function k(e, n, r, i) {
                        var c,
                            y,
                            v,
                            w,
                            T,
                            C = n;
                        2 !== x &&
                            ((x = 2),
                            s && clearTimeout(s),
                            (l = t),
                            (a = i || ""),
                            (N.readyState = e > 0 ? 4 : 0),
                            r && (w = _n(p, N, r)),
                            (e >= 200 && 300 > e) || 304 === e
                                ? (p.ifModified &&
                                      ((T = N.getResponseHeader("Last-Modified")),
                                      T && (b.lastModified[o] = T),
                                      (T = N.getResponseHeader("etag")),
                                      T && (b.etag[o] = T)),
                                  204 === e
                                      ? ((c = !0), (C = "nocontent"))
                                      : 304 === e
                                        ? ((c = !0), (C = "notmodified"))
                                        : ((c = Fn(p, w)), (C = c.state), (y = c.data), (v = c.error), (c = !v)))
                                : ((v = C), (e || !C) && ((C = "error"), 0 > e && (e = 0))),
                            (N.status = e),
                            (N.statusText = (n || C) + ""),
                            c ? h.resolveWith(f, [y, C, N]) : h.rejectWith(f, [N, C, v]),
                            N.statusCode(m),
                            (m = t),
                            u && d.trigger(c ? "ajaxSuccess" : "ajaxError", [N, p, c ? y : v]),
                            g.fireWith(f, [N, C]),
                            u && (d.trigger("ajaxComplete", [N, p]), --b.active || b.event.trigger("ajaxStop")));
                    }
                    return N;
                },
                getScript: function (e, n) {
                    return b.get(e, t, n, "script");
                },
                getJSON: function (e, t, n) {
                    return b.get(e, t, n, "json");
                },
            });
        function _n(e, n, r) {
            var i,
                o,
                a,
                s,
                u = e.contents,
                l = e.dataTypes,
                c = e.responseFields;
            for (s in c) s in r && (n[c[s]] = r[s]);
            while ("*" === l[0]) l.shift(), o === t && (o = e.mimeType || n.getResponseHeader("Content-Type"));
            if (o)
                for (s in u)
                    if (u[s] && u[s].test(o)) {
                        l.unshift(s);
                        break;
                    }
            if (l[0] in r) a = l[0];
            else {
                for (s in r) {
                    if (!l[0] || e.converters[s + " " + l[0]]) {
                        a = s;
                        break;
                    }
                    i || (i = s);
                }
                a = a || i;
            }
            return a ? (a !== l[0] && l.unshift(a), r[a]) : t;
        }
        function Fn(e, t) {
            var n,
                r,
                i,
                o,
                a = {},
                s = 0,
                u = e.dataTypes.slice(),
                l = u[0];
            if ((e.dataFilter && (t = e.dataFilter(t, e.dataType)), u[1]))
                for (i in e.converters) a[i.toLowerCase()] = e.converters[i];
            for (; (r = u[++s]); )
                if ("*" !== r) {
                    if ("*" !== l && l !== r) {
                        if (((i = a[l + " " + r] || a["* " + r]), !i))
                            for (n in a)
                                if (((o = n.split(" ")), o[1] === r && (i = a[l + " " + o[0]] || a["* " + o[0]]))) {
                                    i === !0 ? (i = a[n]) : a[n] !== !0 && ((r = o[0]), u.splice(s--, 0, r));
                                    break;
                                }
                        if (i !== !0)
                            if (i && e["throws"]) t = i(t);
                            else
                                try {
                                    t = i(t);
                                } catch (c) {
                                    return {
                                        state: "parsererror",
                                        error: i ? c : "No conversion from " + l + " to " + r,
                                    };
                                }
                    }
                    l = r;
                }
            return { state: "success", data: t };
        }
        b.ajaxSetup({
            accepts: {
                script: "text/javascript, application/javascript, application/ecmascript, application/x-ecmascript",
            },
            contents: { script: /(?:java|ecma)script/ },
            converters: {
                "text script": function (e) {
                    return b.globalEval(e), e;
                },
            },
        }),
            b.ajaxPrefilter("script", function (e) {
                e.cache === t && (e.cache = !1), e.crossDomain && ((e.type = "GET"), (e.global = !1));
            }),
            b.ajaxTransport("script", function (e) {
                if (e.crossDomain) {
                    var n,
                        r = o.head || b("head")[0] || o.documentElement;
                    return {
                        send: function (t, i) {
                            (n = o.createElement("script")),
                                (n.async = !0),
                                e.scriptCharset && (n.charset = e.scriptCharset),
                                (n.src = e.url),
                                (n.onload = n.onreadystatechange =
                                    function (e, t) {
                                        (t || !n.readyState || /loaded|complete/.test(n.readyState)) &&
                                            ((n.onload = n.onreadystatechange = null),
                                            n.parentNode && n.parentNode.removeChild(n),
                                            (n = null),
                                            t || i(200, "success"));
                                    }),
                                r.insertBefore(n, r.firstChild);
                        },
                        abort: function () {
                            n && n.onload(t, !0);
                        },
                    };
                }
            });
        var On = [],
            Bn = /(=)\?(?=&|$)|\?\?/;
        b.ajaxSetup({
            jsonp: "callback",
            jsonpCallback: function () {
                var e = On.pop() || b.expando + "_" + vn++;
                return (this[e] = !0), e;
            },
        }),
            b.ajaxPrefilter("json jsonp", function (n, r, i) {
                var o,
                    a,
                    s,
                    u =
                        n.jsonp !== !1 &&
                        (Bn.test(n.url)
                            ? "url"
                            : "string" == typeof n.data &&
                              !(n.contentType || "").indexOf("application/x-www-form-urlencoded") &&
                              Bn.test(n.data) &&
                              "data");
                return u || "jsonp" === n.dataTypes[0]
                    ? ((o = n.jsonpCallback = b.isFunction(n.jsonpCallback) ? n.jsonpCallback() : n.jsonpCallback),
                      u
                          ? (n[u] = n[u].replace(Bn, "$1" + o))
                          : n.jsonp !== !1 && (n.url += (bn.test(n.url) ? "&" : "?") + n.jsonp + "=" + o),
                      (n.converters["script json"] = function () {
                          return s || b.error(o + " was not called"), s[0];
                      }),
                      (n.dataTypes[0] = "json"),
                      (a = e[o]),
                      (e[o] = function () {
                          s = arguments;
                      }),
                      i.always(function () {
                          (e[o] = a),
                              n[o] && ((n.jsonpCallback = r.jsonpCallback), On.push(o)),
                              s && b.isFunction(a) && a(s[0]),
                              (s = a = t);
                      }),
                      "script")
                    : t;
            });
        var Pn,
            Rn,
            Wn = 0,
            $n =
                e.ActiveXObject &&
                function () {
                    var e;
                    for (e in Pn) Pn[e](t, !0);
                };
        function In() {
            try {
                return new e.XMLHttpRequest();
            } catch (t) {}
        }
        function zn() {
            try {
                return new e.ActiveXObject("Microsoft.XMLHTTP");
            } catch (t) {}
        }
        (b.ajaxSettings.xhr = e.ActiveXObject
            ? function () {
                  return (!this.isLocal && In()) || zn();
              }
            : In),
            (Rn = b.ajaxSettings.xhr()),
            (b.support.cors = !!Rn && "withCredentials" in Rn),
            (Rn = b.support.ajax = !!Rn),
            Rn &&
                b.ajaxTransport(function (n) {
                    if (!n.crossDomain || b.support.cors) {
                        var r;
                        return {
                            send: function (i, o) {
                                var a,
                                    s,
                                    u = n.xhr();
                                if (
                                    (n.username
                                        ? u.open(n.type, n.url, n.async, n.username, n.password)
                                        : u.open(n.type, n.url, n.async),
                                    n.xhrFields)
                                )
                                    for (s in n.xhrFields) u[s] = n.xhrFields[s];
                                n.mimeType && u.overrideMimeType && u.overrideMimeType(n.mimeType),
                                    n.crossDomain ||
                                        i["X-Requested-With"] ||
                                        (i["X-Requested-With"] = "XMLHttpRequest");
                                try {
                                    for (s in i) u.setRequestHeader(s, i[s]);
                                } catch (l) {}
                                u.send((n.hasContent && n.data) || null),
                                    (r = function (e, i) {
                                        var s, l, c, p;
                                        try {
                                            if (r && (i || 4 === u.readyState))
                                                if (
                                                    ((r = t),
                                                    a && ((u.onreadystatechange = b.noop), $n && delete Pn[a]),
                                                    i)
                                                )
                                                    4 !== u.readyState && u.abort();
                                                else {
                                                    (p = {}),
                                                        (s = u.status),
                                                        (l = u.getAllResponseHeaders()),
                                                        "string" == typeof u.responseText && (p.text = u.responseText);
                                                    try {
                                                        c = u.statusText;
                                                    } catch (f) {
                                                        c = "";
                                                    }
                                                    s || !n.isLocal || n.crossDomain
                                                        ? 1223 === s && (s = 204)
                                                        : (s = p.text ? 200 : 404);
                                                }
                                        } catch (d) {
                                            i || o(-1, d);
                                        }
                                        p && o(s, c, p, l);
                                    }),
                                    n.async
                                        ? 4 === u.readyState
                                            ? setTimeout(r)
                                            : ((a = ++Wn),
                                              $n && (Pn || ((Pn = {}), b(e).unload($n)), (Pn[a] = r)),
                                              (u.onreadystatechange = r))
                                        : r();
                            },
                            abort: function () {
                                r && r(t, !0);
                            },
                        };
                    }
                });
        var Xn,
            Un,
            Vn = /^(?:toggle|show|hide)$/,
            Yn = RegExp("^(?:([+-])=|)(" + x + ")([a-z%]*)$", "i"),
            Jn = /queueHooks$/,
            Gn = [nr],
            Qn = {
                "*": [
                    function (e, t) {
                        var n,
                            r,
                            i = this.createTween(e, t),
                            o = Yn.exec(t),
                            a = i.cur(),
                            s = +a || 0,
                            u = 1,
                            l = 20;
                        if (o) {
                            if (((n = +o[2]), (r = o[3] || (b.cssNumber[e] ? "" : "px")), "px" !== r && s)) {
                                s = b.css(i.elem, e, !0) || n || 1;
                                do (u = u || ".5"), (s /= u), b.style(i.elem, e, s + r);
                                while (u !== (u = i.cur() / a) && 1 !== u && --l);
                            }
                            (i.unit = r), (i.start = s), (i.end = o[1] ? s + (o[1] + 1) * n : n);
                        }
                        return i;
                    },
                ],
            };
        function Kn() {
            return (
                setTimeout(function () {
                    Xn = t;
                }),
                (Xn = b.now())
            );
        }
        function Zn(e, t) {
            b.each(t, function (t, n) {
                var r = (Qn[t] || []).concat(Qn["*"]),
                    i = 0,
                    o = r.length;
                for (; o > i; i++) if (r[i].call(e, t, n)) return;
            });
        }
        function er(e, t, n) {
            var r,
                i,
                o = 0,
                a = Gn.length,
                s = b.Deferred().always(function () {
                    delete u.elem;
                }),
                u = function () {
                    if (i) return !1;
                    var t = Xn || Kn(),
                        n = Math.max(0, l.startTime + l.duration - t),
                        r = n / l.duration || 0,
                        o = 1 - r,
                        a = 0,
                        u = l.tweens.length;
                    for (; u > a; a++) l.tweens[a].run(o);
                    return s.notifyWith(e, [l, o, n]), 1 > o && u ? n : (s.resolveWith(e, [l]), !1);
                },
                l = s.promise({
                    elem: e,
                    props: b.extend({}, t),
                    opts: b.extend(!0, { specialEasing: {} }, n),
                    originalProperties: t,
                    originalOptions: n,
                    startTime: Xn || Kn(),
                    duration: n.duration,
                    tweens: [],
                    createTween: function (t, n) {
                        var r = b.Tween(e, l.opts, t, n, l.opts.specialEasing[t] || l.opts.easing);
                        return l.tweens.push(r), r;
                    },
                    stop: function (t) {
                        var n = 0,
                            r = t ? l.tweens.length : 0;
                        if (i) return this;
                        for (i = !0; r > n; n++) l.tweens[n].run(1);
                        return t ? s.resolveWith(e, [l, t]) : s.rejectWith(e, [l, t]), this;
                    },
                }),
                c = l.props;
            for (tr(c, l.opts.specialEasing); a > o; o++) if ((r = Gn[o].call(l, e, c, l.opts))) return r;
            return (
                Zn(l, c),
                b.isFunction(l.opts.start) && l.opts.start.call(e, l),
                b.fx.timer(b.extend(u, { elem: e, anim: l, queue: l.opts.queue })),
                l.progress(l.opts.progress).done(l.opts.done, l.opts.complete).fail(l.opts.fail).always(l.opts.always)
            );
        }
        function tr(e, t) {
            var n, r, i, o, a;
            for (i in e)
                if (
                    ((r = b.camelCase(i)),
                    (o = t[r]),
                    (n = e[i]),
                    b.isArray(n) && ((o = n[1]), (n = e[i] = n[0])),
                    i !== r && ((e[r] = n), delete e[i]),
                    (a = b.cssHooks[r]),
                    a && "expand" in a)
                ) {
                    (n = a.expand(n)), delete e[r];
                    for (i in n) i in e || ((e[i] = n[i]), (t[i] = o));
                } else t[r] = o;
        }
        b.Animation = b.extend(er, {
            tweener: function (e, t) {
                b.isFunction(e) ? ((t = e), (e = ["*"])) : (e = e.split(" "));
                var n,
                    r = 0,
                    i = e.length;
                for (; i > r; r++) (n = e[r]), (Qn[n] = Qn[n] || []), Qn[n].unshift(t);
            },
            prefilter: function (e, t) {
                t ? Gn.unshift(e) : Gn.push(e);
            },
        });
        function nr(e, t, n) {
            var r,
                i,
                o,
                a,
                s,
                u,
                l,
                c,
                p,
                f = this,
                d = e.style,
                h = {},
                g = [],
                m = e.nodeType && nn(e);
            n.queue ||
                ((c = b._queueHooks(e, "fx")),
                null == c.unqueued &&
                    ((c.unqueued = 0),
                    (p = c.empty.fire),
                    (c.empty.fire = function () {
                        c.unqueued || p();
                    })),
                c.unqueued++,
                f.always(function () {
                    f.always(function () {
                        c.unqueued--, b.queue(e, "fx").length || c.empty.fire();
                    });
                })),
                1 === e.nodeType &&
                    ("height" in t || "width" in t) &&
                    ((n.overflow = [d.overflow, d.overflowX, d.overflowY]),
                    "inline" === b.css(e, "display") &&
                        "none" === b.css(e, "float") &&
                        (b.support.inlineBlockNeedsLayout && "inline" !== un(e.nodeName)
                            ? (d.zoom = 1)
                            : (d.display = "inline-block"))),
                n.overflow &&
                    ((d.overflow = "hidden"),
                    b.support.shrinkWrapBlocks ||
                        f.always(function () {
                            (d.overflow = n.overflow[0]), (d.overflowX = n.overflow[1]), (d.overflowY = n.overflow[2]);
                        }));
            for (i in t)
                if (((a = t[i]), Vn.exec(a))) {
                    if ((delete t[i], (u = u || "toggle" === a), a === (m ? "hide" : "show"))) continue;
                    g.push(i);
                }
            if ((o = g.length)) {
                (s = b._data(e, "fxshow") || b._data(e, "fxshow", {})),
                    "hidden" in s && (m = s.hidden),
                    u && (s.hidden = !m),
                    m
                        ? b(e).show()
                        : f.done(function () {
                              b(e).hide();
                          }),
                    f.done(function () {
                        var t;
                        b._removeData(e, "fxshow");
                        for (t in h) b.style(e, t, h[t]);
                    });
                for (i = 0; o > i; i++)
                    (r = g[i]),
                        (l = f.createTween(r, m ? s[r] : 0)),
                        (h[r] = s[r] || b.style(e, r)),
                        r in s ||
                            ((s[r] = l.start),
                            m && ((l.end = l.start), (l.start = "width" === r || "height" === r ? 1 : 0)));
            }
        }
        function rr(e, t, n, r, i) {
            return new rr.prototype.init(e, t, n, r, i);
        }
        (b.Tween = rr),
            (rr.prototype = {
                constructor: rr,
                init: function (e, t, n, r, i, o) {
                    (this.elem = e),
                        (this.prop = n),
                        (this.easing = i || "swing"),
                        (this.options = t),
                        (this.start = this.now = this.cur()),
                        (this.end = r),
                        (this.unit = o || (b.cssNumber[n] ? "" : "px"));
                },
                cur: function () {
                    var e = rr.propHooks[this.prop];
                    return e && e.get ? e.get(this) : rr.propHooks._default.get(this);
                },
                run: function (e) {
                    var t,
                        n = rr.propHooks[this.prop];
                    return (
                        (this.pos = t =
                            this.options.duration
                                ? b.easing[this.easing](e, this.options.duration * e, 0, 1, this.options.duration)
                                : e),
                        (this.now = (this.end - this.start) * t + this.start),
                        this.options.step && this.options.step.call(this.elem, this.now, this),
                        n && n.set ? n.set(this) : rr.propHooks._default.set(this),
                        this
                    );
                },
            }),
            (rr.prototype.init.prototype = rr.prototype),
            (rr.propHooks = {
                _default: {
                    get: function (e) {
                        var t;
                        return null == e.elem[e.prop] || (e.elem.style && null != e.elem.style[e.prop])
                            ? ((t = b.css(e.elem, e.prop, "")), t && "auto" !== t ? t : 0)
                            : e.elem[e.prop];
                    },
                    set: function (e) {
                        b.fx.step[e.prop]
                            ? b.fx.step[e.prop](e)
                            : e.elem.style && (null != e.elem.style[b.cssProps[e.prop]] || b.cssHooks[e.prop])
                              ? b.style(e.elem, e.prop, e.now + e.unit)
                              : (e.elem[e.prop] = e.now);
                    },
                },
            }),
            (rr.propHooks.scrollTop = rr.propHooks.scrollLeft =
                {
                    set: function (e) {
                        e.elem.nodeType && e.elem.parentNode && (e.elem[e.prop] = e.now);
                    },
                }),
            b.each(["toggle", "show", "hide"], function (e, t) {
                var n = b.fn[t];
                b.fn[t] = function (e, r, i) {
                    return null == e || "boolean" == typeof e
                        ? n.apply(this, arguments)
                        : this.animate(ir(t, !0), e, r, i);
                };
            }),
            b.fn.extend({
                fadeTo: function (e, t, n, r) {
                    return this.filter(nn).css("opacity", 0).show().end().animate({ opacity: t }, e, n, r);
                },
                animate: function (e, t, n, r) {
                    var i = b.isEmptyObject(e),
                        o = b.speed(t, n, r),
                        a = function () {
                            var t = er(this, b.extend({}, e), o);
                            (a.finish = function () {
                                t.stop(!0);
                            }),
                                (i || b._data(this, "finish")) && t.stop(!0);
                        };
                    return (a.finish = a), i || o.queue === !1 ? this.each(a) : this.queue(o.queue, a);
                },
                stop: function (e, n, r) {
                    var i = function (e) {
                        var t = e.stop;
                        delete e.stop, t(r);
                    };
                    return (
                        "string" != typeof e && ((r = n), (n = e), (e = t)),
                        n && e !== !1 && this.queue(e || "fx", []),
                        this.each(function () {
                            var t = !0,
                                n = null != e && e + "queueHooks",
                                o = b.timers,
                                a = b._data(this);
                            if (n) a[n] && a[n].stop && i(a[n]);
                            else for (n in a) a[n] && a[n].stop && Jn.test(n) && i(a[n]);
                            for (n = o.length; n--; )
                                o[n].elem !== this ||
                                    (null != e && o[n].queue !== e) ||
                                    (o[n].anim.stop(r), (t = !1), o.splice(n, 1));
                            (t || !r) && b.dequeue(this, e);
                        })
                    );
                },
                finish: function (e) {
                    return (
                        e !== !1 && (e = e || "fx"),
                        this.each(function () {
                            var t,
                                n = b._data(this),
                                r = n[e + "queue"],
                                i = n[e + "queueHooks"],
                                o = b.timers,
                                a = r ? r.length : 0;
                            for (
                                n.finish = !0,
                                    b.queue(this, e, []),
                                    i && i.cur && i.cur.finish && i.cur.finish.call(this),
                                    t = o.length;
                                t--;

                            )
                                o[t].elem === this && o[t].queue === e && (o[t].anim.stop(!0), o.splice(t, 1));
                            for (t = 0; a > t; t++) r[t] && r[t].finish && r[t].finish.call(this);
                            delete n.finish;
                        })
                    );
                },
            });
        function ir(e, t) {
            var n,
                r = { height: e },
                i = 0;
            for (t = t ? 1 : 0; 4 > i; i += 2 - t) (n = Zt[i]), (r["margin" + n] = r["padding" + n] = e);
            return t && (r.opacity = r.width = e), r;
        }
        b.each(
            {
                slideDown: ir("show"),
                slideUp: ir("hide"),
                slideToggle: ir("toggle"),
                fadeIn: { opacity: "show" },
                fadeOut: { opacity: "hide" },
                fadeToggle: { opacity: "toggle" },
            },
            function (e, t) {
                b.fn[e] = function (e, n, r) {
                    return this.animate(t, e, n, r);
                };
            }
        ),
            (b.speed = function (e, t, n) {
                var r =
                    e && "object" == typeof e
                        ? b.extend({}, e)
                        : {
                              complete: n || (!n && t) || (b.isFunction(e) && e),
                              duration: e,
                              easing: (n && t) || (t && !b.isFunction(t) && t),
                          };
                return (
                    (r.duration = b.fx.off
                        ? 0
                        : "number" == typeof r.duration
                          ? r.duration
                          : r.duration in b.fx.speeds
                            ? b.fx.speeds[r.duration]
                            : b.fx.speeds._default),
                    (null == r.queue || r.queue === !0) && (r.queue = "fx"),
                    (r.old = r.complete),
                    (r.complete = function () {
                        b.isFunction(r.old) && r.old.call(this), r.queue && b.dequeue(this, r.queue);
                    }),
                    r
                );
            }),
            (b.easing = {
                linear: function (e) {
                    return e;
                },
                swing: function (e) {
                    return 0.5 - Math.cos(e * Math.PI) / 2;
                },
            }),
            (b.timers = []),
            (b.fx = rr.prototype.init),
            (b.fx.tick = function () {
                var e,
                    n = b.timers,
                    r = 0;
                for (Xn = b.now(); n.length > r; r++) (e = n[r]), e() || n[r] !== e || n.splice(r--, 1);
                n.length || b.fx.stop(), (Xn = t);
            }),
            (b.fx.timer = function (e) {
                e() && b.timers.push(e) && b.fx.start();
            }),
            (b.fx.interval = 13),
            (b.fx.start = function () {
                Un || (Un = setInterval(b.fx.tick, b.fx.interval));
            }),
            (b.fx.stop = function () {
                clearInterval(Un), (Un = null);
            }),
            (b.fx.speeds = { slow: 600, fast: 200, _default: 400 }),
            (b.fx.step = {}),
            b.expr &&
                b.expr.filters &&
                (b.expr.filters.animated = function (e) {
                    return b.grep(b.timers, function (t) {
                        return e === t.elem;
                    }).length;
                }),
            (b.fn.offset = function (e) {
                if (arguments.length)
                    return e === t
                        ? this
                        : this.each(function (t) {
                              b.offset.setOffset(this, e, t);
                          });
                var n,
                    r,
                    o = { top: 0, left: 0 },
                    a = this[0],
                    s = a && a.ownerDocument;
                if (s)
                    return (
                        (n = s.documentElement),
                        b.contains(n, a)
                            ? (typeof a.getBoundingClientRect !== i && (o = a.getBoundingClientRect()),
                              (r = or(s)),
                              {
                                  top: o.top + (r.pageYOffset || n.scrollTop) - (n.clientTop || 0),
                                  left: o.left + (r.pageXOffset || n.scrollLeft) - (n.clientLeft || 0),
                              })
                            : o
                    );
            }),
            (b.offset = {
                setOffset: function (e, t, n) {
                    var r = b.css(e, "position");
                    "static" === r && (e.style.position = "relative");
                    var i = b(e),
                        o = i.offset(),
                        a = b.css(e, "top"),
                        s = b.css(e, "left"),
                        u = ("absolute" === r || "fixed" === r) && b.inArray("auto", [a, s]) > -1,
                        l = {},
                        c = {},
                        p,
                        f;
                    u
                        ? ((c = i.position()), (p = c.top), (f = c.left))
                        : ((p = parseFloat(a) || 0), (f = parseFloat(s) || 0)),
                        b.isFunction(t) && (t = t.call(e, n, o)),
                        null != t.top && (l.top = t.top - o.top + p),
                        null != t.left && (l.left = t.left - o.left + f),
                        "using" in t ? t.using.call(e, l) : i.css(l);
                },
            }),
            b.fn.extend({
                position: function () {
                    if (this[0]) {
                        var e,
                            t,
                            n = { top: 0, left: 0 },
                            r = this[0];
                        return (
                            "fixed" === b.css(r, "position")
                                ? (t = r.getBoundingClientRect())
                                : ((e = this.offsetParent()),
                                  (t = this.offset()),
                                  b.nodeName(e[0], "html") || (n = e.offset()),
                                  (n.top += b.css(e[0], "borderTopWidth", !0)),
                                  (n.left += b.css(e[0], "borderLeftWidth", !0))),
                            {
                                top: t.top - n.top - b.css(r, "marginTop", !0),
                                left: t.left - n.left - b.css(r, "marginLeft", !0),
                            }
                        );
                    }
                },
                offsetParent: function () {
                    return this.map(function () {
                        var e = this.offsetParent || o.documentElement;
                        while (e && !b.nodeName(e, "html") && "static" === b.css(e, "position")) e = e.offsetParent;
                        return e || o.documentElement;
                    });
                },
            }),
            b.each({ scrollLeft: "pageXOffset", scrollTop: "pageYOffset" }, function (e, n) {
                var r = /Y/.test(n);
                b.fn[e] = function (i) {
                    return b.access(
                        this,
                        function (e, i, o) {
                            var a = or(e);
                            return o === t
                                ? a
                                    ? n in a
                                        ? a[n]
                                        : a.document.documentElement[i]
                                    : e[i]
                                : (a ? a.scrollTo(r ? b(a).scrollLeft() : o, r ? o : b(a).scrollTop()) : (e[i] = o), t);
                        },
                        e,
                        i,
                        arguments.length,
                        null
                    );
                };
            });
        function or(e) {
            return b.isWindow(e) ? e : 9 === e.nodeType ? e.defaultView || e.parentWindow : !1;
        }
        b.each({ Height: "height", Width: "width" }, function (e, n) {
            b.each({ padding: "inner" + e, content: n, "": "outer" + e }, function (r, i) {
                b.fn[i] = function (i, o) {
                    var a = arguments.length && (r || "boolean" != typeof i),
                        s = r || (i === !0 || o === !0 ? "margin" : "border");
                    return b.access(
                        this,
                        function (n, r, i) {
                            var o;
                            return b.isWindow(n)
                                ? n.document.documentElement["client" + e]
                                : 9 === n.nodeType
                                  ? ((o = n.documentElement),
                                    Math.max(
                                        n.body["scroll" + e],
                                        o["scroll" + e],
                                        n.body["offset" + e],
                                        o["offset" + e],
                                        o["client" + e]
                                    ))
                                  : i === t
                                    ? b.css(n, r, s)
                                    : b.style(n, r, i, s);
                        },
                        n,
                        a ? i : t,
                        a,
                        null
                    );
                };
            });
        }),
            (e.jQuery = e.$ = b),
            "function" == typeof define &&
                define.amd &&
                define.amd.jQuery &&
                define("jquery", [], function () {
                    return b;
                });
    })(window);
    (function (factory) {
        if (typeof define === "function" && define.amd) {
            define(["jquery"], factory);
        } else {
            factory(jQuery);
        }
    })(function ($) {
        var pluses = /\+/g;
        function raw(s) {
            return s;
        }
        function decoded(s) {
            return decodeURIComponent(s.replace(pluses, " "));
        }
        function converted(s) {
            if (s.indexOf('"') === 0) {
                s = s.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, "\\");
            }
            try {
                return config.json ? JSON.parse(s) : s;
            } catch (er) {}
        }
        var config = ($.cookie = function (key, value, options) {
            if (value !== undefined) {
                options = $.extend({}, config.defaults, options);
                if (typeof options.expires === "number") {
                    var days = options.expires,
                        t = (options.expires = new Date());
                    t.setDate(t.getDate() + days);
                }
                value = config.json ? JSON.stringify(value) : String(value);
                return (document.cookie = [
                    config.raw ? key : encodeURIComponent(key),
                    "=",
                    config.raw ? value : encodeURIComponent(value),
                    options.expires ? "; expires=" + options.expires.toUTCString() : "",
                    options.path ? "; path=" + options.path : "",
                    options.domain ? "; domain=" + options.domain : "",
                    options.secure ? "; secure" : "",
                ].join(""));
            }
            var decode = config.raw ? raw : decoded;
            var cookies = document.cookie.split("; ");
            var result = key ? undefined : {};
            for (var i = 0, l = cookies.length; i < l; i++) {
                var parts = cookies[i].split("=");
                var name = decode(parts.shift());
                var cookie = decode(parts.join("="));
                if (key && key === name) {
                    result = converted(cookie);
                    break;
                }
                if (!key) {
                    result[name] = converted(cookie);
                }
            }
            return result;
        });
        config.defaults = {};
        $.removeCookie = function (key, options) {
            if ($.cookie(key) !== undefined) {
                $.cookie(key, "", $.extend({}, options, { expires: -1 }));
                return true;
            }
            return false;
        };
    });
    /*! jQuery UI - v1.10.2 - 2013-03-14
     * http://jqueryui.com
     * Includes: jquery.ui.core.js, jquery.ui.widget.js, jquery.ui.mouse.js, jquery.ui.draggable.js, jquery.ui.droppable.js, jquery.ui.resizable.js, jquery.ui.selectable.js, jquery.ui.sortable.js, jquery.ui.effect.js, jquery.ui.accordion.js, jquery.ui.autocomplete.js, jquery.ui.button.js, jquery.ui.datepicker.js, jquery.ui.dialog.js, jquery.ui.effect-blind.js, jquery.ui.effect-bounce.js, jquery.ui.effect-clip.js, jquery.ui.effect-drop.js, jquery.ui.effect-explode.js, jquery.ui.effect-fade.js, jquery.ui.effect-fold.js, jquery.ui.effect-highlight.js, jquery.ui.effect-pulsate.js, jquery.ui.effect-scale.js, jquery.ui.effect-shake.js, jquery.ui.effect-slide.js, jquery.ui.effect-transfer.js, jquery.ui.menu.js, jquery.ui.position.js, jquery.ui.progressbar.js, jquery.ui.slider.js, jquery.ui.spinner.js, jquery.ui.tabs.js, jquery.ui.tooltip.js
     * Copyright 2013 jQuery Foundation and other contributors; Licensed MIT */
    (function (t, e) {
        function i(e, i) {
            var n,
                o,
                a,
                r = e.nodeName.toLowerCase();
            return "area" === r
                ? ((n = e.parentNode),
                  (o = n.name),
                  e.href && o && "map" === n.nodeName.toLowerCase()
                      ? ((a = t("img[usemap=#" + o + "]")[0]), !!a && s(a))
                      : !1)
                : (/input|select|textarea|button|object/.test(r) ? !e.disabled : "a" === r ? e.href || i : i) && s(e);
        }
        function s(e) {
            return (
                t.expr.filters.visible(e) &&
                !t(e)
                    .parents()
                    .addBack()
                    .filter(function () {
                        return "hidden" === t.css(this, "visibility");
                    }).length
            );
        }
        var n = 0,
            o = /^ui-id-\d+$/;
        (t.ui = t.ui || {}),
            t.extend(t.ui, {
                version: "1.10.2",
                keyCode: {
                    BACKSPACE: 8,
                    COMMA: 188,
                    DELETE: 46,
                    DOWN: 40,
                    END: 35,
                    ENTER: 13,
                    ESCAPE: 27,
                    HOME: 36,
                    LEFT: 37,
                    NUMPAD_ADD: 107,
                    NUMPAD_DECIMAL: 110,
                    NUMPAD_DIVIDE: 111,
                    NUMPAD_ENTER: 108,
                    NUMPAD_MULTIPLY: 106,
                    NUMPAD_SUBTRACT: 109,
                    PAGE_DOWN: 34,
                    PAGE_UP: 33,
                    PERIOD: 190,
                    RIGHT: 39,
                    SPACE: 32,
                    TAB: 9,
                    UP: 38,
                },
            }),
            t.fn.extend({
                focus: (function (e) {
                    return function (i, s) {
                        return "number" == typeof i
                            ? this.each(function () {
                                  var e = this;
                                  setTimeout(function () {
                                      t(e).focus(), s && s.call(e);
                                  }, i);
                              })
                            : e.apply(this, arguments);
                    };
                })(t.fn.focus),
                scrollParent: function () {
                    var e;
                    return (
                        (e =
                            (t.ui.ie && /(static|relative)/.test(this.css("position"))) ||
                            /absolute/.test(this.css("position"))
                                ? this.parents()
                                      .filter(function () {
                                          return (
                                              /(relative|absolute|fixed)/.test(t.css(this, "position")) &&
                                              /(auto|scroll)/.test(
                                                  t.css(this, "overflow") +
                                                      t.css(this, "overflow-y") +
                                                      t.css(this, "overflow-x")
                                              )
                                          );
                                      })
                                      .eq(0)
                                : this.parents()
                                      .filter(function () {
                                          return /(auto|scroll)/.test(
                                              t.css(this, "overflow") +
                                                  t.css(this, "overflow-y") +
                                                  t.css(this, "overflow-x")
                                          );
                                      })
                                      .eq(0)),
                        /fixed/.test(this.css("position")) || !e.length ? t(document) : e
                    );
                },
                zIndex: function (i) {
                    if (i !== e) return this.css("zIndex", i);
                    if (this.length)
                        for (var s, n, o = t(this[0]); o.length && o[0] !== document; ) {
                            if (
                                ((s = o.css("position")),
                                ("absolute" === s || "relative" === s || "fixed" === s) &&
                                    ((n = parseInt(o.css("zIndex"), 10)), !isNaN(n) && 0 !== n))
                            )
                                return n;
                            o = o.parent();
                        }
                    return 0;
                },
                uniqueId: function () {
                    return this.each(function () {
                        this.id || (this.id = "ui-id-" + ++n);
                    });
                },
                removeUniqueId: function () {
                    return this.each(function () {
                        o.test(this.id) && t(this).removeAttr("id");
                    });
                },
            }),
            t.extend(t.expr[":"], {
                data: t.expr.createPseudo
                    ? t.expr.createPseudo(function (e) {
                          return function (i) {
                              return !!t.data(i, e);
                          };
                      })
                    : function (e, i, s) {
                          return !!t.data(e, s[3]);
                      },
                focusable: function (e) {
                    return i(e, !isNaN(t.attr(e, "tabindex")));
                },
                tabbable: function (e) {
                    var s = t.attr(e, "tabindex"),
                        n = isNaN(s);
                    return (n || s >= 0) && i(e, !n);
                },
            }),
            t("<a>").outerWidth(1).jquery ||
                t.each(["Width", "Height"], function (i, s) {
                    function n(e, i, s, n) {
                        return (
                            t.each(o, function () {
                                (i -= parseFloat(t.css(e, "padding" + this)) || 0),
                                    s && (i -= parseFloat(t.css(e, "border" + this + "Width")) || 0),
                                    n && (i -= parseFloat(t.css(e, "margin" + this)) || 0);
                            }),
                            i
                        );
                    }
                    var o = "Width" === s ? ["Left", "Right"] : ["Top", "Bottom"],
                        a = s.toLowerCase(),
                        r = {
                            innerWidth: t.fn.innerWidth,
                            innerHeight: t.fn.innerHeight,
                            outerWidth: t.fn.outerWidth,
                            outerHeight: t.fn.outerHeight,
                        };
                    (t.fn["inner" + s] = function (i) {
                        return i === e
                            ? r["inner" + s].call(this)
                            : this.each(function () {
                                  t(this).css(a, n(this, i) + "px");
                              });
                    }),
                        (t.fn["outer" + s] = function (e, i) {
                            return "number" != typeof e
                                ? r["outer" + s].call(this, e)
                                : this.each(function () {
                                      t(this).css(a, n(this, e, !0, i) + "px");
                                  });
                        });
                }),
            t.fn.addBack ||
                (t.fn.addBack = function (t) {
                    return this.add(null == t ? this.prevObject : this.prevObject.filter(t));
                }),
            t("<a>").data("a-b", "a").removeData("a-b").data("a-b") &&
                (t.fn.removeData = (function (e) {
                    return function (i) {
                        return arguments.length ? e.call(this, t.camelCase(i)) : e.call(this);
                    };
                })(t.fn.removeData)),
            (t.ui.ie = !!/msie [\w.]+/.exec(navigator.userAgent.toLowerCase())),
            (t.support.selectstart = "onselectstart" in document.createElement("div")),
            t.fn.extend({
                disableSelection: function () {
                    return this.bind(
                        (t.support.selectstart ? "selectstart" : "mousedown") + ".ui-disableSelection",
                        function (t) {
                            t.preventDefault();
                        }
                    );
                },
                enableSelection: function () {
                    return this.unbind(".ui-disableSelection");
                },
            }),
            t.extend(t.ui, {
                plugin: {
                    add: function (e, i, s) {
                        var n,
                            o = t.ui[e].prototype;
                        for (n in s) (o.plugins[n] = o.plugins[n] || []), o.plugins[n].push([i, s[n]]);
                    },
                    call: function (t, e, i) {
                        var s,
                            n = t.plugins[e];
                        if (n && t.element[0].parentNode && 11 !== t.element[0].parentNode.nodeType)
                            for (s = 0; n.length > s; s++) t.options[n[s][0]] && n[s][1].apply(t.element, i);
                    },
                },
                hasScroll: function (e, i) {
                    if ("hidden" === t(e).css("overflow")) return !1;
                    var s = i && "left" === i ? "scrollLeft" : "scrollTop",
                        n = !1;
                    return e[s] > 0 ? !0 : ((e[s] = 1), (n = e[s] > 0), (e[s] = 0), n);
                },
            });
    })(jQuery),
        (function (t, e) {
            var i = 0,
                s = Array.prototype.slice,
                n = t.cleanData;
            (t.cleanData = function (e) {
                for (var i, s = 0; null != (i = e[s]); s++)
                    try {
                        t(i).triggerHandler("remove");
                    } catch (o) {}
                n(e);
            }),
                (t.widget = function (i, s, n) {
                    var o,
                        a,
                        r,
                        h,
                        l = {},
                        c = i.split(".")[0];
                    (i = i.split(".")[1]),
                        (o = c + "-" + i),
                        n || ((n = s), (s = t.Widget)),
                        (t.expr[":"][o.toLowerCase()] = function (e) {
                            return !!t.data(e, o);
                        }),
                        (t[c] = t[c] || {}),
                        (a = t[c][i]),
                        (r = t[c][i] =
                            function (t, i) {
                                return this._createWidget
                                    ? (arguments.length && this._createWidget(t, i), e)
                                    : new r(t, i);
                            }),
                        t.extend(r, a, { version: n.version, _proto: t.extend({}, n), _childConstructors: [] }),
                        (h = new s()),
                        (h.options = t.widget.extend({}, h.options)),
                        t.each(n, function (i, n) {
                            return t.isFunction(n)
                                ? ((l[i] = (function () {
                                      var t = function () {
                                              return s.prototype[i].apply(this, arguments);
                                          },
                                          e = function (t) {
                                              return s.prototype[i].apply(this, t);
                                          };
                                      return function () {
                                          var i,
                                              s = this._super,
                                              o = this._superApply;
                                          return (
                                              (this._super = t),
                                              (this._superApply = e),
                                              (i = n.apply(this, arguments)),
                                              (this._super = s),
                                              (this._superApply = o),
                                              i
                                          );
                                      };
                                  })()),
                                  e)
                                : ((l[i] = n), e);
                        }),
                        (r.prototype = t.widget.extend(h, { widgetEventPrefix: a ? h.widgetEventPrefix : i }, l, {
                            constructor: r,
                            namespace: c,
                            widgetName: i,
                            widgetFullName: o,
                        })),
                        a
                            ? (t.each(a._childConstructors, function (e, i) {
                                  var s = i.prototype;
                                  t.widget(s.namespace + "." + s.widgetName, r, i._proto);
                              }),
                              delete a._childConstructors)
                            : s._childConstructors.push(r),
                        t.widget.bridge(i, r);
                }),
                (t.widget.extend = function (i) {
                    for (var n, o, a = s.call(arguments, 1), r = 0, h = a.length; h > r; r++)
                        for (n in a[r])
                            (o = a[r][n]),
                                a[r].hasOwnProperty(n) &&
                                    o !== e &&
                                    (i[n] = t.isPlainObject(o)
                                        ? t.isPlainObject(i[n])
                                            ? t.widget.extend({}, i[n], o)
                                            : t.widget.extend({}, o)
                                        : o);
                    return i;
                }),
                (t.widget.bridge = function (i, n) {
                    var o = n.prototype.widgetFullName || i;
                    t.fn[i] = function (a) {
                        var r = "string" == typeof a,
                            h = s.call(arguments, 1),
                            l = this;
                        return (
                            (a = !r && h.length ? t.widget.extend.apply(null, [a].concat(h)) : a),
                            r
                                ? this.each(function () {
                                      var s,
                                          n = t.data(this, o);
                                      return n
                                          ? t.isFunction(n[a]) && "_" !== a.charAt(0)
                                              ? ((s = n[a].apply(n, h)),
                                                s !== n && s !== e
                                                    ? ((l = s && s.jquery ? l.pushStack(s.get()) : s), !1)
                                                    : e)
                                              : t.error("no such method '" + a + "' for " + i + " widget instance")
                                          : t.error(
                                                "cannot call methods on " +
                                                    i +
                                                    " prior to initialization; " +
                                                    "attempted to call method '" +
                                                    a +
                                                    "'"
                                            );
                                  })
                                : this.each(function () {
                                      var e = t.data(this, o);
                                      e ? e.option(a || {})._init() : t.data(this, o, new n(a, this));
                                  }),
                            l
                        );
                    };
                }),
                (t.Widget = function () {}),
                (t.Widget._childConstructors = []),
                (t.Widget.prototype = {
                    widgetName: "widget",
                    widgetEventPrefix: "",
                    defaultElement: "<div>",
                    options: { disabled: !1, create: null },
                    _createWidget: function (e, s) {
                        (s = t(s || this.defaultElement || this)[0]),
                            (this.element = t(s)),
                            (this.uuid = i++),
                            (this.eventNamespace = "." + this.widgetName + this.uuid),
                            (this.options = t.widget.extend({}, this.options, this._getCreateOptions(), e)),
                            (this.bindings = t()),
                            (this.hoverable = t()),
                            (this.focusable = t()),
                            s !== this &&
                                (t.data(s, this.widgetFullName, this),
                                this._on(!0, this.element, {
                                    remove: function (t) {
                                        t.target === s && this.destroy();
                                    },
                                }),
                                (this.document = t(s.style ? s.ownerDocument : s.document || s)),
                                (this.window = t(this.document[0].defaultView || this.document[0].parentWindow))),
                            this._create(),
                            this._trigger("create", null, this._getCreateEventData()),
                            this._init();
                    },
                    _getCreateOptions: t.noop,
                    _getCreateEventData: t.noop,
                    _create: t.noop,
                    _init: t.noop,
                    destroy: function () {
                        this._destroy(),
                            this.element
                                .unbind(this.eventNamespace)
                                .removeData(this.widgetName)
                                .removeData(this.widgetFullName)
                                .removeData(t.camelCase(this.widgetFullName)),
                            this.widget()
                                .unbind(this.eventNamespace)
                                .removeAttr("aria-disabled")
                                .removeClass(this.widgetFullName + "-disabled " + "ui-state-disabled"),
                            this.bindings.unbind(this.eventNamespace),
                            this.hoverable.removeClass("ui-state-hover"),
                            this.focusable.removeClass("ui-state-focus");
                    },
                    _destroy: t.noop,
                    widget: function () {
                        return this.element;
                    },
                    option: function (i, s) {
                        var n,
                            o,
                            a,
                            r = i;
                        if (0 === arguments.length) return t.widget.extend({}, this.options);
                        if ("string" == typeof i)
                            if (((r = {}), (n = i.split(".")), (i = n.shift()), n.length)) {
                                for (o = r[i] = t.widget.extend({}, this.options[i]), a = 0; n.length - 1 > a; a++)
                                    (o[n[a]] = o[n[a]] || {}), (o = o[n[a]]);
                                if (((i = n.pop()), s === e)) return o[i] === e ? null : o[i];
                                o[i] = s;
                            } else {
                                if (s === e) return this.options[i] === e ? null : this.options[i];
                                r[i] = s;
                            }
                        return this._setOptions(r), this;
                    },
                    _setOptions: function (t) {
                        var e;
                        for (e in t) this._setOption(e, t[e]);
                        return this;
                    },
                    _setOption: function (t, e) {
                        return (
                            (this.options[t] = e),
                            "disabled" === t &&
                                (this.widget()
                                    .toggleClass(this.widgetFullName + "-disabled ui-state-disabled", !!e)
                                    .attr("aria-disabled", e),
                                this.hoverable.removeClass("ui-state-hover"),
                                this.focusable.removeClass("ui-state-focus")),
                            this
                        );
                    },
                    enable: function () {
                        return this._setOption("disabled", !1);
                    },
                    disable: function () {
                        return this._setOption("disabled", !0);
                    },
                    _on: function (i, s, n) {
                        var o,
                            a = this;
                        "boolean" != typeof i && ((n = s), (s = i), (i = !1)),
                            n
                                ? ((s = o = t(s)), (this.bindings = this.bindings.add(s)))
                                : ((n = s), (s = this.element), (o = this.widget())),
                            t.each(n, function (n, r) {
                                function h() {
                                    return i || (a.options.disabled !== !0 && !t(this).hasClass("ui-state-disabled"))
                                        ? ("string" == typeof r ? a[r] : r).apply(a, arguments)
                                        : e;
                                }
                                "string" != typeof r && (h.guid = r.guid = r.guid || h.guid || t.guid++);
                                var l = n.match(/^(\w+)\s*(.*)$/),
                                    c = l[1] + a.eventNamespace,
                                    u = l[2];
                                u ? o.delegate(u, c, h) : s.bind(c, h);
                            });
                    },
                    _off: function (t, e) {
                        (e = (e || "").split(" ").join(this.eventNamespace + " ") + this.eventNamespace),
                            t.unbind(e).undelegate(e);
                    },
                    _delay: function (t, e) {
                        function i() {
                            return ("string" == typeof t ? s[t] : t).apply(s, arguments);
                        }
                        var s = this;
                        return setTimeout(i, e || 0);
                    },
                    _hoverable: function (e) {
                        (this.hoverable = this.hoverable.add(e)),
                            this._on(e, {
                                mouseenter: function (e) {
                                    t(e.currentTarget).addClass("ui-state-hover");
                                },
                                mouseleave: function (e) {
                                    t(e.currentTarget).removeClass("ui-state-hover");
                                },
                            });
                    },
                    _focusable: function (e) {
                        (this.focusable = this.focusable.add(e)),
                            this._on(e, {
                                focusin: function (e) {
                                    t(e.currentTarget).addClass("ui-state-focus");
                                },
                                focusout: function (e) {
                                    t(e.currentTarget).removeClass("ui-state-focus");
                                },
                            });
                    },
                    _trigger: function (e, i, s) {
                        var n,
                            o,
                            a = this.options[e];
                        if (
                            ((s = s || {}),
                            (i = t.Event(i)),
                            (i.type = (e === this.widgetEventPrefix ? e : this.widgetEventPrefix + e).toLowerCase()),
                            (i.target = this.element[0]),
                            (o = i.originalEvent))
                        )
                            for (n in o) n in i || (i[n] = o[n]);
                        return (
                            this.element.trigger(i, s),
                            !(
                                (t.isFunction(a) && a.apply(this.element[0], [i].concat(s)) === !1) ||
                                i.isDefaultPrevented()
                            )
                        );
                    },
                }),
                t.each({ show: "fadeIn", hide: "fadeOut" }, function (e, i) {
                    t.Widget.prototype["_" + e] = function (s, n, o) {
                        "string" == typeof n && (n = { effect: n });
                        var a,
                            r = n ? (n === !0 || "number" == typeof n ? i : n.effect || i) : e;
                        (n = n || {}),
                            "number" == typeof n && (n = { duration: n }),
                            (a = !t.isEmptyObject(n)),
                            (n.complete = o),
                            n.delay && s.delay(n.delay),
                            a && t.effects && t.effects.effect[r]
                                ? s[e](n)
                                : r !== e && s[r]
                                  ? s[r](n.duration, n.easing, o)
                                  : s.queue(function (i) {
                                        t(this)[e](), o && o.call(s[0]), i();
                                    });
                    };
                });
        })(jQuery),
        (function (t) {
            var e = !1;
            t(document).mouseup(function () {
                e = !1;
            }),
                t.widget("ui.mouse", {
                    version: "1.10.2",
                    options: { cancel: "input,textarea,button,select,option", distance: 1, delay: 0 },
                    _mouseInit: function () {
                        var e = this;
                        this.element
                            .bind("mousedown." + this.widgetName, function (t) {
                                return e._mouseDown(t);
                            })
                            .bind("click." + this.widgetName, function (i) {
                                return !0 === t.data(i.target, e.widgetName + ".preventClickEvent")
                                    ? (t.removeData(i.target, e.widgetName + ".preventClickEvent"),
                                      i.stopImmediatePropagation(),
                                      !1)
                                    : undefined;
                            }),
                            (this.started = !1);
                    },
                    _mouseDestroy: function () {
                        this.element.unbind("." + this.widgetName),
                            this._mouseMoveDelegate &&
                                t(document)
                                    .unbind("mousemove." + this.widgetName, this._mouseMoveDelegate)
                                    .unbind("mouseup." + this.widgetName, this._mouseUpDelegate);
                    },
                    _mouseDown: function (i) {
                        if (!e) {
                            this._mouseStarted && this._mouseUp(i), (this._mouseDownEvent = i);
                            var s = this,
                                n = 1 === i.which,
                                o =
                                    "string" == typeof this.options.cancel && i.target.nodeName
                                        ? t(i.target).closest(this.options.cancel).length
                                        : !1;
                            return n && !o && this._mouseCapture(i)
                                ? ((this.mouseDelayMet = !this.options.delay),
                                  this.mouseDelayMet ||
                                      (this._mouseDelayTimer = setTimeout(function () {
                                          s.mouseDelayMet = !0;
                                      }, this.options.delay)),
                                  this._mouseDistanceMet(i) &&
                                  this._mouseDelayMet(i) &&
                                  ((this._mouseStarted = this._mouseStart(i) !== !1), !this._mouseStarted)
                                      ? (i.preventDefault(), !0)
                                      : (!0 === t.data(i.target, this.widgetName + ".preventClickEvent") &&
                                            t.removeData(i.target, this.widgetName + ".preventClickEvent"),
                                        (this._mouseMoveDelegate = function (t) {
                                            return s._mouseMove(t);
                                        }),
                                        (this._mouseUpDelegate = function (t) {
                                            return s._mouseUp(t);
                                        }),
                                        t(document)
                                            .bind("mousemove." + this.widgetName, this._mouseMoveDelegate)
                                            .bind("mouseup." + this.widgetName, this._mouseUpDelegate),
                                        i.preventDefault(),
                                        (e = !0),
                                        !0))
                                : !0;
                        }
                    },
                    _mouseMove: function (e) {
                        return t.ui.ie && (!document.documentMode || 9 > document.documentMode) && !e.button
                            ? this._mouseUp(e)
                            : this._mouseStarted
                              ? (this._mouseDrag(e), e.preventDefault())
                              : (this._mouseDistanceMet(e) &&
                                    this._mouseDelayMet(e) &&
                                    ((this._mouseStarted = this._mouseStart(this._mouseDownEvent, e) !== !1),
                                    this._mouseStarted ? this._mouseDrag(e) : this._mouseUp(e)),
                                !this._mouseStarted);
                    },
                    _mouseUp: function (e) {
                        return (
                            t(document)
                                .unbind("mousemove." + this.widgetName, this._mouseMoveDelegate)
                                .unbind("mouseup." + this.widgetName, this._mouseUpDelegate),
                            this._mouseStarted &&
                                ((this._mouseStarted = !1),
                                e.target === this._mouseDownEvent.target &&
                                    t.data(e.target, this.widgetName + ".preventClickEvent", !0),
                                this._mouseStop(e)),
                            !1
                        );
                    },
                    _mouseDistanceMet: function (t) {
                        return (
                            Math.max(
                                Math.abs(this._mouseDownEvent.pageX - t.pageX),
                                Math.abs(this._mouseDownEvent.pageY - t.pageY)
                            ) >= this.options.distance
                        );
                    },
                    _mouseDelayMet: function () {
                        return this.mouseDelayMet;
                    },
                    _mouseStart: function () {},
                    _mouseDrag: function () {},
                    _mouseStop: function () {},
                    _mouseCapture: function () {
                        return !0;
                    },
                });
        })(jQuery),
        (function (t) {
            t.widget("ui.draggable", t.ui.mouse, {
                version: "1.10.2",
                widgetEventPrefix: "drag",
                options: {
                    addClasses: !0,
                    appendTo: "parent",
                    axis: !1,
                    connectToSortable: !1,
                    containment: !1,
                    cursor: "auto",
                    cursorAt: !1,
                    grid: !1,
                    handle: !1,
                    helper: "original",
                    iframeFix: !1,
                    opacity: !1,
                    refreshPositions: !1,
                    revert: !1,
                    revertDuration: 500,
                    scope: "default",
                    scroll: !0,
                    scrollSensitivity: 20,
                    scrollSpeed: 20,
                    snap: !1,
                    snapMode: "both",
                    snapTolerance: 20,
                    stack: !1,
                    zIndex: !1,
                    drag: null,
                    start: null,
                    stop: null,
                },
                _create: function () {
                    "original" !== this.options.helper ||
                        /^(?:r|a|f)/.test(this.element.css("position")) ||
                        (this.element[0].style.position = "relative"),
                        this.options.addClasses && this.element.addClass("ui-draggable"),
                        this.options.disabled && this.element.addClass("ui-draggable-disabled"),
                        this._mouseInit();
                },
                _destroy: function () {
                    this.element.removeClass("ui-draggable ui-draggable-dragging ui-draggable-disabled"),
                        this._mouseDestroy();
                },
                _mouseCapture: function (e) {
                    var i = this.options;
                    return this.helper || i.disabled || t(e.target).closest(".ui-resizable-handle").length > 0
                        ? !1
                        : ((this.handle = this._getHandle(e)),
                          this.handle
                              ? (t(i.iframeFix === !0 ? "iframe" : i.iframeFix).each(function () {
                                    t("<div class='ui-draggable-iframeFix' style='background: #fff;'></div>")
                                        .css({
                                            width: this.offsetWidth + "px",
                                            height: this.offsetHeight + "px",
                                            position: "absolute",
                                            opacity: "0.001",
                                            zIndex: 1e3,
                                        })
                                        .css(t(this).offset())
                                        .appendTo("body");
                                }),
                                !0)
                              : !1);
                },
                _mouseStart: function (e) {
                    var i = this.options;
                    return (
                        (this.helper = this._createHelper(e)),
                        this.helper.addClass("ui-draggable-dragging"),
                        this._cacheHelperProportions(),
                        t.ui.ddmanager && (t.ui.ddmanager.current = this),
                        this._cacheMargins(),
                        (this.cssPosition = this.helper.css("position")),
                        (this.scrollParent = this.helper.scrollParent()),
                        (this.offset = this.positionAbs = this.element.offset()),
                        (this.offset = {
                            top: this.offset.top - this.margins.top,
                            left: this.offset.left - this.margins.left,
                        }),
                        t.extend(this.offset, {
                            click: { left: e.pageX - this.offset.left, top: e.pageY - this.offset.top },
                            parent: this._getParentOffset(),
                            relative: this._getRelativeOffset(),
                        }),
                        (this.originalPosition = this.position = this._generatePosition(e)),
                        (this.originalPageX = e.pageX),
                        (this.originalPageY = e.pageY),
                        i.cursorAt && this._adjustOffsetFromHelper(i.cursorAt),
                        i.containment && this._setContainment(),
                        this._trigger("start", e) === !1
                            ? (this._clear(), !1)
                            : (this._cacheHelperProportions(),
                              t.ui.ddmanager && !i.dropBehaviour && t.ui.ddmanager.prepareOffsets(this, e),
                              this._mouseDrag(e, !0),
                              t.ui.ddmanager && t.ui.ddmanager.dragStart(this, e),
                              !0)
                    );
                },
                _mouseDrag: function (e, i) {
                    if (
                        ((this.position = this._generatePosition(e)),
                        (this.positionAbs = this._convertPositionTo("absolute")),
                        !i)
                    ) {
                        var s = this._uiHash();
                        if (this._trigger("drag", e, s) === !1) return this._mouseUp({}), !1;
                        this.position = s.position;
                    }
                    return (
                        (this.options.axis && "y" === this.options.axis) ||
                            (this.helper[0].style.left = this.position.left + "px"),
                        (this.options.axis && "x" === this.options.axis) ||
                            (this.helper[0].style.top = this.position.top + "px"),
                        t.ui.ddmanager && t.ui.ddmanager.drag(this, e),
                        !1
                    );
                },
                _mouseStop: function (e) {
                    var i,
                        s = this,
                        n = !1,
                        o = !1;
                    for (
                        t.ui.ddmanager && !this.options.dropBehaviour && (o = t.ui.ddmanager.drop(this, e)),
                            this.dropped && ((o = this.dropped), (this.dropped = !1)),
                            i = this.element[0];
                        i && (i = i.parentNode);

                    )
                        i === document && (n = !0);
                    return n || "original" !== this.options.helper
                        ? (("invalid" === this.options.revert && !o) ||
                          ("valid" === this.options.revert && o) ||
                          this.options.revert === !0 ||
                          (t.isFunction(this.options.revert) && this.options.revert.call(this.element, o))
                              ? t(this.helper).animate(
                                    this.originalPosition,
                                    parseInt(this.options.revertDuration, 10),
                                    function () {
                                        s._trigger("stop", e) !== !1 && s._clear();
                                    }
                                )
                              : this._trigger("stop", e) !== !1 && this._clear(),
                          !1)
                        : !1;
                },
                _mouseUp: function (e) {
                    return (
                        t("div.ui-draggable-iframeFix").each(function () {
                            this.parentNode.removeChild(this);
                        }),
                        t.ui.ddmanager && t.ui.ddmanager.dragStop(this, e),
                        t.ui.mouse.prototype._mouseUp.call(this, e)
                    );
                },
                cancel: function () {
                    return this.helper.is(".ui-draggable-dragging") ? this._mouseUp({}) : this._clear(), this;
                },
                _getHandle: function (e) {
                    return this.options.handle
                        ? !!t(e.target).closest(this.element.find(this.options.handle)).length
                        : !0;
                },
                _createHelper: function (e) {
                    var i = this.options,
                        s = t.isFunction(i.helper)
                            ? t(i.helper.apply(this.element[0], [e]))
                            : "clone" === i.helper
                              ? this.element.clone().removeAttr("id")
                              : this.element;
                    return (
                        s.parents("body").length ||
                            s.appendTo("parent" === i.appendTo ? this.element[0].parentNode : i.appendTo),
                        s[0] === this.element[0] ||
                            /(fixed|absolute)/.test(s.css("position")) ||
                            s.css("position", "absolute"),
                        s
                    );
                },
                _adjustOffsetFromHelper: function (e) {
                    "string" == typeof e && (e = e.split(" ")),
                        t.isArray(e) && (e = { left: +e[0], top: +e[1] || 0 }),
                        "left" in e && (this.offset.click.left = e.left + this.margins.left),
                        "right" in e &&
                            (this.offset.click.left = this.helperProportions.width - e.right + this.margins.left),
                        "top" in e && (this.offset.click.top = e.top + this.margins.top),
                        "bottom" in e &&
                            (this.offset.click.top = this.helperProportions.height - e.bottom + this.margins.top);
                },
                _getParentOffset: function () {
                    this.offsetParent = this.helper.offsetParent();
                    var e = this.offsetParent.offset();
                    return (
                        "absolute" === this.cssPosition &&
                            this.scrollParent[0] !== document &&
                            t.contains(this.scrollParent[0], this.offsetParent[0]) &&
                            ((e.left += this.scrollParent.scrollLeft()), (e.top += this.scrollParent.scrollTop())),
                        (this.offsetParent[0] === document.body ||
                            (this.offsetParent[0].tagName &&
                                "html" === this.offsetParent[0].tagName.toLowerCase() &&
                                t.ui.ie)) &&
                            (e = { top: 0, left: 0 }),
                        {
                            top: e.top + (parseInt(this.offsetParent.css("borderTopWidth"), 10) || 0),
                            left: e.left + (parseInt(this.offsetParent.css("borderLeftWidth"), 10) || 0),
                        }
                    );
                },
                _getRelativeOffset: function () {
                    if ("relative" === this.cssPosition) {
                        var t = this.element.position();
                        return {
                            top: t.top - (parseInt(this.helper.css("top"), 10) || 0) + this.scrollParent.scrollTop(),
                            left:
                                t.left - (parseInt(this.helper.css("left"), 10) || 0) + this.scrollParent.scrollLeft(),
                        };
                    }
                    return { top: 0, left: 0 };
                },
                _cacheMargins: function () {
                    this.margins = {
                        left: parseInt(this.element.css("marginLeft"), 10) || 0,
                        top: parseInt(this.element.css("marginTop"), 10) || 0,
                        right: parseInt(this.element.css("marginRight"), 10) || 0,
                        bottom: parseInt(this.element.css("marginBottom"), 10) || 0,
                    };
                },
                _cacheHelperProportions: function () {
                    this.helperProportions = { width: this.helper.outerWidth(), height: this.helper.outerHeight() };
                },
                _setContainment: function () {
                    var e,
                        i,
                        s,
                        n = this.options;
                    if (
                        ("parent" === n.containment && (n.containment = this.helper[0].parentNode),
                        ("document" === n.containment || "window" === n.containment) &&
                            (this.containment = [
                                "document" === n.containment
                                    ? 0
                                    : t(window).scrollLeft() - this.offset.relative.left - this.offset.parent.left,
                                "document" === n.containment
                                    ? 0
                                    : t(window).scrollTop() - this.offset.relative.top - this.offset.parent.top,
                                ("document" === n.containment ? 0 : t(window).scrollLeft()) +
                                    t("document" === n.containment ? document : window).width() -
                                    this.helperProportions.width -
                                    this.margins.left,
                                ("document" === n.containment ? 0 : t(window).scrollTop()) +
                                    (t("document" === n.containment ? document : window).height() ||
                                        document.body.parentNode.scrollHeight) -
                                    this.helperProportions.height -
                                    this.margins.top,
                            ]),
                        /^(document|window|parent)$/.test(n.containment) || n.containment.constructor === Array)
                    )
                        n.containment.constructor === Array && (this.containment = n.containment);
                    else {
                        if (((i = t(n.containment)), (s = i[0]), !s)) return;
                        (e = "hidden" !== t(s).css("overflow")),
                            (this.containment = [
                                (parseInt(t(s).css("borderLeftWidth"), 10) || 0) +
                                    (parseInt(t(s).css("paddingLeft"), 10) || 0),
                                (parseInt(t(s).css("borderTopWidth"), 10) || 0) +
                                    (parseInt(t(s).css("paddingTop"), 10) || 0),
                                (e ? Math.max(s.scrollWidth, s.offsetWidth) : s.offsetWidth) -
                                    (parseInt(t(s).css("borderRightWidth"), 10) || 0) -
                                    (parseInt(t(s).css("paddingRight"), 10) || 0) -
                                    this.helperProportions.width -
                                    this.margins.left -
                                    this.margins.right,
                                (e ? Math.max(s.scrollHeight, s.offsetHeight) : s.offsetHeight) -
                                    (parseInt(t(s).css("borderBottomWidth"), 10) || 0) -
                                    (parseInt(t(s).css("paddingBottom"), 10) || 0) -
                                    this.helperProportions.height -
                                    this.margins.top -
                                    this.margins.bottom,
                            ]),
                            (this.relative_container = i);
                    }
                },
                _convertPositionTo: function (e, i) {
                    i || (i = this.position);
                    var s = "absolute" === e ? 1 : -1,
                        n =
                            "absolute" !== this.cssPosition ||
                            (this.scrollParent[0] !== document &&
                                t.contains(this.scrollParent[0], this.offsetParent[0]))
                                ? this.scrollParent
                                : this.offsetParent,
                        o = /(html|body)/i.test(n[0].tagName);
                    return {
                        top:
                            i.top +
                            this.offset.relative.top * s +
                            this.offset.parent.top * s -
                            ("fixed" === this.cssPosition ? -this.scrollParent.scrollTop() : o ? 0 : n.scrollTop()) * s,
                        left:
                            i.left +
                            this.offset.relative.left * s +
                            this.offset.parent.left * s -
                            ("fixed" === this.cssPosition ? -this.scrollParent.scrollLeft() : o ? 0 : n.scrollLeft()) *
                                s,
                    };
                },
                _generatePosition: function (e) {
                    var i,
                        s,
                        n,
                        o,
                        a = this.options,
                        r =
                            "absolute" !== this.cssPosition ||
                            (this.scrollParent[0] !== document &&
                                t.contains(this.scrollParent[0], this.offsetParent[0]))
                                ? this.scrollParent
                                : this.offsetParent,
                        h = /(html|body)/i.test(r[0].tagName),
                        l = e.pageX,
                        c = e.pageY;
                    return (
                        this.originalPosition &&
                            (this.containment &&
                                (this.relative_container
                                    ? ((s = this.relative_container.offset()),
                                      (i = [
                                          this.containment[0] + s.left,
                                          this.containment[1] + s.top,
                                          this.containment[2] + s.left,
                                          this.containment[3] + s.top,
                                      ]))
                                    : (i = this.containment),
                                e.pageX - this.offset.click.left < i[0] && (l = i[0] + this.offset.click.left),
                                e.pageY - this.offset.click.top < i[1] && (c = i[1] + this.offset.click.top),
                                e.pageX - this.offset.click.left > i[2] && (l = i[2] + this.offset.click.left),
                                e.pageY - this.offset.click.top > i[3] && (c = i[3] + this.offset.click.top)),
                            a.grid &&
                                ((n = a.grid[1]
                                    ? this.originalPageY + Math.round((c - this.originalPageY) / a.grid[1]) * a.grid[1]
                                    : this.originalPageY),
                                (c = i
                                    ? n - this.offset.click.top >= i[1] || n - this.offset.click.top > i[3]
                                        ? n
                                        : n - this.offset.click.top >= i[1]
                                          ? n - a.grid[1]
                                          : n + a.grid[1]
                                    : n),
                                (o = a.grid[0]
                                    ? this.originalPageX + Math.round((l - this.originalPageX) / a.grid[0]) * a.grid[0]
                                    : this.originalPageX),
                                (l = i
                                    ? o - this.offset.click.left >= i[0] || o - this.offset.click.left > i[2]
                                        ? o
                                        : o - this.offset.click.left >= i[0]
                                          ? o - a.grid[0]
                                          : o + a.grid[0]
                                    : o))),
                        {
                            top:
                                c -
                                this.offset.click.top -
                                this.offset.relative.top -
                                this.offset.parent.top +
                                ("fixed" === this.cssPosition ? -this.scrollParent.scrollTop() : h ? 0 : r.scrollTop()),
                            left:
                                l -
                                this.offset.click.left -
                                this.offset.relative.left -
                                this.offset.parent.left +
                                ("fixed" === this.cssPosition
                                    ? -this.scrollParent.scrollLeft()
                                    : h
                                      ? 0
                                      : r.scrollLeft()),
                        }
                    );
                },
                _clear: function () {
                    this.helper.removeClass("ui-draggable-dragging"),
                        this.helper[0] === this.element[0] || this.cancelHelperRemoval || this.helper.remove(),
                        (this.helper = null),
                        (this.cancelHelperRemoval = !1);
                },
                _trigger: function (e, i, s) {
                    return (
                        (s = s || this._uiHash()),
                        t.ui.plugin.call(this, e, [i, s]),
                        "drag" === e && (this.positionAbs = this._convertPositionTo("absolute")),
                        t.Widget.prototype._trigger.call(this, e, i, s)
                    );
                },
                plugins: {},
                _uiHash: function () {
                    return {
                        helper: this.helper,
                        position: this.position,
                        originalPosition: this.originalPosition,
                        offset: this.positionAbs,
                    };
                },
            }),
                t.ui.plugin.add("draggable", "connectToSortable", {
                    start: function (e, i) {
                        var s = t(this).data("ui-draggable"),
                            n = s.options,
                            o = t.extend({}, i, { item: s.element });
                        (s.sortables = []),
                            t(n.connectToSortable).each(function () {
                                var i = t.data(this, "ui-sortable");
                                i &&
                                    !i.options.disabled &&
                                    (s.sortables.push({ instance: i, shouldRevert: i.options.revert }),
                                    i.refreshPositions(),
                                    i._trigger("activate", e, o));
                            });
                    },
                    stop: function (e, i) {
                        var s = t(this).data("ui-draggable"),
                            n = t.extend({}, i, { item: s.element });
                        t.each(s.sortables, function () {
                            this.instance.isOver
                                ? ((this.instance.isOver = 0),
                                  (s.cancelHelperRemoval = !0),
                                  (this.instance.cancelHelperRemoval = !1),
                                  this.shouldRevert && (this.instance.options.revert = this.shouldRevert),
                                  this.instance._mouseStop(e),
                                  (this.instance.options.helper = this.instance.options._helper),
                                  "original" === s.options.helper &&
                                      this.instance.currentItem.css({ top: "auto", left: "auto" }))
                                : ((this.instance.cancelHelperRemoval = !1),
                                  this.instance._trigger("deactivate", e, n));
                        });
                    },
                    drag: function (e, i) {
                        var s = t(this).data("ui-draggable"),
                            n = this;
                        t.each(s.sortables, function () {
                            var o = !1,
                                a = this;
                            (this.instance.positionAbs = s.positionAbs),
                                (this.instance.helperProportions = s.helperProportions),
                                (this.instance.offset.click = s.offset.click),
                                this.instance._intersectsWith(this.instance.containerCache) &&
                                    ((o = !0),
                                    t.each(s.sortables, function () {
                                        return (
                                            (this.instance.positionAbs = s.positionAbs),
                                            (this.instance.helperProportions = s.helperProportions),
                                            (this.instance.offset.click = s.offset.click),
                                            this !== a &&
                                                this.instance._intersectsWith(this.instance.containerCache) &&
                                                t.contains(a.instance.element[0], this.instance.element[0]) &&
                                                (o = !1),
                                            o
                                        );
                                    })),
                                o
                                    ? (this.instance.isOver ||
                                          ((this.instance.isOver = 1),
                                          (this.instance.currentItem = t(n)
                                              .clone()
                                              .removeAttr("id")
                                              .appendTo(this.instance.element)
                                              .data("ui-sortable-item", !0)),
                                          (this.instance.options._helper = this.instance.options.helper),
                                          (this.instance.options.helper = function () {
                                              return i.helper[0];
                                          }),
                                          (e.target = this.instance.currentItem[0]),
                                          this.instance._mouseCapture(e, !0),
                                          this.instance._mouseStart(e, !0, !0),
                                          (this.instance.offset.click.top = s.offset.click.top),
                                          (this.instance.offset.click.left = s.offset.click.left),
                                          (this.instance.offset.parent.left -=
                                              s.offset.parent.left - this.instance.offset.parent.left),
                                          (this.instance.offset.parent.top -=
                                              s.offset.parent.top - this.instance.offset.parent.top),
                                          s._trigger("toSortable", e),
                                          (s.dropped = this.instance.element),
                                          (s.currentItem = s.element),
                                          (this.instance.fromOutside = s)),
                                      this.instance.currentItem && this.instance._mouseDrag(e))
                                    : this.instance.isOver &&
                                      ((this.instance.isOver = 0),
                                      (this.instance.cancelHelperRemoval = !0),
                                      (this.instance.options.revert = !1),
                                      this.instance._trigger("out", e, this.instance._uiHash(this.instance)),
                                      this.instance._mouseStop(e, !0),
                                      (this.instance.options.helper = this.instance.options._helper),
                                      this.instance.currentItem.remove(),
                                      this.instance.placeholder && this.instance.placeholder.remove(),
                                      s._trigger("fromSortable", e),
                                      (s.dropped = !1));
                        });
                    },
                }),
                t.ui.plugin.add("draggable", "cursor", {
                    start: function () {
                        var e = t("body"),
                            i = t(this).data("ui-draggable").options;
                        e.css("cursor") && (i._cursor = e.css("cursor")), e.css("cursor", i.cursor);
                    },
                    stop: function () {
                        var e = t(this).data("ui-draggable").options;
                        e._cursor && t("body").css("cursor", e._cursor);
                    },
                }),
                t.ui.plugin.add("draggable", "opacity", {
                    start: function (e, i) {
                        var s = t(i.helper),
                            n = t(this).data("ui-draggable").options;
                        s.css("opacity") && (n._opacity = s.css("opacity")), s.css("opacity", n.opacity);
                    },
                    stop: function (e, i) {
                        var s = t(this).data("ui-draggable").options;
                        s._opacity && t(i.helper).css("opacity", s._opacity);
                    },
                }),
                t.ui.plugin.add("draggable", "scroll", {
                    start: function () {
                        var e = t(this).data("ui-draggable");
                        e.scrollParent[0] !== document &&
                            "HTML" !== e.scrollParent[0].tagName &&
                            (e.overflowOffset = e.scrollParent.offset());
                    },
                    drag: function (e) {
                        var i = t(this).data("ui-draggable"),
                            s = i.options,
                            n = !1;
                        i.scrollParent[0] !== document && "HTML" !== i.scrollParent[0].tagName
                            ? ((s.axis && "x" === s.axis) ||
                                  (i.overflowOffset.top + i.scrollParent[0].offsetHeight - e.pageY < s.scrollSensitivity
                                      ? (i.scrollParent[0].scrollTop = n = i.scrollParent[0].scrollTop + s.scrollSpeed)
                                      : e.pageY - i.overflowOffset.top < s.scrollSensitivity &&
                                        (i.scrollParent[0].scrollTop = n =
                                            i.scrollParent[0].scrollTop - s.scrollSpeed)),
                              (s.axis && "y" === s.axis) ||
                                  (i.overflowOffset.left + i.scrollParent[0].offsetWidth - e.pageX < s.scrollSensitivity
                                      ? (i.scrollParent[0].scrollLeft = n =
                                            i.scrollParent[0].scrollLeft + s.scrollSpeed)
                                      : e.pageX - i.overflowOffset.left < s.scrollSensitivity &&
                                        (i.scrollParent[0].scrollLeft = n =
                                            i.scrollParent[0].scrollLeft - s.scrollSpeed)))
                            : ((s.axis && "x" === s.axis) ||
                                  (e.pageY - t(document).scrollTop() < s.scrollSensitivity
                                      ? (n = t(document).scrollTop(t(document).scrollTop() - s.scrollSpeed))
                                      : t(window).height() - (e.pageY - t(document).scrollTop()) <
                                            s.scrollSensitivity &&
                                        (n = t(document).scrollTop(t(document).scrollTop() + s.scrollSpeed))),
                              (s.axis && "y" === s.axis) ||
                                  (e.pageX - t(document).scrollLeft() < s.scrollSensitivity
                                      ? (n = t(document).scrollLeft(t(document).scrollLeft() - s.scrollSpeed))
                                      : t(window).width() - (e.pageX - t(document).scrollLeft()) <
                                            s.scrollSensitivity &&
                                        (n = t(document).scrollLeft(t(document).scrollLeft() + s.scrollSpeed)))),
                            n !== !1 && t.ui.ddmanager && !s.dropBehaviour && t.ui.ddmanager.prepareOffsets(i, e);
                    },
                }),
                t.ui.plugin.add("draggable", "snap", {
                    start: function () {
                        var e = t(this).data("ui-draggable"),
                            i = e.options;
                        (e.snapElements = []),
                            t(i.snap.constructor !== String ? i.snap.items || ":data(ui-draggable)" : i.snap).each(
                                function () {
                                    var i = t(this),
                                        s = i.offset();
                                    this !== e.element[0] &&
                                        e.snapElements.push({
                                            item: this,
                                            width: i.outerWidth(),
                                            height: i.outerHeight(),
                                            top: s.top,
                                            left: s.left,
                                        });
                                }
                            );
                    },
                    drag: function (e, i) {
                        var s,
                            n,
                            o,
                            a,
                            r,
                            h,
                            l,
                            c,
                            u,
                            d,
                            p = t(this).data("ui-draggable"),
                            f = p.options,
                            g = f.snapTolerance,
                            m = i.offset.left,
                            v = m + p.helperProportions.width,
                            _ = i.offset.top,
                            b = _ + p.helperProportions.height;
                        for (u = p.snapElements.length - 1; u >= 0; u--)
                            (r = p.snapElements[u].left),
                                (h = r + p.snapElements[u].width),
                                (l = p.snapElements[u].top),
                                (c = l + p.snapElements[u].height),
                                (m > r - g && h + g > m && _ > l - g && c + g > _) ||
                                (m > r - g && h + g > m && b > l - g && c + g > b) ||
                                (v > r - g && h + g > v && _ > l - g && c + g > _) ||
                                (v > r - g && h + g > v && b > l - g && c + g > b)
                                    ? ("inner" !== f.snapMode &&
                                          ((s = g >= Math.abs(l - b)),
                                          (n = g >= Math.abs(c - _)),
                                          (o = g >= Math.abs(r - v)),
                                          (a = g >= Math.abs(h - m)),
                                          s &&
                                              (i.position.top =
                                                  p._convertPositionTo("relative", {
                                                      top: l - p.helperProportions.height,
                                                      left: 0,
                                                  }).top - p.margins.top),
                                          n &&
                                              (i.position.top =
                                                  p._convertPositionTo("relative", { top: c, left: 0 }).top -
                                                  p.margins.top),
                                          o &&
                                              (i.position.left =
                                                  p._convertPositionTo("relative", {
                                                      top: 0,
                                                      left: r - p.helperProportions.width,
                                                  }).left - p.margins.left),
                                          a &&
                                              (i.position.left =
                                                  p._convertPositionTo("relative", { top: 0, left: h }).left -
                                                  p.margins.left)),
                                      (d = s || n || o || a),
                                      "outer" !== f.snapMode &&
                                          ((s = g >= Math.abs(l - _)),
                                          (n = g >= Math.abs(c - b)),
                                          (o = g >= Math.abs(r - m)),
                                          (a = g >= Math.abs(h - v)),
                                          s &&
                                              (i.position.top =
                                                  p._convertPositionTo("relative", { top: l, left: 0 }).top -
                                                  p.margins.top),
                                          n &&
                                              (i.position.top =
                                                  p._convertPositionTo("relative", {
                                                      top: c - p.helperProportions.height,
                                                      left: 0,
                                                  }).top - p.margins.top),
                                          o &&
                                              (i.position.left =
                                                  p._convertPositionTo("relative", { top: 0, left: r }).left -
                                                  p.margins.left),
                                          a &&
                                              (i.position.left =
                                                  p._convertPositionTo("relative", {
                                                      top: 0,
                                                      left: h - p.helperProportions.width,
                                                  }).left - p.margins.left)),
                                      !p.snapElements[u].snapping &&
                                          (s || n || o || a || d) &&
                                          p.options.snap.snap &&
                                          p.options.snap.snap.call(
                                              p.element,
                                              e,
                                              t.extend(p._uiHash(), { snapItem: p.snapElements[u].item })
                                          ),
                                      (p.snapElements[u].snapping = s || n || o || a || d))
                                    : (p.snapElements[u].snapping &&
                                          p.options.snap.release &&
                                          p.options.snap.release.call(
                                              p.element,
                                              e,
                                              t.extend(p._uiHash(), { snapItem: p.snapElements[u].item })
                                          ),
                                      (p.snapElements[u].snapping = !1));
                    },
                }),
                t.ui.plugin.add("draggable", "stack", {
                    start: function () {
                        var e,
                            i = this.data("ui-draggable").options,
                            s = t.makeArray(t(i.stack)).sort(function (e, i) {
                                return (
                                    (parseInt(t(e).css("zIndex"), 10) || 0) - (parseInt(t(i).css("zIndex"), 10) || 0)
                                );
                            });
                        s.length &&
                            ((e = parseInt(t(s[0]).css("zIndex"), 10) || 0),
                            t(s).each(function (i) {
                                t(this).css("zIndex", e + i);
                            }),
                            this.css("zIndex", e + s.length));
                    },
                }),
                t.ui.plugin.add("draggable", "zIndex", {
                    start: function (e, i) {
                        var s = t(i.helper),
                            n = t(this).data("ui-draggable").options;
                        s.css("zIndex") && (n._zIndex = s.css("zIndex")), s.css("zIndex", n.zIndex);
                    },
                    stop: function (e, i) {
                        var s = t(this).data("ui-draggable").options;
                        s._zIndex && t(i.helper).css("zIndex", s._zIndex);
                    },
                });
        })(jQuery),
        (function (t) {
            function e(t, e, i) {
                return t > e && e + i > t;
            }
            t.widget("ui.droppable", {
                version: "1.10.2",
                widgetEventPrefix: "drop",
                options: {
                    accept: "*",
                    activeClass: !1,
                    addClasses: !0,
                    greedy: !1,
                    hoverClass: !1,
                    scope: "default",
                    tolerance: "intersect",
                    activate: null,
                    deactivate: null,
                    drop: null,
                    out: null,
                    over: null,
                },
                _create: function () {
                    var e = this.options,
                        i = e.accept;
                    (this.isover = !1),
                        (this.isout = !0),
                        (this.accept = t.isFunction(i)
                            ? i
                            : function (t) {
                                  return t.is(i);
                              }),
                        (this.proportions = {
                            width: this.element[0].offsetWidth,
                            height: this.element[0].offsetHeight,
                        }),
                        (t.ui.ddmanager.droppables[e.scope] = t.ui.ddmanager.droppables[e.scope] || []),
                        t.ui.ddmanager.droppables[e.scope].push(this),
                        e.addClasses && this.element.addClass("ui-droppable");
                },
                _destroy: function () {
                    for (var e = 0, i = t.ui.ddmanager.droppables[this.options.scope]; i.length > e; e++)
                        i[e] === this && i.splice(e, 1);
                    this.element.removeClass("ui-droppable ui-droppable-disabled");
                },
                _setOption: function (e, i) {
                    "accept" === e &&
                        (this.accept = t.isFunction(i)
                            ? i
                            : function (t) {
                                  return t.is(i);
                              }),
                        t.Widget.prototype._setOption.apply(this, arguments);
                },
                _activate: function (e) {
                    var i = t.ui.ddmanager.current;
                    this.options.activeClass && this.element.addClass(this.options.activeClass),
                        i && this._trigger("activate", e, this.ui(i));
                },
                _deactivate: function (e) {
                    var i = t.ui.ddmanager.current;
                    this.options.activeClass && this.element.removeClass(this.options.activeClass),
                        i && this._trigger("deactivate", e, this.ui(i));
                },
                _over: function (e) {
                    var i = t.ui.ddmanager.current;
                    i &&
                        (i.currentItem || i.element)[0] !== this.element[0] &&
                        this.accept.call(this.element[0], i.currentItem || i.element) &&
                        (this.options.hoverClass && this.element.addClass(this.options.hoverClass),
                        this._trigger("over", e, this.ui(i)));
                },
                _out: function (e) {
                    var i = t.ui.ddmanager.current;
                    i &&
                        (i.currentItem || i.element)[0] !== this.element[0] &&
                        this.accept.call(this.element[0], i.currentItem || i.element) &&
                        (this.options.hoverClass && this.element.removeClass(this.options.hoverClass),
                        this._trigger("out", e, this.ui(i)));
                },
                _drop: function (e, i) {
                    var s = i || t.ui.ddmanager.current,
                        n = !1;
                    return s && (s.currentItem || s.element)[0] !== this.element[0]
                        ? (this.element
                              .find(":data(ui-droppable)")
                              .not(".ui-draggable-dragging")
                              .each(function () {
                                  var e = t.data(this, "ui-droppable");
                                  return e.options.greedy &&
                                      !e.options.disabled &&
                                      e.options.scope === s.options.scope &&
                                      e.accept.call(e.element[0], s.currentItem || s.element) &&
                                      t.ui.intersect(
                                          s,
                                          t.extend(e, { offset: e.element.offset() }),
                                          e.options.tolerance
                                      )
                                      ? ((n = !0), !1)
                                      : undefined;
                              }),
                          n
                              ? !1
                              : this.accept.call(this.element[0], s.currentItem || s.element)
                                ? (this.options.activeClass && this.element.removeClass(this.options.activeClass),
                                  this.options.hoverClass && this.element.removeClass(this.options.hoverClass),
                                  this._trigger("drop", e, this.ui(s)),
                                  this.element)
                                : !1)
                        : !1;
                },
                ui: function (t) {
                    return {
                        draggable: t.currentItem || t.element,
                        helper: t.helper,
                        position: t.position,
                        offset: t.positionAbs,
                    };
                },
            }),
                (t.ui.intersect = function (t, i, s) {
                    if (!i.offset) return !1;
                    var n,
                        o,
                        a = (t.positionAbs || t.position.absolute).left,
                        r = a + t.helperProportions.width,
                        h = (t.positionAbs || t.position.absolute).top,
                        l = h + t.helperProportions.height,
                        c = i.offset.left,
                        u = c + i.proportions.width,
                        d = i.offset.top,
                        p = d + i.proportions.height;
                    switch (s) {
                        case "fit":
                            return a >= c && u >= r && h >= d && p >= l;
                        case "intersect":
                            return (
                                a + t.helperProportions.width / 2 > c &&
                                u > r - t.helperProportions.width / 2 &&
                                h + t.helperProportions.height / 2 > d &&
                                p > l - t.helperProportions.height / 2
                            );
                        case "pointer":
                            return (
                                (n =
                                    (t.positionAbs || t.position.absolute).left +
                                    (t.clickOffset || t.offset.click).left),
                                (o =
                                    (t.positionAbs || t.position.absolute).top + (t.clickOffset || t.offset.click).top),
                                e(o, d, i.proportions.height) && e(n, c, i.proportions.width)
                            );
                        case "touch":
                            return (
                                ((h >= d && p >= h) || (l >= d && p >= l) || (d > h && l > p)) &&
                                ((a >= c && u >= a) || (r >= c && u >= r) || (c > a && r > u))
                            );
                        default:
                            return !1;
                    }
                }),
                (t.ui.ddmanager = {
                    current: null,
                    droppables: { default: [] },
                    prepareOffsets: function (e, i) {
                        var s,
                            n,
                            o = t.ui.ddmanager.droppables[e.options.scope] || [],
                            a = i ? i.type : null,
                            r = (e.currentItem || e.element).find(":data(ui-droppable)").addBack();
                        t: for (s = 0; o.length > s; s++)
                            if (
                                !(
                                    o[s].options.disabled ||
                                    (e && !o[s].accept.call(o[s].element[0], e.currentItem || e.element))
                                )
                            ) {
                                for (n = 0; r.length > n; n++)
                                    if (r[n] === o[s].element[0]) {
                                        o[s].proportions.height = 0;
                                        continue t;
                                    }
                                (o[s].visible = "none" !== o[s].element.css("display")),
                                    o[s].visible &&
                                        ("mousedown" === a && o[s]._activate.call(o[s], i),
                                        (o[s].offset = o[s].element.offset()),
                                        (o[s].proportions = {
                                            width: o[s].element[0].offsetWidth,
                                            height: o[s].element[0].offsetHeight,
                                        }));
                            }
                    },
                    drop: function (e, i) {
                        var s = !1;
                        return (
                            t.each((t.ui.ddmanager.droppables[e.options.scope] || []).slice(), function () {
                                this.options &&
                                    (!this.options.disabled &&
                                        this.visible &&
                                        t.ui.intersect(e, this, this.options.tolerance) &&
                                        (s = this._drop.call(this, i) || s),
                                    !this.options.disabled &&
                                        this.visible &&
                                        this.accept.call(this.element[0], e.currentItem || e.element) &&
                                        ((this.isout = !0), (this.isover = !1), this._deactivate.call(this, i)));
                            }),
                            s
                        );
                    },
                    dragStart: function (e, i) {
                        e.element.parentsUntil("body").bind("scroll.droppable", function () {
                            e.options.refreshPositions || t.ui.ddmanager.prepareOffsets(e, i);
                        });
                    },
                    drag: function (e, i) {
                        e.options.refreshPositions && t.ui.ddmanager.prepareOffsets(e, i),
                            t.each(t.ui.ddmanager.droppables[e.options.scope] || [], function () {
                                if (!this.options.disabled && !this.greedyChild && this.visible) {
                                    var s,
                                        n,
                                        o,
                                        a = t.ui.intersect(e, this, this.options.tolerance),
                                        r = !a && this.isover ? "isout" : a && !this.isover ? "isover" : null;
                                    r &&
                                        (this.options.greedy &&
                                            ((n = this.options.scope),
                                            (o = this.element.parents(":data(ui-droppable)").filter(function () {
                                                return t.data(this, "ui-droppable").options.scope === n;
                                            })),
                                            o.length &&
                                                ((s = t.data(o[0], "ui-droppable")), (s.greedyChild = "isover" === r))),
                                        s && "isover" === r && ((s.isover = !1), (s.isout = !0), s._out.call(s, i)),
                                        (this[r] = !0),
                                        (this["isout" === r ? "isover" : "isout"] = !1),
                                        this["isover" === r ? "_over" : "_out"].call(this, i),
                                        s && "isout" === r && ((s.isout = !1), (s.isover = !0), s._over.call(s, i)));
                                }
                            });
                    },
                    dragStop: function (e, i) {
                        e.element.parentsUntil("body").unbind("scroll.droppable"),
                            e.options.refreshPositions || t.ui.ddmanager.prepareOffsets(e, i);
                    },
                });
        })(jQuery),
        (function (t) {
            function e(t) {
                return parseInt(t, 10) || 0;
            }
            function i(t) {
                return !isNaN(parseInt(t, 10));
            }
            t.widget("ui.resizable", t.ui.mouse, {
                version: "1.10.2",
                widgetEventPrefix: "resize",
                options: {
                    alsoResize: !1,
                    animate: !1,
                    animateDuration: "slow",
                    animateEasing: "swing",
                    aspectRatio: !1,
                    autoHide: !1,
                    containment: !1,
                    ghost: !1,
                    grid: !1,
                    handles: "e,s,se",
                    helper: !1,
                    maxHeight: null,
                    maxWidth: null,
                    minHeight: 10,
                    minWidth: 10,
                    zIndex: 90,
                    resize: null,
                    start: null,
                    stop: null,
                },
                _create: function () {
                    var e,
                        i,
                        s,
                        n,
                        o,
                        a = this,
                        r = this.options;
                    if (
                        (this.element.addClass("ui-resizable"),
                        t.extend(this, {
                            _aspectRatio: !!r.aspectRatio,
                            aspectRatio: r.aspectRatio,
                            originalElement: this.element,
                            _proportionallyResizeElements: [],
                            _helper: r.helper || r.ghost || r.animate ? r.helper || "ui-resizable-helper" : null,
                        }),
                        this.element[0].nodeName.match(/canvas|textarea|input|select|button|img/i) &&
                            (this.element.wrap(
                                t("<div class='ui-wrapper' style='overflow: hidden;'></div>").css({
                                    position: this.element.css("position"),
                                    width: this.element.outerWidth(),
                                    height: this.element.outerHeight(),
                                    top: this.element.css("top"),
                                    left: this.element.css("left"),
                                })
                            ),
                            (this.element = this.element
                                .parent()
                                .data("ui-resizable", this.element.data("ui-resizable"))),
                            (this.elementIsWrapper = !0),
                            this.element.css({
                                marginLeft: this.originalElement.css("marginLeft"),
                                marginTop: this.originalElement.css("marginTop"),
                                marginRight: this.originalElement.css("marginRight"),
                                marginBottom: this.originalElement.css("marginBottom"),
                            }),
                            this.originalElement.css({ marginLeft: 0, marginTop: 0, marginRight: 0, marginBottom: 0 }),
                            (this.originalResizeStyle = this.originalElement.css("resize")),
                            this.originalElement.css("resize", "none"),
                            this._proportionallyResizeElements.push(
                                this.originalElement.css({ position: "static", zoom: 1, display: "block" })
                            ),
                            this.originalElement.css({ margin: this.originalElement.css("margin") }),
                            this._proportionallyResize()),
                        (this.handles =
                            r.handles ||
                            (t(".ui-resizable-handle", this.element).length
                                ? {
                                      n: ".ui-resizable-n",
                                      e: ".ui-resizable-e",
                                      s: ".ui-resizable-s",
                                      w: ".ui-resizable-w",
                                      se: ".ui-resizable-se",
                                      sw: ".ui-resizable-sw",
                                      ne: ".ui-resizable-ne",
                                      nw: ".ui-resizable-nw",
                                  }
                                : "e,s,se")),
                        this.handles.constructor === String)
                    )
                        for (
                            "all" === this.handles && (this.handles = "n,e,s,w,se,sw,ne,nw"),
                                e = this.handles.split(","),
                                this.handles = {},
                                i = 0;
                            e.length > i;
                            i++
                        )
                            (s = t.trim(e[i])),
                                (o = "ui-resizable-" + s),
                                (n = t("<div class='ui-resizable-handle " + o + "'></div>")),
                                n.css({ zIndex: r.zIndex }),
                                "se" === s && n.addClass("ui-icon ui-icon-gripsmall-diagonal-se"),
                                (this.handles[s] = ".ui-resizable-" + s),
                                this.element.append(n);
                    (this._renderAxis = function (e) {
                        var i, s, n, o;
                        e = e || this.element;
                        for (i in this.handles)
                            this.handles[i].constructor === String &&
                                (this.handles[i] = t(this.handles[i], this.element).show()),
                                this.elementIsWrapper &&
                                    this.originalElement[0].nodeName.match(/textarea|input|select|button/i) &&
                                    ((s = t(this.handles[i], this.element)),
                                    (o = /sw|ne|nw|se|n|s/.test(i) ? s.outerHeight() : s.outerWidth()),
                                    (n = [
                                        "padding",
                                        /ne|nw|n/.test(i)
                                            ? "Top"
                                            : /se|sw|s/.test(i)
                                              ? "Bottom"
                                              : /^e$/.test(i)
                                                ? "Right"
                                                : "Left",
                                    ].join("")),
                                    e.css(n, o),
                                    this._proportionallyResize()),
                                t(this.handles[i]).length;
                    }),
                        this._renderAxis(this.element),
                        (this._handles = t(".ui-resizable-handle", this.element).disableSelection()),
                        this._handles.mouseover(function () {
                            a.resizing ||
                                (this.className && (n = this.className.match(/ui-resizable-(se|sw|ne|nw|n|e|s|w)/i)),
                                (a.axis = n && n[1] ? n[1] : "se"));
                        }),
                        r.autoHide &&
                            (this._handles.hide(),
                            t(this.element)
                                .addClass("ui-resizable-autohide")
                                .mouseenter(function () {
                                    r.disabled || (t(this).removeClass("ui-resizable-autohide"), a._handles.show());
                                })
                                .mouseleave(function () {
                                    r.disabled ||
                                        a.resizing ||
                                        (t(this).addClass("ui-resizable-autohide"), a._handles.hide());
                                })),
                        this._mouseInit();
                },
                _destroy: function () {
                    this._mouseDestroy();
                    var e,
                        i = function (e) {
                            t(e)
                                .removeClass("ui-resizable ui-resizable-disabled ui-resizable-resizing")
                                .removeData("resizable")
                                .removeData("ui-resizable")
                                .unbind(".resizable")
                                .find(".ui-resizable-handle")
                                .remove();
                        };
                    return (
                        this.elementIsWrapper &&
                            (i(this.element),
                            (e = this.element),
                            this.originalElement
                                .css({
                                    position: e.css("position"),
                                    width: e.outerWidth(),
                                    height: e.outerHeight(),
                                    top: e.css("top"),
                                    left: e.css("left"),
                                })
                                .insertAfter(e),
                            e.remove()),
                        this.originalElement.css("resize", this.originalResizeStyle),
                        i(this.originalElement),
                        this
                    );
                },
                _mouseCapture: function (e) {
                    var i,
                        s,
                        n = !1;
                    for (i in this.handles)
                        (s = t(this.handles[i])[0]), (s === e.target || t.contains(s, e.target)) && (n = !0);
                    return !this.options.disabled && n;
                },
                _mouseStart: function (i) {
                    var s,
                        n,
                        o,
                        a = this.options,
                        r = this.element.position(),
                        h = this.element;
                    return (
                        (this.resizing = !0),
                        /absolute/.test(h.css("position"))
                            ? h.css({ position: "absolute", top: h.css("top"), left: h.css("left") })
                            : h.is(".ui-draggable") && h.css({ position: "absolute", top: r.top, left: r.left }),
                        this._renderProxy(),
                        (s = e(this.helper.css("left"))),
                        (n = e(this.helper.css("top"))),
                        a.containment &&
                            ((s += t(a.containment).scrollLeft() || 0), (n += t(a.containment).scrollTop() || 0)),
                        (this.offset = this.helper.offset()),
                        (this.position = { left: s, top: n }),
                        (this.size = this._helper
                            ? { width: h.outerWidth(), height: h.outerHeight() }
                            : { width: h.width(), height: h.height() }),
                        (this.originalSize = this._helper
                            ? { width: h.outerWidth(), height: h.outerHeight() }
                            : { width: h.width(), height: h.height() }),
                        (this.originalPosition = { left: s, top: n }),
                        (this.sizeDiff = { width: h.outerWidth() - h.width(), height: h.outerHeight() - h.height() }),
                        (this.originalMousePosition = { left: i.pageX, top: i.pageY }),
                        (this.aspectRatio =
                            "number" == typeof a.aspectRatio
                                ? a.aspectRatio
                                : this.originalSize.width / this.originalSize.height || 1),
                        (o = t(".ui-resizable-" + this.axis).css("cursor")),
                        t("body").css("cursor", "auto" === o ? this.axis + "-resize" : o),
                        h.addClass("ui-resizable-resizing"),
                        this._propagate("start", i),
                        !0
                    );
                },
                _mouseDrag: function (e) {
                    var i,
                        s = this.helper,
                        n = {},
                        o = this.originalMousePosition,
                        a = this.axis,
                        r = this.position.top,
                        h = this.position.left,
                        l = this.size.width,
                        c = this.size.height,
                        u = e.pageX - o.left || 0,
                        d = e.pageY - o.top || 0,
                        p = this._change[a];
                    return p
                        ? ((i = p.apply(this, [e, u, d])),
                          this._updateVirtualBoundaries(e.shiftKey),
                          (this._aspectRatio || e.shiftKey) && (i = this._updateRatio(i, e)),
                          (i = this._respectSize(i, e)),
                          this._updateCache(i),
                          this._propagate("resize", e),
                          this.position.top !== r && (n.top = this.position.top + "px"),
                          this.position.left !== h && (n.left = this.position.left + "px"),
                          this.size.width !== l && (n.width = this.size.width + "px"),
                          this.size.height !== c && (n.height = this.size.height + "px"),
                          s.css(n),
                          !this._helper && this._proportionallyResizeElements.length && this._proportionallyResize(),
                          t.isEmptyObject(n) || this._trigger("resize", e, this.ui()),
                          !1)
                        : !1;
                },
                _mouseStop: function (e) {
                    this.resizing = !1;
                    var i,
                        s,
                        n,
                        o,
                        a,
                        r,
                        h,
                        l = this.options,
                        c = this;
                    return (
                        this._helper &&
                            ((i = this._proportionallyResizeElements),
                            (s = i.length && /textarea/i.test(i[0].nodeName)),
                            (n = s && t.ui.hasScroll(i[0], "left") ? 0 : c.sizeDiff.height),
                            (o = s ? 0 : c.sizeDiff.width),
                            (a = { width: c.helper.width() - o, height: c.helper.height() - n }),
                            (r =
                                parseInt(c.element.css("left"), 10) + (c.position.left - c.originalPosition.left) ||
                                null),
                            (h =
                                parseInt(c.element.css("top"), 10) + (c.position.top - c.originalPosition.top) || null),
                            l.animate || this.element.css(t.extend(a, { top: h, left: r })),
                            c.helper.height(c.size.height),
                            c.helper.width(c.size.width),
                            this._helper && !l.animate && this._proportionallyResize()),
                        t("body").css("cursor", "auto"),
                        this.element.removeClass("ui-resizable-resizing"),
                        this._propagate("stop", e),
                        this._helper && this.helper.remove(),
                        !1
                    );
                },
                _updateVirtualBoundaries: function (t) {
                    var e,
                        s,
                        n,
                        o,
                        a,
                        r = this.options;
                    (a = {
                        minWidth: i(r.minWidth) ? r.minWidth : 0,
                        maxWidth: i(r.maxWidth) ? r.maxWidth : 1 / 0,
                        minHeight: i(r.minHeight) ? r.minHeight : 0,
                        maxHeight: i(r.maxHeight) ? r.maxHeight : 1 / 0,
                    }),
                        (this._aspectRatio || t) &&
                            ((e = a.minHeight * this.aspectRatio),
                            (n = a.minWidth / this.aspectRatio),
                            (s = a.maxHeight * this.aspectRatio),
                            (o = a.maxWidth / this.aspectRatio),
                            e > a.minWidth && (a.minWidth = e),
                            n > a.minHeight && (a.minHeight = n),
                            a.maxWidth > s && (a.maxWidth = s),
                            a.maxHeight > o && (a.maxHeight = o)),
                        (this._vBoundaries = a);
                },
                _updateCache: function (t) {
                    (this.offset = this.helper.offset()),
                        i(t.left) && (this.position.left = t.left),
                        i(t.top) && (this.position.top = t.top),
                        i(t.height) && (this.size.height = t.height),
                        i(t.width) && (this.size.width = t.width);
                },
                _updateRatio: function (t) {
                    var e = this.position,
                        s = this.size,
                        n = this.axis;
                    return (
                        i(t.height)
                            ? (t.width = t.height * this.aspectRatio)
                            : i(t.width) && (t.height = t.width / this.aspectRatio),
                        "sw" === n && ((t.left = e.left + (s.width - t.width)), (t.top = null)),
                        "nw" === n &&
                            ((t.top = e.top + (s.height - t.height)), (t.left = e.left + (s.width - t.width))),
                        t
                    );
                },
                _respectSize: function (t) {
                    var e = this._vBoundaries,
                        s = this.axis,
                        n = i(t.width) && e.maxWidth && e.maxWidth < t.width,
                        o = i(t.height) && e.maxHeight && e.maxHeight < t.height,
                        a = i(t.width) && e.minWidth && e.minWidth > t.width,
                        r = i(t.height) && e.minHeight && e.minHeight > t.height,
                        h = this.originalPosition.left + this.originalSize.width,
                        l = this.position.top + this.size.height,
                        c = /sw|nw|w/.test(s),
                        u = /nw|ne|n/.test(s);
                    return (
                        a && (t.width = e.minWidth),
                        r && (t.height = e.minHeight),
                        n && (t.width = e.maxWidth),
                        o && (t.height = e.maxHeight),
                        a && c && (t.left = h - e.minWidth),
                        n && c && (t.left = h - e.maxWidth),
                        r && u && (t.top = l - e.minHeight),
                        o && u && (t.top = l - e.maxHeight),
                        t.width || t.height || t.left || !t.top
                            ? t.width || t.height || t.top || !t.left || (t.left = null)
                            : (t.top = null),
                        t
                    );
                },
                _proportionallyResize: function () {
                    if (this._proportionallyResizeElements.length) {
                        var t,
                            e,
                            i,
                            s,
                            n,
                            o = this.helper || this.element;
                        for (t = 0; this._proportionallyResizeElements.length > t; t++) {
                            if (((n = this._proportionallyResizeElements[t]), !this.borderDif))
                                for (
                                    this.borderDif = [],
                                        i = [
                                            n.css("borderTopWidth"),
                                            n.css("borderRightWidth"),
                                            n.css("borderBottomWidth"),
                                            n.css("borderLeftWidth"),
                                        ],
                                        s = [
                                            n.css("paddingTop"),
                                            n.css("paddingRight"),
                                            n.css("paddingBottom"),
                                            n.css("paddingLeft"),
                                        ],
                                        e = 0;
                                    i.length > e;
                                    e++
                                )
                                    this.borderDif[e] = (parseInt(i[e], 10) || 0) + (parseInt(s[e], 10) || 0);
                            n.css({
                                height: o.height() - this.borderDif[0] - this.borderDif[2] || 0,
                                width: o.width() - this.borderDif[1] - this.borderDif[3] || 0,
                            });
                        }
                    }
                },
                _renderProxy: function () {
                    var e = this.element,
                        i = this.options;
                    (this.elementOffset = e.offset()),
                        this._helper
                            ? ((this.helper = this.helper || t("<div style='overflow:hidden;'></div>")),
                              this.helper
                                  .addClass(this._helper)
                                  .css({
                                      width: this.element.outerWidth() - 1,
                                      height: this.element.outerHeight() - 1,
                                      position: "absolute",
                                      left: this.elementOffset.left + "px",
                                      top: this.elementOffset.top + "px",
                                      zIndex: ++i.zIndex,
                                  }),
                              this.helper.appendTo("body").disableSelection())
                            : (this.helper = this.element);
                },
                _change: {
                    e: function (t, e) {
                        return { width: this.originalSize.width + e };
                    },
                    w: function (t, e) {
                        var i = this.originalSize,
                            s = this.originalPosition;
                        return { left: s.left + e, width: i.width - e };
                    },
                    n: function (t, e, i) {
                        var s = this.originalSize,
                            n = this.originalPosition;
                        return { top: n.top + i, height: s.height - i };
                    },
                    s: function (t, e, i) {
                        return { height: this.originalSize.height + i };
                    },
                    se: function (e, i, s) {
                        return t.extend(this._change.s.apply(this, arguments), this._change.e.apply(this, [e, i, s]));
                    },
                    sw: function (e, i, s) {
                        return t.extend(this._change.s.apply(this, arguments), this._change.w.apply(this, [e, i, s]));
                    },
                    ne: function (e, i, s) {
                        return t.extend(this._change.n.apply(this, arguments), this._change.e.apply(this, [e, i, s]));
                    },
                    nw: function (e, i, s) {
                        return t.extend(this._change.n.apply(this, arguments), this._change.w.apply(this, [e, i, s]));
                    },
                },
                _propagate: function (e, i) {
                    t.ui.plugin.call(this, e, [i, this.ui()]), "resize" !== e && this._trigger(e, i, this.ui());
                },
                plugins: {},
                ui: function () {
                    return {
                        originalElement: this.originalElement,
                        element: this.element,
                        helper: this.helper,
                        position: this.position,
                        size: this.size,
                        originalSize: this.originalSize,
                        originalPosition: this.originalPosition,
                    };
                },
            }),
                t.ui.plugin.add("resizable", "animate", {
                    stop: function (e) {
                        var i = t(this).data("ui-resizable"),
                            s = i.options,
                            n = i._proportionallyResizeElements,
                            o = n.length && /textarea/i.test(n[0].nodeName),
                            a = o && t.ui.hasScroll(n[0], "left") ? 0 : i.sizeDiff.height,
                            r = o ? 0 : i.sizeDiff.width,
                            h = { width: i.size.width - r, height: i.size.height - a },
                            l =
                                parseInt(i.element.css("left"), 10) + (i.position.left - i.originalPosition.left) ||
                                null,
                            c = parseInt(i.element.css("top"), 10) + (i.position.top - i.originalPosition.top) || null;
                        i.element.animate(t.extend(h, c && l ? { top: c, left: l } : {}), {
                            duration: s.animateDuration,
                            easing: s.animateEasing,
                            step: function () {
                                var s = {
                                    width: parseInt(i.element.css("width"), 10),
                                    height: parseInt(i.element.css("height"), 10),
                                    top: parseInt(i.element.css("top"), 10),
                                    left: parseInt(i.element.css("left"), 10),
                                };
                                n && n.length && t(n[0]).css({ width: s.width, height: s.height }),
                                    i._updateCache(s),
                                    i._propagate("resize", e);
                            },
                        });
                    },
                }),
                t.ui.plugin.add("resizable", "containment", {
                    start: function () {
                        var i,
                            s,
                            n,
                            o,
                            a,
                            r,
                            h,
                            l = t(this).data("ui-resizable"),
                            c = l.options,
                            u = l.element,
                            d = c.containment,
                            p = d instanceof t ? d.get(0) : /parent/.test(d) ? u.parent().get(0) : d;
                        p &&
                            ((l.containerElement = t(p)),
                            /document/.test(d) || d === document
                                ? ((l.containerOffset = { left: 0, top: 0 }),
                                  (l.containerPosition = { left: 0, top: 0 }),
                                  (l.parentData = {
                                      element: t(document),
                                      left: 0,
                                      top: 0,
                                      width: t(document).width(),
                                      height: t(document).height() || document.body.parentNode.scrollHeight,
                                  }))
                                : ((i = t(p)),
                                  (s = []),
                                  t(["Top", "Right", "Left", "Bottom"]).each(function (t, n) {
                                      s[t] = e(i.css("padding" + n));
                                  }),
                                  (l.containerOffset = i.offset()),
                                  (l.containerPosition = i.position()),
                                  (l.containerSize = { height: i.innerHeight() - s[3], width: i.innerWidth() - s[1] }),
                                  (n = l.containerOffset),
                                  (o = l.containerSize.height),
                                  (a = l.containerSize.width),
                                  (r = t.ui.hasScroll(p, "left") ? p.scrollWidth : a),
                                  (h = t.ui.hasScroll(p) ? p.scrollHeight : o),
                                  (l.parentData = { element: p, left: n.left, top: n.top, width: r, height: h })));
                    },
                    resize: function (e) {
                        var i,
                            s,
                            n,
                            o,
                            a = t(this).data("ui-resizable"),
                            r = a.options,
                            h = a.containerOffset,
                            l = a.position,
                            c = a._aspectRatio || e.shiftKey,
                            u = { top: 0, left: 0 },
                            d = a.containerElement;
                        d[0] !== document && /static/.test(d.css("position")) && (u = h),
                            l.left < (a._helper ? h.left : 0) &&
                                ((a.size.width =
                                    a.size.width + (a._helper ? a.position.left - h.left : a.position.left - u.left)),
                                c && (a.size.height = a.size.width / a.aspectRatio),
                                (a.position.left = r.helper ? h.left : 0)),
                            l.top < (a._helper ? h.top : 0) &&
                                ((a.size.height =
                                    a.size.height + (a._helper ? a.position.top - h.top : a.position.top)),
                                c && (a.size.width = a.size.height * a.aspectRatio),
                                (a.position.top = a._helper ? h.top : 0)),
                            (a.offset.left = a.parentData.left + a.position.left),
                            (a.offset.top = a.parentData.top + a.position.top),
                            (i = Math.abs(
                                (a._helper ? a.offset.left - u.left : a.offset.left - u.left) + a.sizeDiff.width
                            )),
                            (s = Math.abs(
                                (a._helper ? a.offset.top - u.top : a.offset.top - h.top) + a.sizeDiff.height
                            )),
                            (n = a.containerElement.get(0) === a.element.parent().get(0)),
                            (o = /relative|absolute/.test(a.containerElement.css("position"))),
                            n && o && (i -= a.parentData.left),
                            i + a.size.width >= a.parentData.width &&
                                ((a.size.width = a.parentData.width - i),
                                c && (a.size.height = a.size.width / a.aspectRatio)),
                            s + a.size.height >= a.parentData.height &&
                                ((a.size.height = a.parentData.height - s),
                                c && (a.size.width = a.size.height * a.aspectRatio));
                    },
                    stop: function () {
                        var e = t(this).data("ui-resizable"),
                            i = e.options,
                            s = e.containerOffset,
                            n = e.containerPosition,
                            o = e.containerElement,
                            a = t(e.helper),
                            r = a.offset(),
                            h = a.outerWidth() - e.sizeDiff.width,
                            l = a.outerHeight() - e.sizeDiff.height;
                        e._helper &&
                            !i.animate &&
                            /relative/.test(o.css("position")) &&
                            t(this).css({ left: r.left - n.left - s.left, width: h, height: l }),
                            e._helper &&
                                !i.animate &&
                                /static/.test(o.css("position")) &&
                                t(this).css({ left: r.left - n.left - s.left, width: h, height: l });
                    },
                }),
                t.ui.plugin.add("resizable", "alsoResize", {
                    start: function () {
                        var e = t(this).data("ui-resizable"),
                            i = e.options,
                            s = function (e) {
                                t(e).each(function () {
                                    var e = t(this);
                                    e.data("ui-resizable-alsoresize", {
                                        width: parseInt(e.width(), 10),
                                        height: parseInt(e.height(), 10),
                                        left: parseInt(e.css("left"), 10),
                                        top: parseInt(e.css("top"), 10),
                                    });
                                });
                            };
                        "object" != typeof i.alsoResize || i.alsoResize.parentNode
                            ? s(i.alsoResize)
                            : i.alsoResize.length
                              ? ((i.alsoResize = i.alsoResize[0]), s(i.alsoResize))
                              : t.each(i.alsoResize, function (t) {
                                    s(t);
                                });
                    },
                    resize: function (e, i) {
                        var s = t(this).data("ui-resizable"),
                            n = s.options,
                            o = s.originalSize,
                            a = s.originalPosition,
                            r = {
                                height: s.size.height - o.height || 0,
                                width: s.size.width - o.width || 0,
                                top: s.position.top - a.top || 0,
                                left: s.position.left - a.left || 0,
                            },
                            h = function (e, s) {
                                t(e).each(function () {
                                    var e = t(this),
                                        n = t(this).data("ui-resizable-alsoresize"),
                                        o = {},
                                        a =
                                            s && s.length
                                                ? s
                                                : e.parents(i.originalElement[0]).length
                                                  ? ["width", "height"]
                                                  : ["width", "height", "top", "left"];
                                    t.each(a, function (t, e) {
                                        var i = (n[e] || 0) + (r[e] || 0);
                                        i && i >= 0 && (o[e] = i || null);
                                    }),
                                        e.css(o);
                                });
                            };
                        "object" != typeof n.alsoResize || n.alsoResize.nodeType
                            ? h(n.alsoResize)
                            : t.each(n.alsoResize, function (t, e) {
                                  h(t, e);
                              });
                    },
                    stop: function () {
                        t(this).removeData("resizable-alsoresize");
                    },
                }),
                t.ui.plugin.add("resizable", "ghost", {
                    start: function () {
                        var e = t(this).data("ui-resizable"),
                            i = e.options,
                            s = e.size;
                        (e.ghost = e.originalElement.clone()),
                            e.ghost
                                .css({
                                    opacity: 0.25,
                                    display: "block",
                                    position: "relative",
                                    height: s.height,
                                    width: s.width,
                                    margin: 0,
                                    left: 0,
                                    top: 0,
                                })
                                .addClass("ui-resizable-ghost")
                                .addClass("string" == typeof i.ghost ? i.ghost : ""),
                            e.ghost.appendTo(e.helper);
                    },
                    resize: function () {
                        var e = t(this).data("ui-resizable");
                        e.ghost && e.ghost.css({ position: "relative", height: e.size.height, width: e.size.width });
                    },
                    stop: function () {
                        var e = t(this).data("ui-resizable");
                        e.ghost && e.helper && e.helper.get(0).removeChild(e.ghost.get(0));
                    },
                }),
                t.ui.plugin.add("resizable", "grid", {
                    resize: function () {
                        var e = t(this).data("ui-resizable"),
                            i = e.options,
                            s = e.size,
                            n = e.originalSize,
                            o = e.originalPosition,
                            a = e.axis,
                            r = "number" == typeof i.grid ? [i.grid, i.grid] : i.grid,
                            h = r[0] || 1,
                            l = r[1] || 1,
                            c = Math.round((s.width - n.width) / h) * h,
                            u = Math.round((s.height - n.height) / l) * l,
                            d = n.width + c,
                            p = n.height + u,
                            f = i.maxWidth && d > i.maxWidth,
                            g = i.maxHeight && p > i.maxHeight,
                            m = i.minWidth && i.minWidth > d,
                            v = i.minHeight && i.minHeight > p;
                        (i.grid = r),
                            m && (d += h),
                            v && (p += l),
                            f && (d -= h),
                            g && (p -= l),
                            /^(se|s|e)$/.test(a)
                                ? ((e.size.width = d), (e.size.height = p))
                                : /^(ne)$/.test(a)
                                  ? ((e.size.width = d), (e.size.height = p), (e.position.top = o.top - u))
                                  : /^(sw)$/.test(a)
                                    ? ((e.size.width = d), (e.size.height = p), (e.position.left = o.left - c))
                                    : ((e.size.width = d),
                                      (e.size.height = p),
                                      (e.position.top = o.top - u),
                                      (e.position.left = o.left - c));
                    },
                });
        })(jQuery),
        (function (t) {
            t.widget("ui.selectable", t.ui.mouse, {
                version: "1.10.2",
                options: {
                    appendTo: "body",
                    autoRefresh: !0,
                    distance: 0,
                    filter: "*",
                    tolerance: "touch",
                    selected: null,
                    selecting: null,
                    start: null,
                    stop: null,
                    unselected: null,
                    unselecting: null,
                },
                _create: function () {
                    var e,
                        i = this;
                    this.element.addClass("ui-selectable"),
                        (this.dragged = !1),
                        (this.refresh = function () {
                            (e = t(i.options.filter, i.element[0])),
                                e.addClass("ui-selectee"),
                                e.each(function () {
                                    var e = t(this),
                                        i = e.offset();
                                    t.data(this, "selectable-item", {
                                        element: this,
                                        $element: e,
                                        left: i.left,
                                        top: i.top,
                                        right: i.left + e.outerWidth(),
                                        bottom: i.top + e.outerHeight(),
                                        startselected: !1,
                                        selected: e.hasClass("ui-selected"),
                                        selecting: e.hasClass("ui-selecting"),
                                        unselecting: e.hasClass("ui-unselecting"),
                                    });
                                });
                        }),
                        this.refresh(),
                        (this.selectees = e.addClass("ui-selectee")),
                        this._mouseInit(),
                        (this.helper = t("<div class='ui-selectable-helper'></div>"));
                },
                _destroy: function () {
                    this.selectees.removeClass("ui-selectee").removeData("selectable-item"),
                        this.element.removeClass("ui-selectable ui-selectable-disabled"),
                        this._mouseDestroy();
                },
                _mouseStart: function (e) {
                    var i = this,
                        s = this.options;
                    (this.opos = [e.pageX, e.pageY]),
                        this.options.disabled ||
                            ((this.selectees = t(s.filter, this.element[0])),
                            this._trigger("start", e),
                            t(s.appendTo).append(this.helper),
                            this.helper.css({ left: e.pageX, top: e.pageY, width: 0, height: 0 }),
                            s.autoRefresh && this.refresh(),
                            this.selectees.filter(".ui-selected").each(function () {
                                var s = t.data(this, "selectable-item");
                                (s.startselected = !0),
                                    e.metaKey ||
                                        e.ctrlKey ||
                                        (s.$element.removeClass("ui-selected"),
                                        (s.selected = !1),
                                        s.$element.addClass("ui-unselecting"),
                                        (s.unselecting = !0),
                                        i._trigger("unselecting", e, { unselecting: s.element }));
                            }),
                            t(e.target)
                                .parents()
                                .addBack()
                                .each(function () {
                                    var s,
                                        n = t.data(this, "selectable-item");
                                    return n
                                        ? ((s = (!e.metaKey && !e.ctrlKey) || !n.$element.hasClass("ui-selected")),
                                          n.$element
                                              .removeClass(s ? "ui-unselecting" : "ui-selected")
                                              .addClass(s ? "ui-selecting" : "ui-unselecting"),
                                          (n.unselecting = !s),
                                          (n.selecting = s),
                                          (n.selected = s),
                                          s
                                              ? i._trigger("selecting", e, { selecting: n.element })
                                              : i._trigger("unselecting", e, { unselecting: n.element }),
                                          !1)
                                        : undefined;
                                }));
                },
                _mouseDrag: function (e) {
                    if (((this.dragged = !0), !this.options.disabled)) {
                        var i,
                            s = this,
                            n = this.options,
                            o = this.opos[0],
                            a = this.opos[1],
                            r = e.pageX,
                            h = e.pageY;
                        return (
                            o > r && ((i = r), (r = o), (o = i)),
                            a > h && ((i = h), (h = a), (a = i)),
                            this.helper.css({ left: o, top: a, width: r - o, height: h - a }),
                            this.selectees.each(function () {
                                var i = t.data(this, "selectable-item"),
                                    l = !1;
                                i &&
                                    i.element !== s.element[0] &&
                                    ("touch" === n.tolerance
                                        ? (l = !(i.left > r || o > i.right || i.top > h || a > i.bottom))
                                        : "fit" === n.tolerance &&
                                          (l = i.left > o && r > i.right && i.top > a && h > i.bottom),
                                    l
                                        ? (i.selected && (i.$element.removeClass("ui-selected"), (i.selected = !1)),
                                          i.unselecting &&
                                              (i.$element.removeClass("ui-unselecting"), (i.unselecting = !1)),
                                          i.selecting ||
                                              (i.$element.addClass("ui-selecting"),
                                              (i.selecting = !0),
                                              s._trigger("selecting", e, { selecting: i.element })))
                                        : (i.selecting &&
                                              ((e.metaKey || e.ctrlKey) && i.startselected
                                                  ? (i.$element.removeClass("ui-selecting"),
                                                    (i.selecting = !1),
                                                    i.$element.addClass("ui-selected"),
                                                    (i.selected = !0))
                                                  : (i.$element.removeClass("ui-selecting"),
                                                    (i.selecting = !1),
                                                    i.startselected &&
                                                        (i.$element.addClass("ui-unselecting"), (i.unselecting = !0)),
                                                    s._trigger("unselecting", e, { unselecting: i.element }))),
                                          i.selected &&
                                              (e.metaKey ||
                                                  e.ctrlKey ||
                                                  i.startselected ||
                                                  (i.$element.removeClass("ui-selected"),
                                                  (i.selected = !1),
                                                  i.$element.addClass("ui-unselecting"),
                                                  (i.unselecting = !0),
                                                  s._trigger("unselecting", e, { unselecting: i.element })))));
                            }),
                            !1
                        );
                    }
                },
                _mouseStop: function (e) {
                    var i = this;
                    return (
                        (this.dragged = !1),
                        t(".ui-unselecting", this.element[0]).each(function () {
                            var s = t.data(this, "selectable-item");
                            s.$element.removeClass("ui-unselecting"),
                                (s.unselecting = !1),
                                (s.startselected = !1),
                                i._trigger("unselected", e, { unselected: s.element });
                        }),
                        t(".ui-selecting", this.element[0]).each(function () {
                            var s = t.data(this, "selectable-item");
                            s.$element.removeClass("ui-selecting").addClass("ui-selected"),
                                (s.selecting = !1),
                                (s.selected = !0),
                                (s.startselected = !0),
                                i._trigger("selected", e, { selected: s.element });
                        }),
                        this._trigger("stop", e),
                        this.helper.remove(),
                        !1
                    );
                },
            });
        })(jQuery),
        (function (t) {
            function e(t, e, i) {
                return t > e && e + i > t;
            }
            function i(t) {
                return /left|right/.test(t.css("float")) || /inline|table-cell/.test(t.css("display"));
            }
            t.widget("ui.sortable", t.ui.mouse, {
                version: "1.10.2",
                widgetEventPrefix: "sort",
                ready: !1,
                options: {
                    appendTo: "parent",
                    axis: !1,
                    connectWith: !1,
                    containment: !1,
                    cursor: "auto",
                    cursorAt: !1,
                    dropOnEmpty: !0,
                    forcePlaceholderSize: !1,
                    forceHelperSize: !1,
                    grid: !1,
                    handle: !1,
                    helper: "original",
                    items: "> *",
                    opacity: !1,
                    placeholder: !1,
                    revert: !1,
                    scroll: !0,
                    scrollSensitivity: 20,
                    scrollSpeed: 20,
                    scope: "default",
                    tolerance: "intersect",
                    zIndex: 1e3,
                    activate: null,
                    beforeStop: null,
                    change: null,
                    deactivate: null,
                    out: null,
                    over: null,
                    receive: null,
                    remove: null,
                    sort: null,
                    start: null,
                    stop: null,
                    update: null,
                },
                _create: function () {
                    var t = this.options;
                    (this.containerCache = {}),
                        this.element.addClass("ui-sortable"),
                        this.refresh(),
                        (this.floating = this.items.length ? "x" === t.axis || i(this.items[0].item) : !1),
                        (this.offset = this.element.offset()),
                        this._mouseInit(),
                        (this.ready = !0);
                },
                _destroy: function () {
                    this.element.removeClass("ui-sortable ui-sortable-disabled"), this._mouseDestroy();
                    for (var t = this.items.length - 1; t >= 0; t--)
                        this.items[t].item.removeData(this.widgetName + "-item");
                    return this;
                },
                _setOption: function (e, i) {
                    "disabled" === e
                        ? ((this.options[e] = i), this.widget().toggleClass("ui-sortable-disabled", !!i))
                        : t.Widget.prototype._setOption.apply(this, arguments);
                },
                _mouseCapture: function (e, i) {
                    var s = null,
                        n = !1,
                        o = this;
                    return this.reverting
                        ? !1
                        : this.options.disabled || "static" === this.options.type
                          ? !1
                          : (this._refreshItems(e),
                            t(e.target)
                                .parents()
                                .each(function () {
                                    return t.data(this, o.widgetName + "-item") === o ? ((s = t(this)), !1) : undefined;
                                }),
                            t.data(e.target, o.widgetName + "-item") === o && (s = t(e.target)),
                            s
                                ? !this.options.handle ||
                                  i ||
                                  (t(this.options.handle, s)
                                      .find("*")
                                      .addBack()
                                      .each(function () {
                                          this === e.target && (n = !0);
                                      }),
                                  n)
                                    ? ((this.currentItem = s), this._removeCurrentsFromItems(), !0)
                                    : !1
                                : !1);
                },
                _mouseStart: function (e, i, s) {
                    var n,
                        o,
                        a = this.options;
                    if (
                        ((this.currentContainer = this),
                        this.refreshPositions(),
                        (this.helper = this._createHelper(e)),
                        this._cacheHelperProportions(),
                        this._cacheMargins(),
                        (this.scrollParent = this.helper.scrollParent()),
                        (this.offset = this.currentItem.offset()),
                        (this.offset = {
                            top: this.offset.top - this.margins.top,
                            left: this.offset.left - this.margins.left,
                        }),
                        t.extend(this.offset, {
                            click: { left: e.pageX - this.offset.left, top: e.pageY - this.offset.top },
                            parent: this._getParentOffset(),
                            relative: this._getRelativeOffset(),
                        }),
                        this.helper.css("position", "absolute"),
                        (this.cssPosition = this.helper.css("position")),
                        (this.originalPosition = this._generatePosition(e)),
                        (this.originalPageX = e.pageX),
                        (this.originalPageY = e.pageY),
                        a.cursorAt && this._adjustOffsetFromHelper(a.cursorAt),
                        (this.domPosition = { prev: this.currentItem.prev()[0], parent: this.currentItem.parent()[0] }),
                        this.helper[0] !== this.currentItem[0] && this.currentItem.hide(),
                        this._createPlaceholder(),
                        a.containment && this._setContainment(),
                        a.cursor &&
                            "auto" !== a.cursor &&
                            ((o = this.document.find("body")),
                            (this.storedCursor = o.css("cursor")),
                            o.css("cursor", a.cursor),
                            (this.storedStylesheet = t(
                                "<style>*{ cursor: " + a.cursor + " !important; }</style>"
                            ).appendTo(o))),
                        a.opacity &&
                            (this.helper.css("opacity") && (this._storedOpacity = this.helper.css("opacity")),
                            this.helper.css("opacity", a.opacity)),
                        a.zIndex &&
                            (this.helper.css("zIndex") && (this._storedZIndex = this.helper.css("zIndex")),
                            this.helper.css("zIndex", a.zIndex)),
                        this.scrollParent[0] !== document &&
                            "HTML" !== this.scrollParent[0].tagName &&
                            (this.overflowOffset = this.scrollParent.offset()),
                        this._trigger("start", e, this._uiHash()),
                        this._preserveHelperProportions || this._cacheHelperProportions(),
                        !s)
                    )
                        for (n = this.containers.length - 1; n >= 0; n--)
                            this.containers[n]._trigger("activate", e, this._uiHash(this));
                    return (
                        t.ui.ddmanager && (t.ui.ddmanager.current = this),
                        t.ui.ddmanager && !a.dropBehaviour && t.ui.ddmanager.prepareOffsets(this, e),
                        (this.dragging = !0),
                        this.helper.addClass("ui-sortable-helper"),
                        this._mouseDrag(e),
                        !0
                    );
                },
                _mouseDrag: function (e) {
                    var i,
                        s,
                        n,
                        o,
                        a = this.options,
                        r = !1;
                    for (
                        this.position = this._generatePosition(e),
                            this.positionAbs = this._convertPositionTo("absolute"),
                            this.lastPositionAbs || (this.lastPositionAbs = this.positionAbs),
                            this.options.scroll &&
                                (this.scrollParent[0] !== document && "HTML" !== this.scrollParent[0].tagName
                                    ? (this.overflowOffset.top + this.scrollParent[0].offsetHeight - e.pageY <
                                      a.scrollSensitivity
                                          ? (this.scrollParent[0].scrollTop = r =
                                                this.scrollParent[0].scrollTop + a.scrollSpeed)
                                          : e.pageY - this.overflowOffset.top < a.scrollSensitivity &&
                                            (this.scrollParent[0].scrollTop = r =
                                                this.scrollParent[0].scrollTop - a.scrollSpeed),
                                      this.overflowOffset.left + this.scrollParent[0].offsetWidth - e.pageX <
                                      a.scrollSensitivity
                                          ? (this.scrollParent[0].scrollLeft = r =
                                                this.scrollParent[0].scrollLeft + a.scrollSpeed)
                                          : e.pageX - this.overflowOffset.left < a.scrollSensitivity &&
                                            (this.scrollParent[0].scrollLeft = r =
                                                this.scrollParent[0].scrollLeft - a.scrollSpeed))
                                    : (e.pageY - t(document).scrollTop() < a.scrollSensitivity
                                          ? (r = t(document).scrollTop(t(document).scrollTop() - a.scrollSpeed))
                                          : t(window).height() - (e.pageY - t(document).scrollTop()) <
                                                a.scrollSensitivity &&
                                            (r = t(document).scrollTop(t(document).scrollTop() + a.scrollSpeed)),
                                      e.pageX - t(document).scrollLeft() < a.scrollSensitivity
                                          ? (r = t(document).scrollLeft(t(document).scrollLeft() - a.scrollSpeed))
                                          : t(window).width() - (e.pageX - t(document).scrollLeft()) <
                                                a.scrollSensitivity &&
                                            (r = t(document).scrollLeft(t(document).scrollLeft() + a.scrollSpeed))),
                                r !== !1 &&
                                    t.ui.ddmanager &&
                                    !a.dropBehaviour &&
                                    t.ui.ddmanager.prepareOffsets(this, e)),
                            this.positionAbs = this._convertPositionTo("absolute"),
                            (this.options.axis && "y" === this.options.axis) ||
                                (this.helper[0].style.left = this.position.left + "px"),
                            (this.options.axis && "x" === this.options.axis) ||
                                (this.helper[0].style.top = this.position.top + "px"),
                            i = this.items.length - 1;
                        i >= 0;
                        i--
                    )
                        if (
                            ((s = this.items[i]),
                            (n = s.item[0]),
                            (o = this._intersectsWithPointer(s)),
                            o &&
                                s.instance === this.currentContainer &&
                                n !== this.currentItem[0] &&
                                this.placeholder[1 === o ? "next" : "prev"]()[0] !== n &&
                                !t.contains(this.placeholder[0], n) &&
                                ("semi-dynamic" === this.options.type ? !t.contains(this.element[0], n) : !0))
                        ) {
                            if (
                                ((this.direction = 1 === o ? "down" : "up"),
                                "pointer" !== this.options.tolerance && !this._intersectsWithSides(s))
                            )
                                break;
                            this._rearrange(e, s), this._trigger("change", e, this._uiHash());
                            break;
                        }
                    return (
                        this._contactContainers(e),
                        t.ui.ddmanager && t.ui.ddmanager.drag(this, e),
                        this._trigger("sort", e, this._uiHash()),
                        (this.lastPositionAbs = this.positionAbs),
                        !1
                    );
                },
                _mouseStop: function (e, i) {
                    if (e) {
                        if (
                            (t.ui.ddmanager && !this.options.dropBehaviour && t.ui.ddmanager.drop(this, e),
                            this.options.revert)
                        ) {
                            var s = this,
                                n = this.placeholder.offset(),
                                o = this.options.axis,
                                a = {};
                            (o && "x" !== o) ||
                                (a.left =
                                    n.left -
                                    this.offset.parent.left -
                                    this.margins.left +
                                    (this.offsetParent[0] === document.body ? 0 : this.offsetParent[0].scrollLeft)),
                                (o && "y" !== o) ||
                                    (a.top =
                                        n.top -
                                        this.offset.parent.top -
                                        this.margins.top +
                                        (this.offsetParent[0] === document.body ? 0 : this.offsetParent[0].scrollTop)),
                                (this.reverting = !0),
                                t(this.helper).animate(a, parseInt(this.options.revert, 10) || 500, function () {
                                    s._clear(e);
                                });
                        } else this._clear(e, i);
                        return !1;
                    }
                },
                cancel: function () {
                    if (this.dragging) {
                        this._mouseUp({ target: null }),
                            "original" === this.options.helper
                                ? this.currentItem.css(this._storedCSS).removeClass("ui-sortable-helper")
                                : this.currentItem.show();
                        for (var e = this.containers.length - 1; e >= 0; e--)
                            this.containers[e]._trigger("deactivate", null, this._uiHash(this)),
                                this.containers[e].containerCache.over &&
                                    (this.containers[e]._trigger("out", null, this._uiHash(this)),
                                    (this.containers[e].containerCache.over = 0));
                    }
                    return (
                        this.placeholder &&
                            (this.placeholder[0].parentNode &&
                                this.placeholder[0].parentNode.removeChild(this.placeholder[0]),
                            "original" !== this.options.helper &&
                                this.helper &&
                                this.helper[0].parentNode &&
                                this.helper.remove(),
                            t.extend(this, { helper: null, dragging: !1, reverting: !1, _noFinalSort: null }),
                            this.domPosition.prev
                                ? t(this.domPosition.prev).after(this.currentItem)
                                : t(this.domPosition.parent).prepend(this.currentItem)),
                        this
                    );
                },
                serialize: function (e) {
                    var i = this._getItemsAsjQuery(e && e.connected),
                        s = [];
                    return (
                        (e = e || {}),
                        t(i).each(function () {
                            var i = (t(e.item || this).attr(e.attribute || "id") || "").match(
                                e.expression || /(.+)[\-=_](.+)/
                            );
                            i && s.push((e.key || i[1] + "[]") + "=" + (e.key && e.expression ? i[1] : i[2]));
                        }),
                        !s.length && e.key && s.push(e.key + "="),
                        s.join("&")
                    );
                },
                toArray: function (e) {
                    var i = this._getItemsAsjQuery(e && e.connected),
                        s = [];
                    return (
                        (e = e || {}),
                        i.each(function () {
                            s.push(t(e.item || this).attr(e.attribute || "id") || "");
                        }),
                        s
                    );
                },
                _intersectsWith: function (t) {
                    var e = this.positionAbs.left,
                        i = e + this.helperProportions.width,
                        s = this.positionAbs.top,
                        n = s + this.helperProportions.height,
                        o = t.left,
                        a = o + t.width,
                        r = t.top,
                        h = r + t.height,
                        l = this.offset.click.top,
                        c = this.offset.click.left,
                        u = s + l > r && h > s + l && e + c > o && a > e + c;
                    return "pointer" === this.options.tolerance ||
                        this.options.forcePointerForContainers ||
                        ("pointer" !== this.options.tolerance &&
                            this.helperProportions[this.floating ? "width" : "height"] >
                                t[this.floating ? "width" : "height"])
                        ? u
                        : e + this.helperProportions.width / 2 > o &&
                              a > i - this.helperProportions.width / 2 &&
                              s + this.helperProportions.height / 2 > r &&
                              h > n - this.helperProportions.height / 2;
                },
                _intersectsWithPointer: function (t) {
                    var i =
                            "x" === this.options.axis ||
                            e(this.positionAbs.top + this.offset.click.top, t.top, t.height),
                        s =
                            "y" === this.options.axis ||
                            e(this.positionAbs.left + this.offset.click.left, t.left, t.width),
                        n = i && s,
                        o = this._getDragVerticalDirection(),
                        a = this._getDragHorizontalDirection();
                    return n
                        ? this.floating
                            ? (a && "right" === a) || "down" === o
                                ? 2
                                : 1
                            : o && ("down" === o ? 2 : 1)
                        : !1;
                },
                _intersectsWithSides: function (t) {
                    var i = e(this.positionAbs.top + this.offset.click.top, t.top + t.height / 2, t.height),
                        s = e(this.positionAbs.left + this.offset.click.left, t.left + t.width / 2, t.width),
                        n = this._getDragVerticalDirection(),
                        o = this._getDragHorizontalDirection();
                    return this.floating && o
                        ? ("right" === o && s) || ("left" === o && !s)
                        : n && (("down" === n && i) || ("up" === n && !i));
                },
                _getDragVerticalDirection: function () {
                    var t = this.positionAbs.top - this.lastPositionAbs.top;
                    return 0 !== t && (t > 0 ? "down" : "up");
                },
                _getDragHorizontalDirection: function () {
                    var t = this.positionAbs.left - this.lastPositionAbs.left;
                    return 0 !== t && (t > 0 ? "right" : "left");
                },
                refresh: function (t) {
                    return this._refreshItems(t), this.refreshPositions(), this;
                },
                _connectWith: function () {
                    var t = this.options;
                    return t.connectWith.constructor === String ? [t.connectWith] : t.connectWith;
                },
                _getItemsAsjQuery: function (e) {
                    var i,
                        s,
                        n,
                        o,
                        a = [],
                        r = [],
                        h = this._connectWith();
                    if (h && e)
                        for (i = h.length - 1; i >= 0; i--)
                            for (n = t(h[i]), s = n.length - 1; s >= 0; s--)
                                (o = t.data(n[s], this.widgetFullName)),
                                    o &&
                                        o !== this &&
                                        !o.options.disabled &&
                                        r.push([
                                            t.isFunction(o.options.items)
                                                ? o.options.items.call(o.element)
                                                : t(o.options.items, o.element)
                                                      .not(".ui-sortable-helper")
                                                      .not(".ui-sortable-placeholder"),
                                            o,
                                        ]);
                    for (
                        r.push([
                            t.isFunction(this.options.items)
                                ? this.options.items.call(this.element, null, {
                                      options: this.options,
                                      item: this.currentItem,
                                  })
                                : t(this.options.items, this.element)
                                      .not(".ui-sortable-helper")
                                      .not(".ui-sortable-placeholder"),
                            this,
                        ]),
                            i = r.length - 1;
                        i >= 0;
                        i--
                    )
                        r[i][0].each(function () {
                            a.push(this);
                        });
                    return t(a);
                },
                _removeCurrentsFromItems: function () {
                    var e = this.currentItem.find(":data(" + this.widgetName + "-item)");
                    this.items = t.grep(this.items, function (t) {
                        for (var i = 0; e.length > i; i++) if (e[i] === t.item[0]) return !1;
                        return !0;
                    });
                },
                _refreshItems: function (e) {
                    (this.items = []), (this.containers = [this]);
                    var i,
                        s,
                        n,
                        o,
                        a,
                        r,
                        h,
                        l,
                        c = this.items,
                        u = [
                            [
                                t.isFunction(this.options.items)
                                    ? this.options.items.call(this.element[0], e, { item: this.currentItem })
                                    : t(this.options.items, this.element),
                                this,
                            ],
                        ],
                        d = this._connectWith();
                    if (d && this.ready)
                        for (i = d.length - 1; i >= 0; i--)
                            for (n = t(d[i]), s = n.length - 1; s >= 0; s--)
                                (o = t.data(n[s], this.widgetFullName)),
                                    o &&
                                        o !== this &&
                                        !o.options.disabled &&
                                        (u.push([
                                            t.isFunction(o.options.items)
                                                ? o.options.items.call(o.element[0], e, { item: this.currentItem })
                                                : t(o.options.items, o.element),
                                            o,
                                        ]),
                                        this.containers.push(o));
                    for (i = u.length - 1; i >= 0; i--)
                        for (a = u[i][1], r = u[i][0], s = 0, l = r.length; l > s; s++)
                            (h = t(r[s])),
                                h.data(this.widgetName + "-item", a),
                                c.push({ item: h, instance: a, width: 0, height: 0, left: 0, top: 0 });
                },
                refreshPositions: function (e) {
                    this.offsetParent && this.helper && (this.offset.parent = this._getParentOffset());
                    var i, s, n, o;
                    for (i = this.items.length - 1; i >= 0; i--)
                        (s = this.items[i]),
                            (s.instance !== this.currentContainer &&
                                this.currentContainer &&
                                s.item[0] !== this.currentItem[0]) ||
                                ((n = this.options.toleranceElement
                                    ? t(this.options.toleranceElement, s.item)
                                    : s.item),
                                e || ((s.width = n.outerWidth()), (s.height = n.outerHeight())),
                                (o = n.offset()),
                                (s.left = o.left),
                                (s.top = o.top));
                    if (this.options.custom && this.options.custom.refreshContainers)
                        this.options.custom.refreshContainers.call(this);
                    else
                        for (i = this.containers.length - 1; i >= 0; i--)
                            (o = this.containers[i].element.offset()),
                                (this.containers[i].containerCache.left = o.left),
                                (this.containers[i].containerCache.top = o.top),
                                (this.containers[i].containerCache.width = this.containers[i].element.outerWidth()),
                                (this.containers[i].containerCache.height = this.containers[i].element.outerHeight());
                    return this;
                },
                _createPlaceholder: function (e) {
                    e = e || this;
                    var i,
                        s = e.options;
                    (s.placeholder && s.placeholder.constructor !== String) ||
                        ((i = s.placeholder),
                        (s.placeholder = {
                            element: function () {
                                var s = e.currentItem[0].nodeName.toLowerCase(),
                                    n = t(e.document[0].createElement(s))
                                        .addClass(i || e.currentItem[0].className + " ui-sortable-placeholder")
                                        .removeClass("ui-sortable-helper");
                                return (
                                    "tr" === s
                                        ? n.append("<td colspan='99'>&#160;</td>")
                                        : "img" === s && n.attr("src", e.currentItem.attr("src")),
                                    i || n.css("visibility", "hidden"),
                                    n
                                );
                            },
                            update: function (t, n) {
                                (!i || s.forcePlaceholderSize) &&
                                    (n.height() ||
                                        n.height(
                                            e.currentItem.innerHeight() -
                                                parseInt(e.currentItem.css("paddingTop") || 0, 10) -
                                                parseInt(e.currentItem.css("paddingBottom") || 0, 10)
                                        ),
                                    n.width() ||
                                        n.width(
                                            e.currentItem.innerWidth() -
                                                parseInt(e.currentItem.css("paddingLeft") || 0, 10) -
                                                parseInt(e.currentItem.css("paddingRight") || 0, 10)
                                        ));
                            },
                        })),
                        (e.placeholder = t(s.placeholder.element.call(e.element, e.currentItem))),
                        e.currentItem.after(e.placeholder),
                        s.placeholder.update(e, e.placeholder);
                },
                _contactContainers: function (s) {
                    var n,
                        o,
                        a,
                        r,
                        h,
                        l,
                        c,
                        u,
                        d,
                        p,
                        f = null,
                        g = null;
                    for (n = this.containers.length - 1; n >= 0; n--)
                        if (!t.contains(this.currentItem[0], this.containers[n].element[0]))
                            if (this._intersectsWith(this.containers[n].containerCache)) {
                                if (f && t.contains(this.containers[n].element[0], f.element[0])) continue;
                                (f = this.containers[n]), (g = n);
                            } else
                                this.containers[n].containerCache.over &&
                                    (this.containers[n]._trigger("out", s, this._uiHash(this)),
                                    (this.containers[n].containerCache.over = 0));
                    if (f)
                        if (1 === this.containers.length)
                            this.containers[g].containerCache.over ||
                                (this.containers[g]._trigger("over", s, this._uiHash(this)),
                                (this.containers[g].containerCache.over = 1));
                        else {
                            for (
                                a = 1e4,
                                    r = null,
                                    p = f.floating || i(this.currentItem),
                                    h = p ? "left" : "top",
                                    l = p ? "width" : "height",
                                    c = this.positionAbs[h] + this.offset.click[h],
                                    o = this.items.length - 1;
                                o >= 0;
                                o--
                            )
                                t.contains(this.containers[g].element[0], this.items[o].item[0]) &&
                                    this.items[o].item[0] !== this.currentItem[0] &&
                                    (!p ||
                                        e(
                                            this.positionAbs.top + this.offset.click.top,
                                            this.items[o].top,
                                            this.items[o].height
                                        )) &&
                                    ((u = this.items[o].item.offset()[h]),
                                    (d = !1),
                                    Math.abs(u - c) > Math.abs(u + this.items[o][l] - c) &&
                                        ((d = !0), (u += this.items[o][l])),
                                    a > Math.abs(u - c) &&
                                        ((a = Math.abs(u - c)),
                                        (r = this.items[o]),
                                        (this.direction = d ? "up" : "down")));
                            if (!r && !this.options.dropOnEmpty) return;
                            if (this.currentContainer === this.containers[g]) return;
                            r
                                ? this._rearrange(s, r, null, !0)
                                : this._rearrange(s, null, this.containers[g].element, !0),
                                this._trigger("change", s, this._uiHash()),
                                this.containers[g]._trigger("change", s, this._uiHash(this)),
                                (this.currentContainer = this.containers[g]),
                                this.options.placeholder.update(this.currentContainer, this.placeholder),
                                this.containers[g]._trigger("over", s, this._uiHash(this)),
                                (this.containers[g].containerCache.over = 1);
                        }
                },
                _createHelper: function (e) {
                    var i = this.options,
                        s = t.isFunction(i.helper)
                            ? t(i.helper.apply(this.element[0], [e, this.currentItem]))
                            : "clone" === i.helper
                              ? this.currentItem.clone()
                              : this.currentItem;
                    return (
                        s.parents("body").length ||
                            t("parent" !== i.appendTo ? i.appendTo : this.currentItem[0].parentNode)[0].appendChild(
                                s[0]
                            ),
                        s[0] === this.currentItem[0] &&
                            (this._storedCSS = {
                                width: this.currentItem[0].style.width,
                                height: this.currentItem[0].style.height,
                                position: this.currentItem.css("position"),
                                top: this.currentItem.css("top"),
                                left: this.currentItem.css("left"),
                            }),
                        (!s[0].style.width || i.forceHelperSize) && s.width(this.currentItem.width()),
                        (!s[0].style.height || i.forceHelperSize) && s.height(this.currentItem.height()),
                        s
                    );
                },
                _adjustOffsetFromHelper: function (e) {
                    "string" == typeof e && (e = e.split(" ")),
                        t.isArray(e) && (e = { left: +e[0], top: +e[1] || 0 }),
                        "left" in e && (this.offset.click.left = e.left + this.margins.left),
                        "right" in e &&
                            (this.offset.click.left = this.helperProportions.width - e.right + this.margins.left),
                        "top" in e && (this.offset.click.top = e.top + this.margins.top),
                        "bottom" in e &&
                            (this.offset.click.top = this.helperProportions.height - e.bottom + this.margins.top);
                },
                _getParentOffset: function () {
                    this.offsetParent = this.helper.offsetParent();
                    var e = this.offsetParent.offset();
                    return (
                        "absolute" === this.cssPosition &&
                            this.scrollParent[0] !== document &&
                            t.contains(this.scrollParent[0], this.offsetParent[0]) &&
                            ((e.left += this.scrollParent.scrollLeft()), (e.top += this.scrollParent.scrollTop())),
                        (this.offsetParent[0] === document.body ||
                            (this.offsetParent[0].tagName &&
                                "html" === this.offsetParent[0].tagName.toLowerCase() &&
                                t.ui.ie)) &&
                            (e = { top: 0, left: 0 }),
                        {
                            top: e.top + (parseInt(this.offsetParent.css("borderTopWidth"), 10) || 0),
                            left: e.left + (parseInt(this.offsetParent.css("borderLeftWidth"), 10) || 0),
                        }
                    );
                },
                _getRelativeOffset: function () {
                    if ("relative" === this.cssPosition) {
                        var t = this.currentItem.position();
                        return {
                            top: t.top - (parseInt(this.helper.css("top"), 10) || 0) + this.scrollParent.scrollTop(),
                            left:
                                t.left - (parseInt(this.helper.css("left"), 10) || 0) + this.scrollParent.scrollLeft(),
                        };
                    }
                    return { top: 0, left: 0 };
                },
                _cacheMargins: function () {
                    this.margins = {
                        left: parseInt(this.currentItem.css("marginLeft"), 10) || 0,
                        top: parseInt(this.currentItem.css("marginTop"), 10) || 0,
                    };
                },
                _cacheHelperProportions: function () {
                    this.helperProportions = { width: this.helper.outerWidth(), height: this.helper.outerHeight() };
                },
                _setContainment: function () {
                    var e,
                        i,
                        s,
                        n = this.options;
                    "parent" === n.containment && (n.containment = this.helper[0].parentNode),
                        ("document" === n.containment || "window" === n.containment) &&
                            (this.containment = [
                                0 - this.offset.relative.left - this.offset.parent.left,
                                0 - this.offset.relative.top - this.offset.parent.top,
                                t("document" === n.containment ? document : window).width() -
                                    this.helperProportions.width -
                                    this.margins.left,
                                (t("document" === n.containment ? document : window).height() ||
                                    document.body.parentNode.scrollHeight) -
                                    this.helperProportions.height -
                                    this.margins.top,
                            ]),
                        /^(document|window|parent)$/.test(n.containment) ||
                            ((e = t(n.containment)[0]),
                            (i = t(n.containment).offset()),
                            (s = "hidden" !== t(e).css("overflow")),
                            (this.containment = [
                                i.left +
                                    (parseInt(t(e).css("borderLeftWidth"), 10) || 0) +
                                    (parseInt(t(e).css("paddingLeft"), 10) || 0) -
                                    this.margins.left,
                                i.top +
                                    (parseInt(t(e).css("borderTopWidth"), 10) || 0) +
                                    (parseInt(t(e).css("paddingTop"), 10) || 0) -
                                    this.margins.top,
                                i.left +
                                    (s ? Math.max(e.scrollWidth, e.offsetWidth) : e.offsetWidth) -
                                    (parseInt(t(e).css("borderLeftWidth"), 10) || 0) -
                                    (parseInt(t(e).css("paddingRight"), 10) || 0) -
                                    this.helperProportions.width -
                                    this.margins.left,
                                i.top +
                                    (s ? Math.max(e.scrollHeight, e.offsetHeight) : e.offsetHeight) -
                                    (parseInt(t(e).css("borderTopWidth"), 10) || 0) -
                                    (parseInt(t(e).css("paddingBottom"), 10) || 0) -
                                    this.helperProportions.height -
                                    this.margins.top,
                            ]));
                },
                _convertPositionTo: function (e, i) {
                    i || (i = this.position);
                    var s = "absolute" === e ? 1 : -1,
                        n =
                            "absolute" !== this.cssPosition ||
                            (this.scrollParent[0] !== document &&
                                t.contains(this.scrollParent[0], this.offsetParent[0]))
                                ? this.scrollParent
                                : this.offsetParent,
                        o = /(html|body)/i.test(n[0].tagName);
                    return {
                        top:
                            i.top +
                            this.offset.relative.top * s +
                            this.offset.parent.top * s -
                            ("fixed" === this.cssPosition ? -this.scrollParent.scrollTop() : o ? 0 : n.scrollTop()) * s,
                        left:
                            i.left +
                            this.offset.relative.left * s +
                            this.offset.parent.left * s -
                            ("fixed" === this.cssPosition ? -this.scrollParent.scrollLeft() : o ? 0 : n.scrollLeft()) *
                                s,
                    };
                },
                _generatePosition: function (e) {
                    var i,
                        s,
                        n = this.options,
                        o = e.pageX,
                        a = e.pageY,
                        r =
                            "absolute" !== this.cssPosition ||
                            (this.scrollParent[0] !== document &&
                                t.contains(this.scrollParent[0], this.offsetParent[0]))
                                ? this.scrollParent
                                : this.offsetParent,
                        h = /(html|body)/i.test(r[0].tagName);
                    return (
                        "relative" !== this.cssPosition ||
                            (this.scrollParent[0] !== document && this.scrollParent[0] !== this.offsetParent[0]) ||
                            (this.offset.relative = this._getRelativeOffset()),
                        this.originalPosition &&
                            (this.containment &&
                                (e.pageX - this.offset.click.left < this.containment[0] &&
                                    (o = this.containment[0] + this.offset.click.left),
                                e.pageY - this.offset.click.top < this.containment[1] &&
                                    (a = this.containment[1] + this.offset.click.top),
                                e.pageX - this.offset.click.left > this.containment[2] &&
                                    (o = this.containment[2] + this.offset.click.left),
                                e.pageY - this.offset.click.top > this.containment[3] &&
                                    (a = this.containment[3] + this.offset.click.top)),
                            n.grid &&
                                ((i =
                                    this.originalPageY + Math.round((a - this.originalPageY) / n.grid[1]) * n.grid[1]),
                                (a = this.containment
                                    ? i - this.offset.click.top >= this.containment[1] &&
                                      i - this.offset.click.top <= this.containment[3]
                                        ? i
                                        : i - this.offset.click.top >= this.containment[1]
                                          ? i - n.grid[1]
                                          : i + n.grid[1]
                                    : i),
                                (s = this.originalPageX + Math.round((o - this.originalPageX) / n.grid[0]) * n.grid[0]),
                                (o = this.containment
                                    ? s - this.offset.click.left >= this.containment[0] &&
                                      s - this.offset.click.left <= this.containment[2]
                                        ? s
                                        : s - this.offset.click.left >= this.containment[0]
                                          ? s - n.grid[0]
                                          : s + n.grid[0]
                                    : s))),
                        {
                            top:
                                a -
                                this.offset.click.top -
                                this.offset.relative.top -
                                this.offset.parent.top +
                                ("fixed" === this.cssPosition ? -this.scrollParent.scrollTop() : h ? 0 : r.scrollTop()),
                            left:
                                o -
                                this.offset.click.left -
                                this.offset.relative.left -
                                this.offset.parent.left +
                                ("fixed" === this.cssPosition
                                    ? -this.scrollParent.scrollLeft()
                                    : h
                                      ? 0
                                      : r.scrollLeft()),
                        }
                    );
                },
                _rearrange: function (t, e, i, s) {
                    i
                        ? i[0].appendChild(this.placeholder[0])
                        : e.item[0].parentNode.insertBefore(
                              this.placeholder[0],
                              "down" === this.direction ? e.item[0] : e.item[0].nextSibling
                          ),
                        (this.counter = this.counter ? ++this.counter : 1);
                    var n = this.counter;
                    this._delay(function () {
                        n === this.counter && this.refreshPositions(!s);
                    });
                },
                _clear: function (t, e) {
                    this.reverting = !1;
                    var i,
                        s = [];
                    if (
                        (!this._noFinalSort &&
                            this.currentItem.parent().length &&
                            this.placeholder.before(this.currentItem),
                        (this._noFinalSort = null),
                        this.helper[0] === this.currentItem[0])
                    ) {
                        for (i in this._storedCSS)
                            ("auto" === this._storedCSS[i] || "static" === this._storedCSS[i]) &&
                                (this._storedCSS[i] = "");
                        this.currentItem.css(this._storedCSS).removeClass("ui-sortable-helper");
                    } else this.currentItem.show();
                    for (
                        this.fromOutside &&
                            !e &&
                            s.push(function (t) {
                                this._trigger("receive", t, this._uiHash(this.fromOutside));
                            }),
                            (!this.fromOutside &&
                                this.domPosition.prev === this.currentItem.prev().not(".ui-sortable-helper")[0] &&
                                this.domPosition.parent === this.currentItem.parent()[0]) ||
                                e ||
                                s.push(function (t) {
                                    this._trigger("update", t, this._uiHash());
                                }),
                            this !== this.currentContainer &&
                                (e ||
                                    (s.push(function (t) {
                                        this._trigger("remove", t, this._uiHash());
                                    }),
                                    s.push(
                                        function (t) {
                                            return function (e) {
                                                t._trigger("receive", e, this._uiHash(this));
                                            };
                                        }.call(this, this.currentContainer)
                                    ),
                                    s.push(
                                        function (t) {
                                            return function (e) {
                                                t._trigger("update", e, this._uiHash(this));
                                            };
                                        }.call(this, this.currentContainer)
                                    ))),
                            i = this.containers.length - 1;
                        i >= 0;
                        i--
                    )
                        e ||
                            s.push(
                                function (t) {
                                    return function (e) {
                                        t._trigger("deactivate", e, this._uiHash(this));
                                    };
                                }.call(this, this.containers[i])
                            ),
                            this.containers[i].containerCache.over &&
                                (s.push(
                                    function (t) {
                                        return function (e) {
                                            t._trigger("out", e, this._uiHash(this));
                                        };
                                    }.call(this, this.containers[i])
                                ),
                                (this.containers[i].containerCache.over = 0));
                    if (
                        (this.storedCursor &&
                            (this.document.find("body").css("cursor", this.storedCursor),
                            this.storedStylesheet.remove()),
                        this._storedOpacity && this.helper.css("opacity", this._storedOpacity),
                        this._storedZIndex &&
                            this.helper.css("zIndex", "auto" === this._storedZIndex ? "" : this._storedZIndex),
                        (this.dragging = !1),
                        this.cancelHelperRemoval)
                    ) {
                        if (!e) {
                            for (this._trigger("beforeStop", t, this._uiHash()), i = 0; s.length > i; i++)
                                s[i].call(this, t);
                            this._trigger("stop", t, this._uiHash());
                        }
                        return (this.fromOutside = !1), !1;
                    }
                    if (
                        (e || this._trigger("beforeStop", t, this._uiHash()),
                        this.placeholder[0].parentNode.removeChild(this.placeholder[0]),
                        this.helper[0] !== this.currentItem[0] && this.helper.remove(),
                        (this.helper = null),
                        !e)
                    ) {
                        for (i = 0; s.length > i; i++) s[i].call(this, t);
                        this._trigger("stop", t, this._uiHash());
                    }
                    return (this.fromOutside = !1), !0;
                },
                _trigger: function () {
                    t.Widget.prototype._trigger.apply(this, arguments) === !1 && this.cancel();
                },
                _uiHash: function (e) {
                    var i = e || this;
                    return {
                        helper: i.helper,
                        placeholder: i.placeholder || t([]),
                        position: i.position,
                        originalPosition: i.originalPosition,
                        offset: i.positionAbs,
                        item: i.currentItem,
                        sender: e ? e.element : null,
                    };
                },
            });
        })(jQuery),
        (function (t, e) {
            var i = "ui-effects-";
            (t.effects = { effect: {} }),
                (function (t, e) {
                    function i(t, e, i) {
                        var s = u[e.type] || {};
                        return null == t
                            ? i || !e.def
                                ? null
                                : e.def
                            : ((t = s.floor ? ~~t : parseFloat(t)),
                              isNaN(t) ? e.def : s.mod ? (t + s.mod) % s.mod : 0 > t ? 0 : t > s.max ? s.max : t);
                    }
                    function s(i) {
                        var s = l(),
                            n = (s._rgba = []);
                        return (
                            (i = i.toLowerCase()),
                            f(h, function (t, o) {
                                var a,
                                    r = o.re.exec(i),
                                    h = r && o.parse(r),
                                    l = o.space || "rgba";
                                return h
                                    ? ((a = s[l](h)), (s[c[l].cache] = a[c[l].cache]), (n = s._rgba = a._rgba), !1)
                                    : e;
                            }),
                            n.length ? ("0,0,0,0" === n.join() && t.extend(n, o.transparent), s) : o[i]
                        );
                    }
                    function n(t, e, i) {
                        return (
                            (i = (i + 1) % 1),
                            1 > 6 * i
                                ? t + 6 * (e - t) * i
                                : 1 > 2 * i
                                  ? e
                                  : 2 > 3 * i
                                    ? t + 6 * (e - t) * (2 / 3 - i)
                                    : t
                        );
                    }
                    var o,
                        a =
                            "backgroundColor borderBottomColor borderLeftColor borderRightColor borderTopColor color columnRuleColor outlineColor textDecorationColor textEmphasisColor",
                        r = /^([\-+])=\s*(\d+\.?\d*)/,
                        h = [
                            {
                                re: /rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*(?:,\s*(\d?(?:\.\d+)?)\s*)?\)/,
                                parse: function (t) {
                                    return [t[1], t[2], t[3], t[4]];
                                },
                            },
                            {
                                re: /rgba?\(\s*(\d+(?:\.\d+)?)\%\s*,\s*(\d+(?:\.\d+)?)\%\s*,\s*(\d+(?:\.\d+)?)\%\s*(?:,\s*(\d?(?:\.\d+)?)\s*)?\)/,
                                parse: function (t) {
                                    return [2.55 * t[1], 2.55 * t[2], 2.55 * t[3], t[4]];
                                },
                            },
                            {
                                re: /#([a-f0-9]{2})([a-f0-9]{2})([a-f0-9]{2})/,
                                parse: function (t) {
                                    return [parseInt(t[1], 16), parseInt(t[2], 16), parseInt(t[3], 16)];
                                },
                            },
                            {
                                re: /#([a-f0-9])([a-f0-9])([a-f0-9])/,
                                parse: function (t) {
                                    return [
                                        parseInt(t[1] + t[1], 16),
                                        parseInt(t[2] + t[2], 16),
                                        parseInt(t[3] + t[3], 16),
                                    ];
                                },
                            },
                            {
                                re: /hsla?\(\s*(\d+(?:\.\d+)?)\s*,\s*(\d+(?:\.\d+)?)\%\s*,\s*(\d+(?:\.\d+)?)\%\s*(?:,\s*(\d?(?:\.\d+)?)\s*)?\)/,
                                space: "hsla",
                                parse: function (t) {
                                    return [t[1], t[2] / 100, t[3] / 100, t[4]];
                                },
                            },
                        ],
                        l = (t.Color = function (e, i, s, n) {
                            return new t.Color.fn.parse(e, i, s, n);
                        }),
                        c = {
                            rgba: {
                                props: {
                                    red: { idx: 0, type: "byte" },
                                    green: { idx: 1, type: "byte" },
                                    blue: { idx: 2, type: "byte" },
                                },
                            },
                            hsla: {
                                props: {
                                    hue: { idx: 0, type: "degrees" },
                                    saturation: { idx: 1, type: "percent" },
                                    lightness: { idx: 2, type: "percent" },
                                },
                            },
                        },
                        u = { byte: { floor: !0, max: 255 }, percent: { max: 1 }, degrees: { mod: 360, floor: !0 } },
                        d = (l.support = {}),
                        p = t("<p>")[0],
                        f = t.each;
                    (p.style.cssText = "background-color:rgba(1,1,1,.5)"),
                        (d.rgba = p.style.backgroundColor.indexOf("rgba") > -1),
                        f(c, function (t, e) {
                            (e.cache = "_" + t), (e.props.alpha = { idx: 3, type: "percent", def: 1 });
                        }),
                        (l.fn = t.extend(l.prototype, {
                            parse: function (n, a, r, h) {
                                if (n === e) return (this._rgba = [null, null, null, null]), this;
                                (n.jquery || n.nodeType) && ((n = t(n).css(a)), (a = e));
                                var u = this,
                                    d = t.type(n),
                                    p = (this._rgba = []);
                                return (
                                    a !== e && ((n = [n, a, r, h]), (d = "array")),
                                    "string" === d
                                        ? this.parse(s(n) || o._default)
                                        : "array" === d
                                          ? (f(c.rgba.props, function (t, e) {
                                                p[e.idx] = i(n[e.idx], e);
                                            }),
                                            this)
                                          : "object" === d
                                            ? (n instanceof l
                                                  ? f(c, function (t, e) {
                                                        n[e.cache] && (u[e.cache] = n[e.cache].slice());
                                                    })
                                                  : f(c, function (e, s) {
                                                        var o = s.cache;
                                                        f(s.props, function (t, e) {
                                                            if (!u[o] && s.to) {
                                                                if ("alpha" === t || null == n[t]) return;
                                                                u[o] = s.to(u._rgba);
                                                            }
                                                            u[o][e.idx] = i(n[t], e, !0);
                                                        }),
                                                            u[o] &&
                                                                0 > t.inArray(null, u[o].slice(0, 3)) &&
                                                                ((u[o][3] = 1), s.from && (u._rgba = s.from(u[o])));
                                                    }),
                                              this)
                                            : e
                                );
                            },
                            is: function (t) {
                                var i = l(t),
                                    s = !0,
                                    n = this;
                                return (
                                    f(c, function (t, o) {
                                        var a,
                                            r = i[o.cache];
                                        return (
                                            r &&
                                                ((a = n[o.cache] || (o.to && o.to(n._rgba)) || []),
                                                f(o.props, function (t, i) {
                                                    return null != r[i.idx] ? (s = r[i.idx] === a[i.idx]) : e;
                                                })),
                                            s
                                        );
                                    }),
                                    s
                                );
                            },
                            _space: function () {
                                var t = [],
                                    e = this;
                                return (
                                    f(c, function (i, s) {
                                        e[s.cache] && t.push(i);
                                    }),
                                    t.pop()
                                );
                            },
                            transition: function (t, e) {
                                var s = l(t),
                                    n = s._space(),
                                    o = c[n],
                                    a = 0 === this.alpha() ? l("transparent") : this,
                                    r = a[o.cache] || o.to(a._rgba),
                                    h = r.slice();
                                return (
                                    (s = s[o.cache]),
                                    f(o.props, function (t, n) {
                                        var o = n.idx,
                                            a = r[o],
                                            l = s[o],
                                            c = u[n.type] || {};
                                        null !== l &&
                                            (null === a
                                                ? (h[o] = l)
                                                : (c.mod &&
                                                      (l - a > c.mod / 2
                                                          ? (a += c.mod)
                                                          : a - l > c.mod / 2 && (a -= c.mod)),
                                                  (h[o] = i((l - a) * e + a, n))));
                                    }),
                                    this[n](h)
                                );
                            },
                            blend: function (e) {
                                if (1 === this._rgba[3]) return this;
                                var i = this._rgba.slice(),
                                    s = i.pop(),
                                    n = l(e)._rgba;
                                return l(
                                    t.map(i, function (t, e) {
                                        return (1 - s) * n[e] + s * t;
                                    })
                                );
                            },
                            toRgbaString: function () {
                                var e = "rgba(",
                                    i = t.map(this._rgba, function (t, e) {
                                        return null == t ? (e > 2 ? 1 : 0) : t;
                                    });
                                return 1 === i[3] && (i.pop(), (e = "rgb(")), e + i.join() + ")";
                            },
                            toHslaString: function () {
                                var e = "hsla(",
                                    i = t.map(this.hsla(), function (t, e) {
                                        return (
                                            null == t && (t = e > 2 ? 1 : 0),
                                            e && 3 > e && (t = Math.round(100 * t) + "%"),
                                            t
                                        );
                                    });
                                return 1 === i[3] && (i.pop(), (e = "hsl(")), e + i.join() + ")";
                            },
                            toHexString: function (e) {
                                var i = this._rgba.slice(),
                                    s = i.pop();
                                return (
                                    e && i.push(~~(255 * s)),
                                    "#" +
                                        t
                                            .map(i, function (t) {
                                                return (t = (t || 0).toString(16)), 1 === t.length ? "0" + t : t;
                                            })
                                            .join("")
                                );
                            },
                            toString: function () {
                                return 0 === this._rgba[3] ? "transparent" : this.toRgbaString();
                            },
                        })),
                        (l.fn.parse.prototype = l.fn),
                        (c.hsla.to = function (t) {
                            if (null == t[0] || null == t[1] || null == t[2]) return [null, null, null, t[3]];
                            var e,
                                i,
                                s = t[0] / 255,
                                n = t[1] / 255,
                                o = t[2] / 255,
                                a = t[3],
                                r = Math.max(s, n, o),
                                h = Math.min(s, n, o),
                                l = r - h,
                                c = r + h,
                                u = 0.5 * c;
                            return (
                                (e =
                                    h === r
                                        ? 0
                                        : s === r
                                          ? (60 * (n - o)) / l + 360
                                          : n === r
                                            ? (60 * (o - s)) / l + 120
                                            : (60 * (s - n)) / l + 240),
                                (i = 0 === l ? 0 : 0.5 >= u ? l / c : l / (2 - c)),
                                [Math.round(e) % 360, i, u, null == a ? 1 : a]
                            );
                        }),
                        (c.hsla.from = function (t) {
                            if (null == t[0] || null == t[1] || null == t[2]) return [null, null, null, t[3]];
                            var e = t[0] / 360,
                                i = t[1],
                                s = t[2],
                                o = t[3],
                                a = 0.5 >= s ? s * (1 + i) : s + i - s * i,
                                r = 2 * s - a;
                            return [
                                Math.round(255 * n(r, a, e + 1 / 3)),
                                Math.round(255 * n(r, a, e)),
                                Math.round(255 * n(r, a, e - 1 / 3)),
                                o,
                            ];
                        }),
                        f(c, function (s, n) {
                            var o = n.props,
                                a = n.cache,
                                h = n.to,
                                c = n.from;
                            (l.fn[s] = function (s) {
                                if ((h && !this[a] && (this[a] = h(this._rgba)), s === e)) return this[a].slice();
                                var n,
                                    r = t.type(s),
                                    u = "array" === r || "object" === r ? s : arguments,
                                    d = this[a].slice();
                                return (
                                    f(o, function (t, e) {
                                        var s = u["object" === r ? t : e.idx];
                                        null == s && (s = d[e.idx]), (d[e.idx] = i(s, e));
                                    }),
                                    c ? ((n = l(c(d))), (n[a] = d), n) : l(d)
                                );
                            }),
                                f(o, function (e, i) {
                                    l.fn[e] ||
                                        (l.fn[e] = function (n) {
                                            var o,
                                                a = t.type(n),
                                                h = "alpha" === e ? (this._hsla ? "hsla" : "rgba") : s,
                                                l = this[h](),
                                                c = l[i.idx];
                                            return "undefined" === a
                                                ? c
                                                : ("function" === a && ((n = n.call(this, c)), (a = t.type(n))),
                                                  null == n && i.empty
                                                      ? this
                                                      : ("string" === a &&
                                                            ((o = r.exec(n)),
                                                            o && (n = c + parseFloat(o[2]) * ("+" === o[1] ? 1 : -1))),
                                                        (l[i.idx] = n),
                                                        this[h](l)));
                                        });
                                });
                        }),
                        (l.hook = function (e) {
                            var i = e.split(" ");
                            f(i, function (e, i) {
                                (t.cssHooks[i] = {
                                    set: function (e, n) {
                                        var o,
                                            a,
                                            r = "";
                                        if ("transparent" !== n && ("string" !== t.type(n) || (o = s(n)))) {
                                            if (((n = l(o || n)), !d.rgba && 1 !== n._rgba[3])) {
                                                for (
                                                    a = "backgroundColor" === i ? e.parentNode : e;
                                                    ("" === r || "transparent" === r) && a && a.style;

                                                )
                                                    try {
                                                        (r = t.css(a, "backgroundColor")), (a = a.parentNode);
                                                    } catch (h) {}
                                                n = n.blend(r && "transparent" !== r ? r : "_default");
                                            }
                                            n = n.toRgbaString();
                                        }
                                        try {
                                            e.style[i] = n;
                                        } catch (h) {}
                                    },
                                }),
                                    (t.fx.step[i] = function (e) {
                                        e.colorInit ||
                                            ((e.start = l(e.elem, i)), (e.end = l(e.end)), (e.colorInit = !0)),
                                            t.cssHooks[i].set(e.elem, e.start.transition(e.end, e.pos));
                                    });
                            });
                        }),
                        l.hook(a),
                        (t.cssHooks.borderColor = {
                            expand: function (t) {
                                var e = {};
                                return (
                                    f(["Top", "Right", "Bottom", "Left"], function (i, s) {
                                        e["border" + s + "Color"] = t;
                                    }),
                                    e
                                );
                            },
                        }),
                        (o = t.Color.names =
                            {
                                aqua: "#00ffff",
                                black: "#000000",
                                blue: "#0000ff",
                                fuchsia: "#ff00ff",
                                gray: "#808080",
                                green: "#008000",
                                lime: "#00ff00",
                                maroon: "#800000",
                                navy: "#000080",
                                olive: "#808000",
                                purple: "#800080",
                                red: "#ff0000",
                                silver: "#c0c0c0",
                                teal: "#008080",
                                white: "#ffffff",
                                yellow: "#ffff00",
                                transparent: [null, null, null, 0],
                                _default: "#ffffff",
                            });
                })(jQuery),
                (function () {
                    function i(e) {
                        var i,
                            s,
                            n = e.ownerDocument.defaultView
                                ? e.ownerDocument.defaultView.getComputedStyle(e, null)
                                : e.currentStyle,
                            o = {};
                        if (n && n.length && n[0] && n[n[0]])
                            for (s = n.length; s--; ) (i = n[s]), "string" == typeof n[i] && (o[t.camelCase(i)] = n[i]);
                        else for (i in n) "string" == typeof n[i] && (o[i] = n[i]);
                        return o;
                    }
                    function s(e, i) {
                        var s,
                            n,
                            a = {};
                        for (s in i)
                            (n = i[s]), e[s] !== n && (o[s] || ((t.fx.step[s] || !isNaN(parseFloat(n))) && (a[s] = n)));
                        return a;
                    }
                    var n = ["add", "remove", "toggle"],
                        o = {
                            border: 1,
                            borderBottom: 1,
                            borderColor: 1,
                            borderLeft: 1,
                            borderRight: 1,
                            borderTop: 1,
                            borderWidth: 1,
                            margin: 1,
                            padding: 1,
                        };
                    t.each(
                        ["borderLeftStyle", "borderRightStyle", "borderBottomStyle", "borderTopStyle"],
                        function (e, i) {
                            t.fx.step[i] = function (t) {
                                (("none" !== t.end && !t.setAttr) || (1 === t.pos && !t.setAttr)) &&
                                    (jQuery.style(t.elem, i, t.end), (t.setAttr = !0));
                            };
                        }
                    ),
                        t.fn.addBack ||
                            (t.fn.addBack = function (t) {
                                return this.add(null == t ? this.prevObject : this.prevObject.filter(t));
                            }),
                        (t.effects.animateClass = function (e, o, a, r) {
                            var h = t.speed(o, a, r);
                            return this.queue(function () {
                                var o,
                                    a = t(this),
                                    r = a.attr("class") || "",
                                    l = h.children ? a.find("*").addBack() : a;
                                (l = l.map(function () {
                                    var e = t(this);
                                    return { el: e, start: i(this) };
                                })),
                                    (o = function () {
                                        t.each(n, function (t, i) {
                                            e[i] && a[i + "Class"](e[i]);
                                        });
                                    }),
                                    o(),
                                    (l = l.map(function () {
                                        return (this.end = i(this.el[0])), (this.diff = s(this.start, this.end)), this;
                                    })),
                                    a.attr("class", r),
                                    (l = l.map(function () {
                                        var e = this,
                                            i = t.Deferred(),
                                            s = t.extend({}, h, {
                                                queue: !1,
                                                complete: function () {
                                                    i.resolve(e);
                                                },
                                            });
                                        return this.el.animate(this.diff, s), i.promise();
                                    })),
                                    t.when.apply(t, l.get()).done(function () {
                                        o(),
                                            t.each(arguments, function () {
                                                var e = this.el;
                                                t.each(this.diff, function (t) {
                                                    e.css(t, "");
                                                });
                                            }),
                                            h.complete.call(a[0]);
                                    });
                            });
                        }),
                        t.fn.extend({
                            addClass: (function (e) {
                                return function (i, s, n, o) {
                                    return s
                                        ? t.effects.animateClass.call(this, { add: i }, s, n, o)
                                        : e.apply(this, arguments);
                                };
                            })(t.fn.addClass),
                            removeClass: (function (e) {
                                return function (i, s, n, o) {
                                    return arguments.length > 1
                                        ? t.effects.animateClass.call(this, { remove: i }, s, n, o)
                                        : e.apply(this, arguments);
                                };
                            })(t.fn.removeClass),
                            toggleClass: (function (i) {
                                return function (s, n, o, a, r) {
                                    return "boolean" == typeof n || n === e
                                        ? o
                                            ? t.effects.animateClass.call(this, n ? { add: s } : { remove: s }, o, a, r)
                                            : i.apply(this, arguments)
                                        : t.effects.animateClass.call(this, { toggle: s }, n, o, a);
                                };
                            })(t.fn.toggleClass),
                            switchClass: function (e, i, s, n, o) {
                                return t.effects.animateClass.call(this, { add: i, remove: e }, s, n, o);
                            },
                        });
                })(),
                (function () {
                    function s(e, i, s, n) {
                        return (
                            t.isPlainObject(e) && ((i = e), (e = e.effect)),
                            (e = { effect: e }),
                            null == i && (i = {}),
                            t.isFunction(i) && ((n = i), (s = null), (i = {})),
                            ("number" == typeof i || t.fx.speeds[i]) && ((n = s), (s = i), (i = {})),
                            t.isFunction(s) && ((n = s), (s = null)),
                            i && t.extend(e, i),
                            (s = s || i.duration),
                            (e.duration = t.fx.off
                                ? 0
                                : "number" == typeof s
                                  ? s
                                  : s in t.fx.speeds
                                    ? t.fx.speeds[s]
                                    : t.fx.speeds._default),
                            (e.complete = n || i.complete),
                            e
                        );
                    }
                    function n(e) {
                        return !e || "number" == typeof e || t.fx.speeds[e]
                            ? !0
                            : "string" != typeof e || t.effects.effect[e]
                              ? t.isFunction(e)
                                  ? !0
                                  : "object" != typeof e || e.effect
                                    ? !1
                                    : !0
                              : !0;
                    }
                    t.extend(t.effects, {
                        version: "1.10.2",
                        save: function (t, e) {
                            for (var s = 0; e.length > s; s++) null !== e[s] && t.data(i + e[s], t[0].style[e[s]]);
                        },
                        restore: function (t, s) {
                            var n, o;
                            for (o = 0; s.length > o; o++)
                                null !== s[o] && ((n = t.data(i + s[o])), n === e && (n = ""), t.css(s[o], n));
                        },
                        setMode: function (t, e) {
                            return "toggle" === e && (e = t.is(":hidden") ? "show" : "hide"), e;
                        },
                        getBaseline: function (t, e) {
                            var i, s;
                            switch (t[0]) {
                                case "top":
                                    i = 0;
                                    break;
                                case "middle":
                                    i = 0.5;
                                    break;
                                case "bottom":
                                    i = 1;
                                    break;
                                default:
                                    i = t[0] / e.height;
                            }
                            switch (t[1]) {
                                case "left":
                                    s = 0;
                                    break;
                                case "center":
                                    s = 0.5;
                                    break;
                                case "right":
                                    s = 1;
                                    break;
                                default:
                                    s = t[1] / e.width;
                            }
                            return { x: s, y: i };
                        },
                        createWrapper: function (e) {
                            if (e.parent().is(".ui-effects-wrapper")) return e.parent();
                            var i = { width: e.outerWidth(!0), height: e.outerHeight(!0), float: e.css("float") },
                                s = t("<div></div>")
                                    .addClass("ui-effects-wrapper")
                                    .css({
                                        fontSize: "100%",
                                        background: "transparent",
                                        border: "none",
                                        margin: 0,
                                        padding: 0,
                                    }),
                                n = { width: e.width(), height: e.height() },
                                o = document.activeElement;
                            try {
                                o.id;
                            } catch (a) {
                                o = document.body;
                            }
                            return (
                                e.wrap(s),
                                (e[0] === o || t.contains(e[0], o)) && t(o).focus(),
                                (s = e.parent()),
                                "static" === e.css("position")
                                    ? (s.css({ position: "relative" }), e.css({ position: "relative" }))
                                    : (t.extend(i, { position: e.css("position"), zIndex: e.css("z-index") }),
                                      t.each(["top", "left", "bottom", "right"], function (t, s) {
                                          (i[s] = e.css(s)), isNaN(parseInt(i[s], 10)) && (i[s] = "auto");
                                      }),
                                      e.css({ position: "relative", top: 0, left: 0, right: "auto", bottom: "auto" })),
                                e.css(n),
                                s.css(i).show()
                            );
                        },
                        removeWrapper: function (e) {
                            var i = document.activeElement;
                            return (
                                e.parent().is(".ui-effects-wrapper") &&
                                    (e.parent().replaceWith(e), (e[0] === i || t.contains(e[0], i)) && t(i).focus()),
                                e
                            );
                        },
                        setTransition: function (e, i, s, n) {
                            return (
                                (n = n || {}),
                                t.each(i, function (t, i) {
                                    var o = e.cssUnit(i);
                                    o[0] > 0 && (n[i] = o[0] * s + o[1]);
                                }),
                                n
                            );
                        },
                    }),
                        t.fn.extend({
                            effect: function () {
                                function e(e) {
                                    function s() {
                                        t.isFunction(o) && o.call(n[0]), t.isFunction(e) && e();
                                    }
                                    var n = t(this),
                                        o = i.complete,
                                        r = i.mode;
                                    (n.is(":hidden") ? "hide" === r : "show" === r)
                                        ? (n[r](), s())
                                        : a.call(n[0], i, s);
                                }
                                var i = s.apply(this, arguments),
                                    n = i.mode,
                                    o = i.queue,
                                    a = t.effects.effect[i.effect];
                                return t.fx.off || !a
                                    ? n
                                        ? this[n](i.duration, i.complete)
                                        : this.each(function () {
                                              i.complete && i.complete.call(this);
                                          })
                                    : o === !1
                                      ? this.each(e)
                                      : this.queue(o || "fx", e);
                            },
                            show: (function (t) {
                                return function (e) {
                                    if (n(e)) return t.apply(this, arguments);
                                    var i = s.apply(this, arguments);
                                    return (i.mode = "show"), this.effect.call(this, i);
                                };
                            })(t.fn.show),
                            hide: (function (t) {
                                return function (e) {
                                    if (n(e)) return t.apply(this, arguments);
                                    var i = s.apply(this, arguments);
                                    return (i.mode = "hide"), this.effect.call(this, i);
                                };
                            })(t.fn.hide),
                            toggle: (function (t) {
                                return function (e) {
                                    if (n(e) || "boolean" == typeof e) return t.apply(this, arguments);
                                    var i = s.apply(this, arguments);
                                    return (i.mode = "toggle"), this.effect.call(this, i);
                                };
                            })(t.fn.toggle),
                            cssUnit: function (e) {
                                var i = this.css(e),
                                    s = [];
                                return (
                                    t.each(["em", "px", "%", "pt"], function (t, e) {
                                        i.indexOf(e) > 0 && (s = [parseFloat(i), e]);
                                    }),
                                    s
                                );
                            },
                        });
                })(),
                (function () {
                    var e = {};
                    t.each(["Quad", "Cubic", "Quart", "Quint", "Expo"], function (t, i) {
                        e[i] = function (e) {
                            return Math.pow(e, t + 2);
                        };
                    }),
                        t.extend(e, {
                            Sine: function (t) {
                                return 1 - Math.cos((t * Math.PI) / 2);
                            },
                            Circ: function (t) {
                                return 1 - Math.sqrt(1 - t * t);
                            },
                            Elastic: function (t) {
                                return 0 === t || 1 === t
                                    ? t
                                    : -Math.pow(2, 8 * (t - 1)) * Math.sin(((80 * (t - 1) - 7.5) * Math.PI) / 15);
                            },
                            Back: function (t) {
                                return t * t * (3 * t - 2);
                            },
                            Bounce: function (t) {
                                for (var e, i = 4; ((e = Math.pow(2, --i)) - 1) / 11 > t; );
                                return 1 / Math.pow(4, 3 - i) - 7.5625 * Math.pow((3 * e - 2) / 22 - t, 2);
                            },
                        }),
                        t.each(e, function (e, i) {
                            (t.easing["easeIn" + e] = i),
                                (t.easing["easeOut" + e] = function (t) {
                                    return 1 - i(1 - t);
                                }),
                                (t.easing["easeInOut" + e] = function (t) {
                                    return 0.5 > t ? i(2 * t) / 2 : 1 - i(-2 * t + 2) / 2;
                                });
                        });
                })();
        })(jQuery),
        (function (t) {
            var e = 0,
                i = {},
                s = {};
            (i.height = i.paddingTop = i.paddingBottom = i.borderTopWidth = i.borderBottomWidth = "hide"),
                (s.height = s.paddingTop = s.paddingBottom = s.borderTopWidth = s.borderBottomWidth = "show"),
                t.widget("ui.accordion", {
                    version: "1.10.2",
                    options: {
                        active: 0,
                        animate: {},
                        collapsible: !1,
                        event: "click",
                        header: "> li > :first-child,> :not(li):even",
                        heightStyle: "auto",
                        icons: { activeHeader: "ui-icon-triangle-1-s", header: "ui-icon-triangle-1-e" },
                        activate: null,
                        beforeActivate: null,
                    },
                    _create: function () {
                        var e = this.options;
                        (this.prevShow = this.prevHide = t()),
                            this.element.addClass("ui-accordion ui-widget ui-helper-reset").attr("role", "tablist"),
                            e.collapsible || (e.active !== !1 && null != e.active) || (e.active = 0),
                            this._processPanels(),
                            0 > e.active && (e.active += this.headers.length),
                            this._refresh();
                    },
                    _getCreateEventData: function () {
                        return {
                            header: this.active,
                            panel: this.active.length ? this.active.next() : t(),
                            content: this.active.length ? this.active.next() : t(),
                        };
                    },
                    _createIcons: function () {
                        var e = this.options.icons;
                        e &&
                            (t("<span>")
                                .addClass("ui-accordion-header-icon ui-icon " + e.header)
                                .prependTo(this.headers),
                            this.active
                                .children(".ui-accordion-header-icon")
                                .removeClass(e.header)
                                .addClass(e.activeHeader),
                            this.headers.addClass("ui-accordion-icons"));
                    },
                    _destroyIcons: function () {
                        this.headers.removeClass("ui-accordion-icons").children(".ui-accordion-header-icon").remove();
                    },
                    _destroy: function () {
                        var t;
                        this.element.removeClass("ui-accordion ui-widget ui-helper-reset").removeAttr("role"),
                            this.headers
                                .removeClass(
                                    "ui-accordion-header ui-accordion-header-active ui-helper-reset ui-state-default ui-corner-all ui-state-active ui-state-disabled ui-corner-top"
                                )
                                .removeAttr("role")
                                .removeAttr("aria-selected")
                                .removeAttr("aria-controls")
                                .removeAttr("tabIndex")
                                .each(function () {
                                    /^ui-accordion/.test(this.id) && this.removeAttribute("id");
                                }),
                            this._destroyIcons(),
                            (t = this.headers
                                .next()
                                .css("display", "")
                                .removeAttr("role")
                                .removeAttr("aria-expanded")
                                .removeAttr("aria-hidden")
                                .removeAttr("aria-labelledby")
                                .removeClass(
                                    "ui-helper-reset ui-widget-content ui-corner-bottom ui-accordion-content ui-accordion-content-active ui-state-disabled"
                                )
                                .each(function () {
                                    /^ui-accordion/.test(this.id) && this.removeAttribute("id");
                                })),
                            "content" !== this.options.heightStyle && t.css("height", "");
                    },
                    _setOption: function (t, e) {
                        return "active" === t
                            ? (this._activate(e), undefined)
                            : ("event" === t &&
                                  (this.options.event && this._off(this.headers, this.options.event),
                                  this._setupEvents(e)),
                              this._super(t, e),
                              "collapsible" !== t || e || this.options.active !== !1 || this._activate(0),
                              "icons" === t && (this._destroyIcons(), e && this._createIcons()),
                              "disabled" === t &&
                                  this.headers.add(this.headers.next()).toggleClass("ui-state-disabled", !!e),
                              undefined);
                    },
                    _keydown: function (e) {
                        if (!e.altKey && !e.ctrlKey) {
                            var i = t.ui.keyCode,
                                s = this.headers.length,
                                n = this.headers.index(e.target),
                                o = !1;
                            switch (e.keyCode) {
                                case i.RIGHT:
                                case i.DOWN:
                                    o = this.headers[(n + 1) % s];
                                    break;
                                case i.LEFT:
                                case i.UP:
                                    o = this.headers[(n - 1 + s) % s];
                                    break;
                                case i.SPACE:
                                case i.ENTER:
                                    this._eventHandler(e);
                                    break;
                                case i.HOME:
                                    o = this.headers[0];
                                    break;
                                case i.END:
                                    o = this.headers[s - 1];
                            }
                            o &&
                                (t(e.target).attr("tabIndex", -1),
                                t(o).attr("tabIndex", 0),
                                o.focus(),
                                e.preventDefault());
                        }
                    },
                    _panelKeyDown: function (e) {
                        e.keyCode === t.ui.keyCode.UP && e.ctrlKey && t(e.currentTarget).prev().focus();
                    },
                    refresh: function () {
                        var e = this.options;
                        this._processPanels(),
                            ((e.active === !1 && e.collapsible === !0) || !this.headers.length) &&
                                ((e.active = !1), (this.active = t())),
                            e.active === !1
                                ? this._activate(0)
                                : this.active.length && !t.contains(this.element[0], this.active[0])
                                  ? this.headers.length === this.headers.find(".ui-state-disabled").length
                                      ? ((e.active = !1), (this.active = t()))
                                      : this._activate(Math.max(0, e.active - 1))
                                  : (e.active = this.headers.index(this.active)),
                            this._destroyIcons(),
                            this._refresh();
                    },
                    _processPanels: function () {
                        (this.headers = this.element
                            .find(this.options.header)
                            .addClass("ui-accordion-header ui-helper-reset ui-state-default ui-corner-all")),
                            this.headers
                                .next()
                                .addClass("ui-accordion-content ui-helper-reset ui-widget-content ui-corner-bottom")
                                .filter(":not(.ui-accordion-content-active)")
                                .hide();
                    },
                    _refresh: function () {
                        var i,
                            s = this.options,
                            n = s.heightStyle,
                            o = this.element.parent(),
                            a = (this.accordionId = "ui-accordion-" + (this.element.attr("id") || ++e));
                        (this.active = this._findActive(s.active)
                            .addClass("ui-accordion-header-active ui-state-active ui-corner-top")
                            .removeClass("ui-corner-all")),
                            this.active.next().addClass("ui-accordion-content-active").show(),
                            this.headers
                                .attr("role", "tab")
                                .each(function (e) {
                                    var i = t(this),
                                        s = i.attr("id"),
                                        n = i.next(),
                                        o = n.attr("id");
                                    s || ((s = a + "-header-" + e), i.attr("id", s)),
                                        o || ((o = a + "-panel-" + e), n.attr("id", o)),
                                        i.attr("aria-controls", o),
                                        n.attr("aria-labelledby", s);
                                })
                                .next()
                                .attr("role", "tabpanel"),
                            this.headers
                                .not(this.active)
                                .attr({ "aria-selected": "false", tabIndex: -1 })
                                .next()
                                .attr({ "aria-expanded": "false", "aria-hidden": "true" })
                                .hide(),
                            this.active.length
                                ? this.active
                                      .attr({ "aria-selected": "true", tabIndex: 0 })
                                      .next()
                                      .attr({ "aria-expanded": "true", "aria-hidden": "false" })
                                : this.headers.eq(0).attr("tabIndex", 0),
                            this._createIcons(),
                            this._setupEvents(s.event),
                            "fill" === n
                                ? ((i = o.height()),
                                  this.element.siblings(":visible").each(function () {
                                      var e = t(this),
                                          s = e.css("position");
                                      "absolute" !== s && "fixed" !== s && (i -= e.outerHeight(!0));
                                  }),
                                  this.headers.each(function () {
                                      i -= t(this).outerHeight(!0);
                                  }),
                                  this.headers
                                      .next()
                                      .each(function () {
                                          t(this).height(Math.max(0, i - t(this).innerHeight() + t(this).height()));
                                      })
                                      .css("overflow", "auto"))
                                : "auto" === n &&
                                  ((i = 0),
                                  this.headers
                                      .next()
                                      .each(function () {
                                          i = Math.max(i, t(this).css("height", "").height());
                                      })
                                      .height(i));
                    },
                    _activate: function (e) {
                        var i = this._findActive(e)[0];
                        i !== this.active[0] &&
                            ((i = i || this.active[0]),
                            this._eventHandler({ target: i, currentTarget: i, preventDefault: t.noop }));
                    },
                    _findActive: function (e) {
                        return "number" == typeof e ? this.headers.eq(e) : t();
                    },
                    _setupEvents: function (e) {
                        var i = { keydown: "_keydown" };
                        e &&
                            t.each(e.split(" "), function (t, e) {
                                i[e] = "_eventHandler";
                            }),
                            this._off(this.headers.add(this.headers.next())),
                            this._on(this.headers, i),
                            this._on(this.headers.next(), { keydown: "_panelKeyDown" }),
                            this._hoverable(this.headers),
                            this._focusable(this.headers);
                    },
                    _eventHandler: function (e) {
                        var i = this.options,
                            s = this.active,
                            n = t(e.currentTarget),
                            o = n[0] === s[0],
                            a = o && i.collapsible,
                            r = a ? t() : n.next(),
                            h = s.next(),
                            l = { oldHeader: s, oldPanel: h, newHeader: a ? t() : n, newPanel: r };
                        e.preventDefault(),
                            (o && !i.collapsible) ||
                                this._trigger("beforeActivate", e, l) === !1 ||
                                ((i.active = a ? !1 : this.headers.index(n)),
                                (this.active = o ? t() : n),
                                this._toggle(l),
                                s.removeClass("ui-accordion-header-active ui-state-active"),
                                i.icons &&
                                    s
                                        .children(".ui-accordion-header-icon")
                                        .removeClass(i.icons.activeHeader)
                                        .addClass(i.icons.header),
                                o ||
                                    (n
                                        .removeClass("ui-corner-all")
                                        .addClass("ui-accordion-header-active ui-state-active ui-corner-top"),
                                    i.icons &&
                                        n
                                            .children(".ui-accordion-header-icon")
                                            .removeClass(i.icons.header)
                                            .addClass(i.icons.activeHeader),
                                    n.next().addClass("ui-accordion-content-active")));
                    },
                    _toggle: function (e) {
                        var i = e.newPanel,
                            s = this.prevShow.length ? this.prevShow : e.oldPanel;
                        this.prevShow.add(this.prevHide).stop(!0, !0),
                            (this.prevShow = i),
                            (this.prevHide = s),
                            this.options.animate
                                ? this._animate(i, s, e)
                                : (s.hide(), i.show(), this._toggleComplete(e)),
                            s.attr({ "aria-expanded": "false", "aria-hidden": "true" }),
                            s.prev().attr("aria-selected", "false"),
                            i.length && s.length
                                ? s.prev().attr("tabIndex", -1)
                                : i.length &&
                                  this.headers
                                      .filter(function () {
                                          return 0 === t(this).attr("tabIndex");
                                      })
                                      .attr("tabIndex", -1),
                            i
                                .attr({ "aria-expanded": "true", "aria-hidden": "false" })
                                .prev()
                                .attr({ "aria-selected": "true", tabIndex: 0 });
                    },
                    _animate: function (t, e, n) {
                        var o,
                            a,
                            r,
                            h = this,
                            l = 0,
                            c = t.length && (!e.length || t.index() < e.index()),
                            u = this.options.animate || {},
                            d = (c && u.down) || u,
                            p = function () {
                                h._toggleComplete(n);
                            };
                        return (
                            "number" == typeof d && (r = d),
                            "string" == typeof d && (a = d),
                            (a = a || d.easing || u.easing),
                            (r = r || d.duration || u.duration),
                            e.length
                                ? t.length
                                    ? ((o = t.show().outerHeight()),
                                      e.animate(i, {
                                          duration: r,
                                          easing: a,
                                          step: function (t, e) {
                                              e.now = Math.round(t);
                                          },
                                      }),
                                      t.hide().animate(s, {
                                          duration: r,
                                          easing: a,
                                          complete: p,
                                          step: function (t, i) {
                                              (i.now = Math.round(t)),
                                                  "height" !== i.prop
                                                      ? (l += i.now)
                                                      : "content" !== h.options.heightStyle &&
                                                        ((i.now = Math.round(o - e.outerHeight() - l)), (l = 0));
                                          },
                                      }),
                                      undefined)
                                    : e.animate(i, r, a, p)
                                : t.animate(s, r, a, p)
                        );
                    },
                    _toggleComplete: function (t) {
                        var e = t.oldPanel;
                        e
                            .removeClass("ui-accordion-content-active")
                            .prev()
                            .removeClass("ui-corner-top")
                            .addClass("ui-corner-all"),
                            e.length && (e.parent()[0].className = e.parent()[0].className),
                            this._trigger("activate", null, t);
                    },
                });
        })(jQuery),
        (function (t) {
            var e = 0;
            t.widget("ui.autocomplete", {
                version: "1.10.2",
                defaultElement: "<input>",
                options: {
                    appendTo: null,
                    autoFocus: !1,
                    delay: 300,
                    minLength: 1,
                    position: { my: "left top", at: "left bottom", collision: "none" },
                    source: null,
                    change: null,
                    close: null,
                    focus: null,
                    open: null,
                    response: null,
                    search: null,
                    select: null,
                },
                pending: 0,
                _create: function () {
                    var e,
                        i,
                        s,
                        n = this.element[0].nodeName.toLowerCase(),
                        o = "textarea" === n,
                        a = "input" === n;
                    (this.isMultiLine = o ? !0 : a ? !1 : this.element.prop("isContentEditable")),
                        (this.valueMethod = this.element[o || a ? "val" : "text"]),
                        (this.isNewMenu = !0),
                        this.element.addClass("ui-autocomplete-input").attr("autocomplete", "off"),
                        this._on(this.element, {
                            keydown: function (n) {
                                if (this.element.prop("readOnly")) return (e = !0), (s = !0), (i = !0), undefined;
                                (e = !1), (s = !1), (i = !1);
                                var o = t.ui.keyCode;
                                switch (n.keyCode) {
                                    case o.PAGE_UP:
                                        (e = !0), this._move("previousPage", n);
                                        break;
                                    case o.PAGE_DOWN:
                                        (e = !0), this._move("nextPage", n);
                                        break;
                                    case o.UP:
                                        (e = !0), this._keyEvent("previous", n);
                                        break;
                                    case o.DOWN:
                                        (e = !0), this._keyEvent("next", n);
                                        break;
                                    case o.ENTER:
                                    case o.NUMPAD_ENTER:
                                        this.menu.active && ((e = !0), n.preventDefault(), this.menu.select(n));
                                        break;
                                    case o.TAB:
                                        this.menu.active && this.menu.select(n);
                                        break;
                                    case o.ESCAPE:
                                        this.menu.element.is(":visible") &&
                                            (this._value(this.term), this.close(n), n.preventDefault());
                                        break;
                                    default:
                                        (i = !0), this._searchTimeout(n);
                                }
                            },
                            keypress: function (s) {
                                if (e) return (e = !1), s.preventDefault(), undefined;
                                if (!i) {
                                    var n = t.ui.keyCode;
                                    switch (s.keyCode) {
                                        case n.PAGE_UP:
                                            this._move("previousPage", s);
                                            break;
                                        case n.PAGE_DOWN:
                                            this._move("nextPage", s);
                                            break;
                                        case n.UP:
                                            this._keyEvent("previous", s);
                                            break;
                                        case n.DOWN:
                                            this._keyEvent("next", s);
                                    }
                                }
                            },
                            input: function (t) {
                                return s
                                    ? ((s = !1), t.preventDefault(), undefined)
                                    : (this._searchTimeout(t), undefined);
                            },
                            focus: function () {
                                (this.selectedItem = null), (this.previous = this._value());
                            },
                            blur: function (t) {
                                return this.cancelBlur
                                    ? (delete this.cancelBlur, undefined)
                                    : (clearTimeout(this.searching), this.close(t), this._change(t), undefined);
                            },
                        }),
                        this._initSource(),
                        (this.menu = t("<ul>")
                            .addClass("ui-autocomplete ui-front")
                            .appendTo(this._appendTo())
                            .menu({ input: t(), role: null })
                            .hide()
                            .data("ui-menu")),
                        this._on(this.menu.element, {
                            mousedown: function (e) {
                                e.preventDefault(),
                                    (this.cancelBlur = !0),
                                    this._delay(function () {
                                        delete this.cancelBlur;
                                    });
                                var i = this.menu.element[0];
                                t(e.target).closest(".ui-menu-item").length ||
                                    this._delay(function () {
                                        var e = this;
                                        this.document.one("mousedown", function (s) {
                                            s.target === e.element[0] ||
                                                s.target === i ||
                                                t.contains(i, s.target) ||
                                                e.close();
                                        });
                                    });
                            },
                            menufocus: function (e, i) {
                                if (
                                    this.isNewMenu &&
                                    ((this.isNewMenu = !1), e.originalEvent && /^mouse/.test(e.originalEvent.type))
                                )
                                    return (
                                        this.menu.blur(),
                                        this.document.one("mousemove", function () {
                                            t(e.target).trigger(e.originalEvent);
                                        }),
                                        undefined
                                    );
                                var s = i.item.data("ui-autocomplete-item");
                                !1 !== this._trigger("focus", e, { item: s })
                                    ? e.originalEvent && /^key/.test(e.originalEvent.type) && this._value(s.value)
                                    : this.liveRegion.text(s.value);
                            },
                            menuselect: function (t, e) {
                                var i = e.item.data("ui-autocomplete-item"),
                                    s = this.previous;
                                this.element[0] !== this.document[0].activeElement &&
                                    (this.element.focus(),
                                    (this.previous = s),
                                    this._delay(function () {
                                        (this.previous = s), (this.selectedItem = i);
                                    })),
                                    !1 !== this._trigger("select", t, { item: i }) && this._value(i.value),
                                    (this.term = this._value()),
                                    this.close(t),
                                    (this.selectedItem = i);
                            },
                        }),
                        (this.liveRegion = t("<span>", { role: "status", "aria-live": "polite" })
                            .addClass("ui-helper-hidden-accessible")
                            .insertAfter(this.element)),
                        this._on(this.window, {
                            beforeunload: function () {
                                this.element.removeAttr("autocomplete");
                            },
                        });
                },
                _destroy: function () {
                    clearTimeout(this.searching),
                        this.element.removeClass("ui-autocomplete-input").removeAttr("autocomplete"),
                        this.menu.element.remove(),
                        this.liveRegion.remove();
                },
                _setOption: function (t, e) {
                    this._super(t, e),
                        "source" === t && this._initSource(),
                        "appendTo" === t && this.menu.element.appendTo(this._appendTo()),
                        "disabled" === t && e && this.xhr && this.xhr.abort();
                },
                _appendTo: function () {
                    var e = this.options.appendTo;
                    return (
                        e && (e = e.jquery || e.nodeType ? t(e) : this.document.find(e).eq(0)),
                        e || (e = this.element.closest(".ui-front")),
                        e.length || (e = this.document[0].body),
                        e
                    );
                },
                _initSource: function () {
                    var e,
                        i,
                        s = this;
                    t.isArray(this.options.source)
                        ? ((e = this.options.source),
                          (this.source = function (i, s) {
                              s(t.ui.autocomplete.filter(e, i.term));
                          }))
                        : "string" == typeof this.options.source
                          ? ((i = this.options.source),
                            (this.source = function (e, n) {
                                s.xhr && s.xhr.abort(),
                                    (s.xhr = t.ajax({
                                        url: i,
                                        data: e,
                                        dataType: "json",
                                        success: function (t) {
                                            n(t);
                                        },
                                        error: function () {
                                            n([]);
                                        },
                                    }));
                            }))
                          : (this.source = this.options.source);
                },
                _searchTimeout: function (t) {
                    clearTimeout(this.searching),
                        (this.searching = this._delay(function () {
                            this.term !== this._value() && ((this.selectedItem = null), this.search(null, t));
                        }, this.options.delay));
                },
                search: function (t, e) {
                    return (
                        (t = null != t ? t : this._value()),
                        (this.term = this._value()),
                        t.length < this.options.minLength
                            ? this.close(e)
                            : this._trigger("search", e) !== !1
                              ? this._search(t)
                              : undefined
                    );
                },
                _search: function (t) {
                    this.pending++,
                        this.element.addClass("ui-autocomplete-loading"),
                        (this.cancelSearch = !1),
                        this.source({ term: t }, this._response());
                },
                _response: function () {
                    var t = this,
                        i = ++e;
                    return function (s) {
                        i === e && t.__response(s),
                            t.pending--,
                            t.pending || t.element.removeClass("ui-autocomplete-loading");
                    };
                },
                __response: function (t) {
                    t && (t = this._normalize(t)),
                        this._trigger("response", null, { content: t }),
                        !this.options.disabled && t && t.length && !this.cancelSearch
                            ? (this._suggest(t), this._trigger("open"))
                            : this._close();
                },
                close: function (t) {
                    (this.cancelSearch = !0), this._close(t);
                },
                _close: function (t) {
                    this.menu.element.is(":visible") &&
                        (this.menu.element.hide(), this.menu.blur(), (this.isNewMenu = !0), this._trigger("close", t));
                },
                _change: function (t) {
                    this.previous !== this._value() && this._trigger("change", t, { item: this.selectedItem });
                },
                _normalize: function (e) {
                    return e.length && e[0].label && e[0].value
                        ? e
                        : t.map(e, function (e) {
                              return "string" == typeof e
                                  ? { label: e, value: e }
                                  : t.extend({ label: e.label || e.value, value: e.value || e.label }, e);
                          });
                },
                _suggest: function (e) {
                    var i = this.menu.element.empty();
                    this._renderMenu(i, e),
                        (this.isNewMenu = !0),
                        this.menu.refresh(),
                        i.show(),
                        this._resizeMenu(),
                        i.position(t.extend({ of: this.element }, this.options.position)),
                        this.options.autoFocus && this.menu.next();
                },
                _resizeMenu: function () {
                    var t = this.menu.element;
                    t.outerWidth(Math.max(t.width("").outerWidth() + 1, this.element.outerWidth()));
                },
                _renderMenu: function (e, i) {
                    var s = this;
                    t.each(i, function (t, i) {
                        s._renderItemData(e, i);
                    });
                },
                _renderItemData: function (t, e) {
                    return this._renderItem(t, e).data("ui-autocomplete-item", e);
                },
                _renderItem: function (e, i) {
                    return t("<li>").append(t("<a>").text(i.label)).appendTo(e);
                },
                _move: function (t, e) {
                    return this.menu.element.is(":visible")
                        ? (this.menu.isFirstItem() && /^previous/.test(t)) ||
                          (this.menu.isLastItem() && /^next/.test(t))
                            ? (this._value(this.term), this.menu.blur(), undefined)
                            : (this.menu[t](e), undefined)
                        : (this.search(null, e), undefined);
                },
                widget: function () {
                    return this.menu.element;
                },
                _value: function () {
                    return this.valueMethod.apply(this.element, arguments);
                },
                _keyEvent: function (t, e) {
                    (!this.isMultiLine || this.menu.element.is(":visible")) && (this._move(t, e), e.preventDefault());
                },
            }),
                t.extend(t.ui.autocomplete, {
                    escapeRegex: function (t) {
                        return t.replace(/[\-\[\]{}()*+?.,\\\^$|#\s]/g, "\\$&");
                    },
                    filter: function (e, i) {
                        var s = RegExp(t.ui.autocomplete.escapeRegex(i), "i");
                        return t.grep(e, function (t) {
                            return s.test(t.label || t.value || t);
                        });
                    },
                }),
                t.widget("ui.autocomplete", t.ui.autocomplete, {
                    options: {
                        messages: {
                            noResults: "No search results.",
                            results: function (t) {
                                return (
                                    t +
                                    (t > 1 ? " results are" : " result is") +
                                    " available, use up and down arrow keys to navigate."
                                );
                            },
                        },
                    },
                    __response: function (t) {
                        var e;
                        this._superApply(arguments),
                            this.options.disabled ||
                                this.cancelSearch ||
                                ((e =
                                    t && t.length
                                        ? this.options.messages.results(t.length)
                                        : this.options.messages.noResults),
                                this.liveRegion.text(e));
                    },
                });
        })(jQuery),
        (function (t) {
            var e,
                i,
                s,
                n,
                o = "ui-button ui-widget ui-state-default ui-corner-all",
                a = "ui-state-hover ui-state-active ",
                r =
                    "ui-button-icons-only ui-button-icon-only ui-button-text-icons ui-button-text-icon-primary ui-button-text-icon-secondary ui-button-text-only",
                h = function () {
                    var e = t(this).find(":ui-button");
                    setTimeout(function () {
                        e.button("refresh");
                    }, 1);
                },
                l = function (e) {
                    var i = e.name,
                        s = e.form,
                        n = t([]);
                    return (
                        i &&
                            ((i = i.replace(/'/g, "\\'")),
                            (n = s
                                ? t(s).find("[name='" + i + "']")
                                : t("[name='" + i + "']", e.ownerDocument).filter(function () {
                                      return !this.form;
                                  }))),
                        n
                    );
                };
            t.widget("ui.button", {
                version: "1.10.2",
                defaultElement: "<button>",
                options: { disabled: null, text: !0, label: null, icons: { primary: null, secondary: null } },
                _create: function () {
                    this.element
                        .closest("form")
                        .unbind("reset" + this.eventNamespace)
                        .bind("reset" + this.eventNamespace, h),
                        "boolean" != typeof this.options.disabled
                            ? (this.options.disabled = !!this.element.prop("disabled"))
                            : this.element.prop("disabled", this.options.disabled),
                        this._determineButtonType(),
                        (this.hasTitle = !!this.buttonElement.attr("title"));
                    var a = this,
                        r = this.options,
                        c = "checkbox" === this.type || "radio" === this.type,
                        u = c ? "" : "ui-state-active",
                        d = "ui-state-focus";
                    null === r.label &&
                        (r.label = "input" === this.type ? this.buttonElement.val() : this.buttonElement.html()),
                        this._hoverable(this.buttonElement),
                        this.buttonElement
                            .addClass(o)
                            .attr("role", "button")
                            .bind("mouseenter" + this.eventNamespace, function () {
                                r.disabled || (this === e && t(this).addClass("ui-state-active"));
                            })
                            .bind("mouseleave" + this.eventNamespace, function () {
                                r.disabled || t(this).removeClass(u);
                            })
                            .bind("click" + this.eventNamespace, function (t) {
                                r.disabled && (t.preventDefault(), t.stopImmediatePropagation());
                            }),
                        this.element
                            .bind("focus" + this.eventNamespace, function () {
                                a.buttonElement.addClass(d);
                            })
                            .bind("blur" + this.eventNamespace, function () {
                                a.buttonElement.removeClass(d);
                            }),
                        c &&
                            (this.element.bind("change" + this.eventNamespace, function () {
                                n || a.refresh();
                            }),
                            this.buttonElement
                                .bind("mousedown" + this.eventNamespace, function (t) {
                                    r.disabled || ((n = !1), (i = t.pageX), (s = t.pageY));
                                })
                                .bind("mouseup" + this.eventNamespace, function (t) {
                                    r.disabled || ((i !== t.pageX || s !== t.pageY) && (n = !0));
                                })),
                        "checkbox" === this.type
                            ? this.buttonElement.bind("click" + this.eventNamespace, function () {
                                  return r.disabled || n ? !1 : undefined;
                              })
                            : "radio" === this.type
                              ? this.buttonElement.bind("click" + this.eventNamespace, function () {
                                    if (r.disabled || n) return !1;
                                    t(this).addClass("ui-state-active"), a.buttonElement.attr("aria-pressed", "true");
                                    var e = a.element[0];
                                    l(e)
                                        .not(e)
                                        .map(function () {
                                            return t(this).button("widget")[0];
                                        })
                                        .removeClass("ui-state-active")
                                        .attr("aria-pressed", "false");
                                })
                              : (this.buttonElement
                                    .bind("mousedown" + this.eventNamespace, function () {
                                        return r.disabled
                                            ? !1
                                            : (t(this).addClass("ui-state-active"),
                                              (e = this),
                                              a.document.one("mouseup", function () {
                                                  e = null;
                                              }),
                                              undefined);
                                    })
                                    .bind("mouseup" + this.eventNamespace, function () {
                                        return r.disabled ? !1 : (t(this).removeClass("ui-state-active"), undefined);
                                    })
                                    .bind("keydown" + this.eventNamespace, function (e) {
                                        return r.disabled
                                            ? !1
                                            : ((e.keyCode === t.ui.keyCode.SPACE || e.keyCode === t.ui.keyCode.ENTER) &&
                                                  t(this).addClass("ui-state-active"),
                                              undefined);
                                    })
                                    .bind("keyup" + this.eventNamespace + " blur" + this.eventNamespace, function () {
                                        t(this).removeClass("ui-state-active");
                                    }),
                                this.buttonElement.is("a") &&
                                    this.buttonElement.keyup(function (e) {
                                        e.keyCode === t.ui.keyCode.SPACE && t(this).click();
                                    })),
                        this._setOption("disabled", r.disabled),
                        this._resetButton();
                },
                _determineButtonType: function () {
                    var t, e, i;
                    (this.type = this.element.is("[type=checkbox]")
                        ? "checkbox"
                        : this.element.is("[type=radio]")
                          ? "radio"
                          : this.element.is("input")
                            ? "input"
                            : "button"),
                        "checkbox" === this.type || "radio" === this.type
                            ? ((t = this.element.parents().last()),
                              (e = "label[for='" + this.element.attr("id") + "']"),
                              (this.buttonElement = t.find(e)),
                              this.buttonElement.length ||
                                  ((t = t.length ? t.siblings() : this.element.siblings()),
                                  (this.buttonElement = t.filter(e)),
                                  this.buttonElement.length || (this.buttonElement = t.find(e))),
                              this.element.addClass("ui-helper-hidden-accessible"),
                              (i = this.element.is(":checked")),
                              i && this.buttonElement.addClass("ui-state-active"),
                              this.buttonElement.prop("aria-pressed", i))
                            : (this.buttonElement = this.element);
                },
                widget: function () {
                    return this.buttonElement;
                },
                _destroy: function () {
                    this.element.removeClass("ui-helper-hidden-accessible"),
                        this.buttonElement
                            .removeClass(o + " " + a + " " + r)
                            .removeAttr("role")
                            .removeAttr("aria-pressed")
                            .html(this.buttonElement.find(".ui-button-text").html()),
                        this.hasTitle || this.buttonElement.removeAttr("title");
                },
                _setOption: function (t, e) {
                    return (
                        this._super(t, e),
                        "disabled" === t
                            ? (e ? this.element.prop("disabled", !0) : this.element.prop("disabled", !1), undefined)
                            : (this._resetButton(), undefined)
                    );
                },
                refresh: function () {
                    var e = this.element.is("input, button")
                        ? this.element.is(":disabled")
                        : this.element.hasClass("ui-button-disabled");
                    e !== this.options.disabled && this._setOption("disabled", e),
                        "radio" === this.type
                            ? l(this.element[0]).each(function () {
                                  t(this).is(":checked")
                                      ? t(this)
                                            .button("widget")
                                            .addClass("ui-state-active")
                                            .attr("aria-pressed", "true")
                                      : t(this)
                                            .button("widget")
                                            .removeClass("ui-state-active")
                                            .attr("aria-pressed", "false");
                              })
                            : "checkbox" === this.type &&
                              (this.element.is(":checked")
                                  ? this.buttonElement.addClass("ui-state-active").attr("aria-pressed", "true")
                                  : this.buttonElement.removeClass("ui-state-active").attr("aria-pressed", "false"));
                },
                _resetButton: function () {
                    if ("input" === this.type)
                        return this.options.label && this.element.val(this.options.label), undefined;
                    var e = this.buttonElement.removeClass(r),
                        i = t("<span></span>", this.document[0])
                            .addClass("ui-button-text")
                            .html(this.options.label)
                            .appendTo(e.empty())
                            .text(),
                        s = this.options.icons,
                        n = s.primary && s.secondary,
                        o = [];
                    s.primary || s.secondary
                        ? (this.options.text &&
                              o.push("ui-button-text-icon" + (n ? "s" : s.primary ? "-primary" : "-secondary")),
                          s.primary &&
                              e.prepend("<span class='ui-button-icon-primary ui-icon " + s.primary + "'></span>"),
                          s.secondary &&
                              e.append("<span class='ui-button-icon-secondary ui-icon " + s.secondary + "'></span>"),
                          this.options.text ||
                              (o.push(n ? "ui-button-icons-only" : "ui-button-icon-only"),
                              this.hasTitle || e.attr("title", t.trim(i))))
                        : o.push("ui-button-text-only"),
                        e.addClass(o.join(" "));
                },
            }),
                t.widget("ui.buttonset", {
                    version: "1.10.2",
                    options: {
                        items: "button, input[type=button], input[type=submit], input[type=reset], input[type=checkbox], input[type=radio], a, :data(ui-button)",
                    },
                    _create: function () {
                        this.element.addClass("ui-buttonset");
                    },
                    _init: function () {
                        this.refresh();
                    },
                    _setOption: function (t, e) {
                        "disabled" === t && this.buttons.button("option", t, e), this._super(t, e);
                    },
                    refresh: function () {
                        var e = "rtl" === this.element.css("direction");
                        this.buttons = this.element
                            .find(this.options.items)
                            .filter(":ui-button")
                            .button("refresh")
                            .end()
                            .not(":ui-button")
                            .button()
                            .end()
                            .map(function () {
                                return t(this).button("widget")[0];
                            })
                            .removeClass("ui-corner-all ui-corner-left ui-corner-right")
                            .filter(":first")
                            .addClass(e ? "ui-corner-right" : "ui-corner-left")
                            .end()
                            .filter(":last")
                            .addClass(e ? "ui-corner-left" : "ui-corner-right")
                            .end()
                            .end();
                    },
                    _destroy: function () {
                        this.element.removeClass("ui-buttonset"),
                            this.buttons
                                .map(function () {
                                    return t(this).button("widget")[0];
                                })
                                .removeClass("ui-corner-left ui-corner-right")
                                .end()
                                .button("destroy");
                    },
                });
        })(jQuery),
        (function (t, e) {
            function i() {
                (this._curInst = null),
                    (this._keyEvent = !1),
                    (this._disabledInputs = []),
                    (this._datepickerShowing = !1),
                    (this._inDialog = !1),
                    (this._mainDivId = "ui-datepicker-div"),
                    (this._inlineClass = "ui-datepicker-inline"),
                    (this._appendClass = "ui-datepicker-append"),
                    (this._triggerClass = "ui-datepicker-trigger"),
                    (this._dialogClass = "ui-datepicker-dialog"),
                    (this._disableClass = "ui-datepicker-disabled"),
                    (this._unselectableClass = "ui-datepicker-unselectable"),
                    (this._currentClass = "ui-datepicker-current-day"),
                    (this._dayOverClass = "ui-datepicker-days-cell-over"),
                    (this.regional = []),
                    (this.regional[""] = {
                        closeText: "Done",
                        prevText: "Prev",
                        nextText: "Next",
                        currentText: "Today",
                        monthNames: [
                            "January",
                            "February",
                            "March",
                            "April",
                            "May",
                            "June",
                            "July",
                            "August",
                            "September",
                            "October",
                            "November",
                            "December",
                        ],
                        monthNamesShort: [
                            "Jan",
                            "Feb",
                            "Mar",
                            "Apr",
                            "May",
                            "Jun",
                            "Jul",
                            "Aug",
                            "Sep",
                            "Oct",
                            "Nov",
                            "Dec",
                        ],
                        dayNames: ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"],
                        dayNamesShort: ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"],
                        dayNamesMin: ["Su", "Mo", "Tu", "We", "Th", "Fr", "Sa"],
                        weekHeader: "Wk",
                        dateFormat: "mm/dd/yy",
                        firstDay: 0,
                        isRTL: !1,
                        showMonthAfterYear: !1,
                        yearSuffix: "",
                    }),
                    (this._defaults = {
                        showOn: "focus",
                        showAnim: "fadeIn",
                        showOptions: {},
                        defaultDate: null,
                        appendText: "",
                        buttonText: "...",
                        buttonImage: "",
                        buttonImageOnly: !1,
                        hideIfNoPrevNext: !1,
                        navigationAsDateFormat: !1,
                        gotoCurrent: !1,
                        changeMonth: !1,
                        changeYear: !1,
                        yearRange: "c-10:c+10",
                        showOtherMonths: !1,
                        selectOtherMonths: !1,
                        showWeek: !1,
                        calculateWeek: this.iso8601Week,
                        shortYearCutoff: "+10",
                        minDate: null,
                        maxDate: null,
                        duration: "fast",
                        beforeShowDay: null,
                        beforeShow: null,
                        onSelect: null,
                        onChangeMonthYear: null,
                        onClose: null,
                        numberOfMonths: 1,
                        showCurrentAtPos: 0,
                        stepMonths: 1,
                        stepBigMonths: 12,
                        altField: "",
                        altFormat: "",
                        constrainInput: !0,
                        showButtonPanel: !1,
                        autoSize: !1,
                        disabled: !1,
                    }),
                    t.extend(this._defaults, this.regional[""]),
                    (this.dpDiv = s(
                        t(
                            "<div id='" +
                                this._mainDivId +
                                "' class='ui-datepicker ui-widget ui-widget-content ui-helper-clearfix ui-corner-all'></div>"
                        )
                    ));
            }
            function s(e) {
                var i = "button, .ui-datepicker-prev, .ui-datepicker-next, .ui-datepicker-calendar td a";
                return e
                    .delegate(i, "mouseout", function () {
                        t(this).removeClass("ui-state-hover"),
                            -1 !== this.className.indexOf("ui-datepicker-prev") &&
                                t(this).removeClass("ui-datepicker-prev-hover"),
                            -1 !== this.className.indexOf("ui-datepicker-next") &&
                                t(this).removeClass("ui-datepicker-next-hover");
                    })
                    .delegate(i, "mouseover", function () {
                        t.datepicker._isDisabledDatepicker(o.inline ? e.parent()[0] : o.input[0]) ||
                            (t(this).parents(".ui-datepicker-calendar").find("a").removeClass("ui-state-hover"),
                            t(this).addClass("ui-state-hover"),
                            -1 !== this.className.indexOf("ui-datepicker-prev") &&
                                t(this).addClass("ui-datepicker-prev-hover"),
                            -1 !== this.className.indexOf("ui-datepicker-next") &&
                                t(this).addClass("ui-datepicker-next-hover"));
                    });
            }
            function n(e, i) {
                t.extend(e, i);
                for (var s in i) null == i[s] && (e[s] = i[s]);
                return e;
            }
            t.extend(t.ui, { datepicker: { version: "1.10.2" } });
            var o,
                a = "datepicker",
                r = new Date().getTime();
            t.extend(i.prototype, {
                markerClassName: "hasDatepicker",
                maxRows: 4,
                _widgetDatepicker: function () {
                    return this.dpDiv;
                },
                setDefaults: function (t) {
                    return n(this._defaults, t || {}), this;
                },
                _attachDatepicker: function (e, i) {
                    var s, n, o;
                    (s = e.nodeName.toLowerCase()),
                        (n = "div" === s || "span" === s),
                        e.id || ((this.uuid += 1), (e.id = "dp" + this.uuid)),
                        (o = this._newInst(t(e), n)),
                        (o.settings = t.extend({}, i || {})),
                        "input" === s ? this._connectDatepicker(e, o) : n && this._inlineDatepicker(e, o);
                },
                _newInst: function (e, i) {
                    var n = e[0].id.replace(/([^A-Za-z0-9_\-])/g, "\\\\$1");
                    return {
                        id: n,
                        input: e,
                        selectedDay: 0,
                        selectedMonth: 0,
                        selectedYear: 0,
                        drawMonth: 0,
                        drawYear: 0,
                        inline: i,
                        dpDiv: i
                            ? s(
                                  t(
                                      "<div class='" +
                                          this._inlineClass +
                                          " ui-datepicker ui-widget ui-widget-content ui-helper-clearfix ui-corner-all'></div>"
                                  )
                              )
                            : this.dpDiv,
                    };
                },
                _connectDatepicker: function (e, i) {
                    var s = t(e);
                    (i.append = t([])),
                        (i.trigger = t([])),
                        s.hasClass(this.markerClassName) ||
                            (this._attachments(s, i),
                            s
                                .addClass(this.markerClassName)
                                .keydown(this._doKeyDown)
                                .keypress(this._doKeyPress)
                                .keyup(this._doKeyUp),
                            this._autoSize(i),
                            t.data(e, a, i),
                            i.settings.disabled && this._disableDatepicker(e));
                },
                _attachments: function (e, i) {
                    var s,
                        n,
                        o,
                        a = this._get(i, "appendText"),
                        r = this._get(i, "isRTL");
                    i.append && i.append.remove(),
                        a &&
                            ((i.append = t("<span class='" + this._appendClass + "'>" + a + "</span>")),
                            e[r ? "before" : "after"](i.append)),
                        e.unbind("focus", this._showDatepicker),
                        i.trigger && i.trigger.remove(),
                        (s = this._get(i, "showOn")),
                        ("focus" === s || "both" === s) && e.focus(this._showDatepicker),
                        ("button" === s || "both" === s) &&
                            ((n = this._get(i, "buttonText")),
                            (o = this._get(i, "buttonImage")),
                            (i.trigger = t(
                                this._get(i, "buttonImageOnly")
                                    ? t("<img/>").addClass(this._triggerClass).attr({ src: o, alt: n, title: n })
                                    : t("<button type='button'></button>")
                                          .addClass(this._triggerClass)
                                          .html(o ? t("<img/>").attr({ src: o, alt: n, title: n }) : n)
                            )),
                            e[r ? "before" : "after"](i.trigger),
                            i.trigger.click(function () {
                                return (
                                    t.datepicker._datepickerShowing && t.datepicker._lastInput === e[0]
                                        ? t.datepicker._hideDatepicker()
                                        : t.datepicker._datepickerShowing && t.datepicker._lastInput !== e[0]
                                          ? (t.datepicker._hideDatepicker(), t.datepicker._showDatepicker(e[0]))
                                          : t.datepicker._showDatepicker(e[0]),
                                    !1
                                );
                            }));
                },
                _autoSize: function (t) {
                    if (this._get(t, "autoSize") && !t.inline) {
                        var e,
                            i,
                            s,
                            n,
                            o = new Date(2009, 11, 20),
                            a = this._get(t, "dateFormat");
                        a.match(/[DM]/) &&
                            ((e = function (t) {
                                for (i = 0, s = 0, n = 0; t.length > n; n++)
                                    t[n].length > i && ((i = t[n].length), (s = n));
                                return s;
                            }),
                            o.setMonth(e(this._get(t, a.match(/MM/) ? "monthNames" : "monthNamesShort"))),
                            o.setDate(e(this._get(t, a.match(/DD/) ? "dayNames" : "dayNamesShort")) + 20 - o.getDay())),
                            t.input.attr("size", this._formatDate(t, o).length);
                    }
                },
                _inlineDatepicker: function (e, i) {
                    var s = t(e);
                    s.hasClass(this.markerClassName) ||
                        (s.addClass(this.markerClassName).append(i.dpDiv),
                        t.data(e, a, i),
                        this._setDate(i, this._getDefaultDate(i), !0),
                        this._updateDatepicker(i),
                        this._updateAlternate(i),
                        i.settings.disabled && this._disableDatepicker(e),
                        i.dpDiv.css("display", "block"));
                },
                _dialogDatepicker: function (e, i, s, o, r) {
                    var h,
                        l,
                        c,
                        u,
                        d,
                        p = this._dialogInst;
                    return (
                        p ||
                            ((this.uuid += 1),
                            (h = "dp" + this.uuid),
                            (this._dialogInput = t(
                                "<input type='text' id='" +
                                    h +
                                    "' style='position: absolute; top: -100px; width: 0px;'/>"
                            )),
                            this._dialogInput.keydown(this._doKeyDown),
                            t("body").append(this._dialogInput),
                            (p = this._dialogInst = this._newInst(this._dialogInput, !1)),
                            (p.settings = {}),
                            t.data(this._dialogInput[0], a, p)),
                        n(p.settings, o || {}),
                        (i = i && i.constructor === Date ? this._formatDate(p, i) : i),
                        this._dialogInput.val(i),
                        (this._pos = r ? (r.length ? r : [r.pageX, r.pageY]) : null),
                        this._pos ||
                            ((l = document.documentElement.clientWidth),
                            (c = document.documentElement.clientHeight),
                            (u = document.documentElement.scrollLeft || document.body.scrollLeft),
                            (d = document.documentElement.scrollTop || document.body.scrollTop),
                            (this._pos = [l / 2 - 100 + u, c / 2 - 150 + d])),
                        this._dialogInput.css("left", this._pos[0] + 20 + "px").css("top", this._pos[1] + "px"),
                        (p.settings.onSelect = s),
                        (this._inDialog = !0),
                        this.dpDiv.addClass(this._dialogClass),
                        this._showDatepicker(this._dialogInput[0]),
                        t.blockUI && t.blockUI(this.dpDiv),
                        t.data(this._dialogInput[0], a, p),
                        this
                    );
                },
                _destroyDatepicker: function (e) {
                    var i,
                        s = t(e),
                        n = t.data(e, a);
                    s.hasClass(this.markerClassName) &&
                        ((i = e.nodeName.toLowerCase()),
                        t.removeData(e, a),
                        "input" === i
                            ? (n.append.remove(),
                              n.trigger.remove(),
                              s
                                  .removeClass(this.markerClassName)
                                  .unbind("focus", this._showDatepicker)
                                  .unbind("keydown", this._doKeyDown)
                                  .unbind("keypress", this._doKeyPress)
                                  .unbind("keyup", this._doKeyUp))
                            : ("div" === i || "span" === i) && s.removeClass(this.markerClassName).empty());
                },
                _enableDatepicker: function (e) {
                    var i,
                        s,
                        n = t(e),
                        o = t.data(e, a);
                    n.hasClass(this.markerClassName) &&
                        ((i = e.nodeName.toLowerCase()),
                        "input" === i
                            ? ((e.disabled = !1),
                              o.trigger
                                  .filter("button")
                                  .each(function () {
                                      this.disabled = !1;
                                  })
                                  .end()
                                  .filter("img")
                                  .css({ opacity: "1.0", cursor: "" }))
                            : ("div" === i || "span" === i) &&
                              ((s = n.children("." + this._inlineClass)),
                              s.children().removeClass("ui-state-disabled"),
                              s.find("select.ui-datepicker-month, select.ui-datepicker-year").prop("disabled", !1)),
                        (this._disabledInputs = t.map(this._disabledInputs, function (t) {
                            return t === e ? null : t;
                        })));
                },
                _disableDatepicker: function (e) {
                    var i,
                        s,
                        n = t(e),
                        o = t.data(e, a);
                    n.hasClass(this.markerClassName) &&
                        ((i = e.nodeName.toLowerCase()),
                        "input" === i
                            ? ((e.disabled = !0),
                              o.trigger
                                  .filter("button")
                                  .each(function () {
                                      this.disabled = !0;
                                  })
                                  .end()
                                  .filter("img")
                                  .css({ opacity: "0.5", cursor: "default" }))
                            : ("div" === i || "span" === i) &&
                              ((s = n.children("." + this._inlineClass)),
                              s.children().addClass("ui-state-disabled"),
                              s.find("select.ui-datepicker-month, select.ui-datepicker-year").prop("disabled", !0)),
                        (this._disabledInputs = t.map(this._disabledInputs, function (t) {
                            return t === e ? null : t;
                        })),
                        (this._disabledInputs[this._disabledInputs.length] = e));
                },
                _isDisabledDatepicker: function (t) {
                    if (!t) return !1;
                    for (var e = 0; this._disabledInputs.length > e; e++) if (this._disabledInputs[e] === t) return !0;
                    return !1;
                },
                _getInst: function (e) {
                    try {
                        return t.data(e, a);
                    } catch (i) {
                        throw "Missing instance data for this datepicker";
                    }
                },
                _optionDatepicker: function (i, s, o) {
                    var a,
                        r,
                        h,
                        l,
                        c = this._getInst(i);
                    return 2 === arguments.length && "string" == typeof s
                        ? "defaults" === s
                            ? t.extend({}, t.datepicker._defaults)
                            : c
                              ? "all" === s
                                  ? t.extend({}, c.settings)
                                  : this._get(c, s)
                              : null
                        : ((a = s || {}),
                          "string" == typeof s && ((a = {}), (a[s] = o)),
                          c &&
                              (this._curInst === c && this._hideDatepicker(),
                              (r = this._getDateDatepicker(i, !0)),
                              (h = this._getMinMaxDate(c, "min")),
                              (l = this._getMinMaxDate(c, "max")),
                              n(c.settings, a),
                              null !== h &&
                                  a.dateFormat !== e &&
                                  a.minDate === e &&
                                  (c.settings.minDate = this._formatDate(c, h)),
                              null !== l &&
                                  a.dateFormat !== e &&
                                  a.maxDate === e &&
                                  (c.settings.maxDate = this._formatDate(c, l)),
                              "disabled" in a && (a.disabled ? this._disableDatepicker(i) : this._enableDatepicker(i)),
                              this._attachments(t(i), c),
                              this._autoSize(c),
                              this._setDate(c, r),
                              this._updateAlternate(c),
                              this._updateDatepicker(c)),
                          e);
                },
                _changeDatepicker: function (t, e, i) {
                    this._optionDatepicker(t, e, i);
                },
                _refreshDatepicker: function (t) {
                    var e = this._getInst(t);
                    e && this._updateDatepicker(e);
                },
                _setDateDatepicker: function (t, e) {
                    var i = this._getInst(t);
                    i && (this._setDate(i, e), this._updateDatepicker(i), this._updateAlternate(i));
                },
                _getDateDatepicker: function (t, e) {
                    var i = this._getInst(t);
                    return i && !i.inline && this._setDateFromField(i, e), i ? this._getDate(i) : null;
                },
                _doKeyDown: function (e) {
                    var i,
                        s,
                        n,
                        o = t.datepicker._getInst(e.target),
                        a = !0,
                        r = o.dpDiv.is(".ui-datepicker-rtl");
                    if (((o._keyEvent = !0), t.datepicker._datepickerShowing))
                        switch (e.keyCode) {
                            case 9:
                                t.datepicker._hideDatepicker(), (a = !1);
                                break;
                            case 13:
                                return (
                                    (n = t(
                                        "td." +
                                            t.datepicker._dayOverClass +
                                            ":not(." +
                                            t.datepicker._currentClass +
                                            ")",
                                        o.dpDiv
                                    )),
                                    n[0] && t.datepicker._selectDay(e.target, o.selectedMonth, o.selectedYear, n[0]),
                                    (i = t.datepicker._get(o, "onSelect")),
                                    i
                                        ? ((s = t.datepicker._formatDate(o)),
                                          i.apply(o.input ? o.input[0] : null, [s, o]))
                                        : t.datepicker._hideDatepicker(),
                                    !1
                                );
                            case 27:
                                t.datepicker._hideDatepicker();
                                break;
                            case 33:
                                t.datepicker._adjustDate(
                                    e.target,
                                    e.ctrlKey
                                        ? -t.datepicker._get(o, "stepBigMonths")
                                        : -t.datepicker._get(o, "stepMonths"),
                                    "M"
                                );
                                break;
                            case 34:
                                t.datepicker._adjustDate(
                                    e.target,
                                    e.ctrlKey
                                        ? +t.datepicker._get(o, "stepBigMonths")
                                        : +t.datepicker._get(o, "stepMonths"),
                                    "M"
                                );
                                break;
                            case 35:
                                (e.ctrlKey || e.metaKey) && t.datepicker._clearDate(e.target),
                                    (a = e.ctrlKey || e.metaKey);
                                break;
                            case 36:
                                (e.ctrlKey || e.metaKey) && t.datepicker._gotoToday(e.target),
                                    (a = e.ctrlKey || e.metaKey);
                                break;
                            case 37:
                                (e.ctrlKey || e.metaKey) && t.datepicker._adjustDate(e.target, r ? 1 : -1, "D"),
                                    (a = e.ctrlKey || e.metaKey),
                                    e.originalEvent.altKey &&
                                        t.datepicker._adjustDate(
                                            e.target,
                                            e.ctrlKey
                                                ? -t.datepicker._get(o, "stepBigMonths")
                                                : -t.datepicker._get(o, "stepMonths"),
                                            "M"
                                        );
                                break;
                            case 38:
                                (e.ctrlKey || e.metaKey) && t.datepicker._adjustDate(e.target, -7, "D"),
                                    (a = e.ctrlKey || e.metaKey);
                                break;
                            case 39:
                                (e.ctrlKey || e.metaKey) && t.datepicker._adjustDate(e.target, r ? -1 : 1, "D"),
                                    (a = e.ctrlKey || e.metaKey),
                                    e.originalEvent.altKey &&
                                        t.datepicker._adjustDate(
                                            e.target,
                                            e.ctrlKey
                                                ? +t.datepicker._get(o, "stepBigMonths")
                                                : +t.datepicker._get(o, "stepMonths"),
                                            "M"
                                        );
                                break;
                            case 40:
                                (e.ctrlKey || e.metaKey) && t.datepicker._adjustDate(e.target, 7, "D"),
                                    (a = e.ctrlKey || e.metaKey);
                                break;
                            default:
                                a = !1;
                        }
                    else 36 === e.keyCode && e.ctrlKey ? t.datepicker._showDatepicker(this) : (a = !1);
                    a && (e.preventDefault(), e.stopPropagation());
                },
                _doKeyPress: function (i) {
                    var s,
                        n,
                        o = t.datepicker._getInst(i.target);
                    return t.datepicker._get(o, "constrainInput")
                        ? ((s = t.datepicker._possibleChars(t.datepicker._get(o, "dateFormat"))),
                          (n = String.fromCharCode(null == i.charCode ? i.keyCode : i.charCode)),
                          i.ctrlKey || i.metaKey || " " > n || !s || s.indexOf(n) > -1)
                        : e;
                },
                _doKeyUp: function (e) {
                    var i,
                        s = t.datepicker._getInst(e.target);
                    if (s.input.val() !== s.lastVal)
                        try {
                            (i = t.datepicker.parseDate(
                                t.datepicker._get(s, "dateFormat"),
                                s.input ? s.input.val() : null,
                                t.datepicker._getFormatConfig(s)
                            )),
                                i &&
                                    (t.datepicker._setDateFromField(s),
                                    t.datepicker._updateAlternate(s),
                                    t.datepicker._updateDatepicker(s));
                        } catch (n) {}
                    return !0;
                },
                _showDatepicker: function (e) {
                    if (
                        ((e = e.target || e),
                        "input" !== e.nodeName.toLowerCase() && (e = t("input", e.parentNode)[0]),
                        !t.datepicker._isDisabledDatepicker(e) && t.datepicker._lastInput !== e)
                    ) {
                        var i, s, o, a, r, h, l;
                        (i = t.datepicker._getInst(e)),
                            t.datepicker._curInst &&
                                t.datepicker._curInst !== i &&
                                (t.datepicker._curInst.dpDiv.stop(!0, !0),
                                i &&
                                    t.datepicker._datepickerShowing &&
                                    t.datepicker._hideDatepicker(t.datepicker._curInst.input[0])),
                            (s = t.datepicker._get(i, "beforeShow")),
                            (o = s ? s.apply(e, [e, i]) : {}),
                            o !== !1 &&
                                (n(i.settings, o),
                                (i.lastVal = null),
                                (t.datepicker._lastInput = e),
                                t.datepicker._setDateFromField(i),
                                t.datepicker._inDialog && (e.value = ""),
                                t.datepicker._pos ||
                                    ((t.datepicker._pos = t.datepicker._findPos(e)),
                                    (t.datepicker._pos[1] += e.offsetHeight)),
                                (a = !1),
                                t(e)
                                    .parents()
                                    .each(function () {
                                        return (a |= "fixed" === t(this).css("position")), !a;
                                    }),
                                (r = { left: t.datepicker._pos[0], top: t.datepicker._pos[1] }),
                                (t.datepicker._pos = null),
                                i.dpDiv.empty(),
                                i.dpDiv.css({ position: "absolute", display: "block", top: "-1000px" }),
                                t.datepicker._updateDatepicker(i),
                                (r = t.datepicker._checkOffset(i, r, a)),
                                i.dpDiv.css({
                                    position: t.datepicker._inDialog && t.blockUI ? "static" : a ? "fixed" : "absolute",
                                    display: "none",
                                    left: r.left + "px",
                                    top: r.top + "px",
                                }),
                                i.inline ||
                                    ((h = t.datepicker._get(i, "showAnim")),
                                    (l = t.datepicker._get(i, "duration")),
                                    i.dpDiv.zIndex(t(e).zIndex() + 1),
                                    (t.datepicker._datepickerShowing = !0),
                                    t.effects && t.effects.effect[h]
                                        ? i.dpDiv.show(h, t.datepicker._get(i, "showOptions"), l)
                                        : i.dpDiv[h || "show"](h ? l : null),
                                    i.input.is(":visible") && !i.input.is(":disabled") && i.input.focus(),
                                    (t.datepicker._curInst = i)));
                    }
                },
                _updateDatepicker: function (e) {
                    (this.maxRows = 4),
                        (o = e),
                        e.dpDiv.empty().append(this._generateHTML(e)),
                        this._attachHandlers(e),
                        e.dpDiv.find("." + this._dayOverClass + " a").mouseover();
                    var i,
                        s = this._getNumberOfMonths(e),
                        n = s[1],
                        a = 17;
                    e.dpDiv.removeClass("ui-datepicker-multi-2 ui-datepicker-multi-3 ui-datepicker-multi-4").width(""),
                        n > 1 && e.dpDiv.addClass("ui-datepicker-multi-" + n).css("width", a * n + "em"),
                        e.dpDiv[(1 !== s[0] || 1 !== s[1] ? "add" : "remove") + "Class"]("ui-datepicker-multi"),
                        e.dpDiv[(this._get(e, "isRTL") ? "add" : "remove") + "Class"]("ui-datepicker-rtl"),
                        e === t.datepicker._curInst &&
                            t.datepicker._datepickerShowing &&
                            e.input &&
                            e.input.is(":visible") &&
                            !e.input.is(":disabled") &&
                            e.input[0] !== document.activeElement &&
                            e.input.focus(),
                        e.yearshtml &&
                            ((i = e.yearshtml),
                            setTimeout(function () {
                                i === e.yearshtml &&
                                    e.yearshtml &&
                                    e.dpDiv.find("select.ui-datepicker-year:first").replaceWith(e.yearshtml),
                                    (i = e.yearshtml = null);
                            }, 0));
                },
                _getBorders: function (t) {
                    var e = function (t) {
                        return { thin: 1, medium: 2, thick: 3 }[t] || t;
                    };
                    return [parseFloat(e(t.css("border-left-width"))), parseFloat(e(t.css("border-top-width")))];
                },
                _checkOffset: function (e, i, s) {
                    var n = e.dpDiv.outerWidth(),
                        o = e.dpDiv.outerHeight(),
                        a = e.input ? e.input.outerWidth() : 0,
                        r = e.input ? e.input.outerHeight() : 0,
                        h = document.documentElement.clientWidth + (s ? 0 : t(document).scrollLeft()),
                        l = document.documentElement.clientHeight + (s ? 0 : t(document).scrollTop());
                    return (
                        (i.left -= this._get(e, "isRTL") ? n - a : 0),
                        (i.left -= s && i.left === e.input.offset().left ? t(document).scrollLeft() : 0),
                        (i.top -= s && i.top === e.input.offset().top + r ? t(document).scrollTop() : 0),
                        (i.left -= Math.min(i.left, i.left + n > h && h > n ? Math.abs(i.left + n - h) : 0)),
                        (i.top -= Math.min(i.top, i.top + o > l && l > o ? Math.abs(o + r) : 0)),
                        i
                    );
                },
                _findPos: function (e) {
                    for (
                        var i, s = this._getInst(e), n = this._get(s, "isRTL");
                        e && ("hidden" === e.type || 1 !== e.nodeType || t.expr.filters.hidden(e));

                    )
                        e = e[n ? "previousSibling" : "nextSibling"];
                    return (i = t(e).offset()), [i.left, i.top];
                },
                _hideDatepicker: function (e) {
                    var i,
                        s,
                        n,
                        o,
                        r = this._curInst;
                    !r ||
                        (e && r !== t.data(e, a)) ||
                        (this._datepickerShowing &&
                            ((i = this._get(r, "showAnim")),
                            (s = this._get(r, "duration")),
                            (n = function () {
                                t.datepicker._tidyDialog(r);
                            }),
                            t.effects && (t.effects.effect[i] || t.effects[i])
                                ? r.dpDiv.hide(i, t.datepicker._get(r, "showOptions"), s, n)
                                : r.dpDiv["slideDown" === i ? "slideUp" : "fadeIn" === i ? "fadeOut" : "hide"](
                                      i ? s : null,
                                      n
                                  ),
                            i || n(),
                            (this._datepickerShowing = !1),
                            (o = this._get(r, "onClose")),
                            o && o.apply(r.input ? r.input[0] : null, [r.input ? r.input.val() : "", r]),
                            (this._lastInput = null),
                            this._inDialog &&
                                (this._dialogInput.css({ position: "absolute", left: "0", top: "-100px" }),
                                t.blockUI && (t.unblockUI(), t("body").append(this.dpDiv))),
                            (this._inDialog = !1)));
                },
                _tidyDialog: function (t) {
                    t.dpDiv.removeClass(this._dialogClass).unbind(".ui-datepicker-calendar");
                },
                _checkExternalClick: function (e) {
                    if (t.datepicker._curInst) {
                        var i = t(e.target),
                            s = t.datepicker._getInst(i[0]);
                        ((i[0].id !== t.datepicker._mainDivId &&
                            0 === i.parents("#" + t.datepicker._mainDivId).length &&
                            !i.hasClass(t.datepicker.markerClassName) &&
                            !i.closest("." + t.datepicker._triggerClass).length &&
                            t.datepicker._datepickerShowing &&
                            (!t.datepicker._inDialog || !t.blockUI)) ||
                            (i.hasClass(t.datepicker.markerClassName) && t.datepicker._curInst !== s)) &&
                            t.datepicker._hideDatepicker();
                    }
                },
                _adjustDate: function (e, i, s) {
                    var n = t(e),
                        o = this._getInst(n[0]);
                    this._isDisabledDatepicker(n[0]) ||
                        (this._adjustInstDate(o, i + ("M" === s ? this._get(o, "showCurrentAtPos") : 0), s),
                        this._updateDatepicker(o));
                },
                _gotoToday: function (e) {
                    var i,
                        s = t(e),
                        n = this._getInst(s[0]);
                    this._get(n, "gotoCurrent") && n.currentDay
                        ? ((n.selectedDay = n.currentDay),
                          (n.drawMonth = n.selectedMonth = n.currentMonth),
                          (n.drawYear = n.selectedYear = n.currentYear))
                        : ((i = new Date()),
                          (n.selectedDay = i.getDate()),
                          (n.drawMonth = n.selectedMonth = i.getMonth()),
                          (n.drawYear = n.selectedYear = i.getFullYear())),
                        this._notifyChange(n),
                        this._adjustDate(s);
                },
                _selectMonthYear: function (e, i, s) {
                    var n = t(e),
                        o = this._getInst(n[0]);
                    (o["selected" + ("M" === s ? "Month" : "Year")] = o["draw" + ("M" === s ? "Month" : "Year")] =
                        parseInt(i.options[i.selectedIndex].value, 10)),
                        this._notifyChange(o),
                        this._adjustDate(n);
                },
                _selectDay: function (e, i, s, n) {
                    var o,
                        a = t(e);
                    t(n).hasClass(this._unselectableClass) ||
                        this._isDisabledDatepicker(a[0]) ||
                        ((o = this._getInst(a[0])),
                        (o.selectedDay = o.currentDay = t("a", n).html()),
                        (o.selectedMonth = o.currentMonth = i),
                        (o.selectedYear = o.currentYear = s),
                        this._selectDate(e, this._formatDate(o, o.currentDay, o.currentMonth, o.currentYear)));
                },
                _clearDate: function (e) {
                    var i = t(e);
                    this._selectDate(i, "");
                },
                _selectDate: function (e, i) {
                    var s,
                        n = t(e),
                        o = this._getInst(n[0]);
                    (i = null != i ? i : this._formatDate(o)),
                        o.input && o.input.val(i),
                        this._updateAlternate(o),
                        (s = this._get(o, "onSelect")),
                        s ? s.apply(o.input ? o.input[0] : null, [i, o]) : o.input && o.input.trigger("change"),
                        o.inline
                            ? this._updateDatepicker(o)
                            : (this._hideDatepicker(),
                              (this._lastInput = o.input[0]),
                              "object" != typeof o.input[0] && o.input.focus(),
                              (this._lastInput = null));
                },
                _updateAlternate: function (e) {
                    var i,
                        s,
                        n,
                        o = this._get(e, "altField");
                    o &&
                        ((i = this._get(e, "altFormat") || this._get(e, "dateFormat")),
                        (s = this._getDate(e)),
                        (n = this.formatDate(i, s, this._getFormatConfig(e))),
                        t(o).each(function () {
                            t(this).val(n);
                        }));
                },
                noWeekends: function (t) {
                    var e = t.getDay();
                    return [e > 0 && 6 > e, ""];
                },
                iso8601Week: function (t) {
                    var e,
                        i = new Date(t.getTime());
                    return (
                        i.setDate(i.getDate() + 4 - (i.getDay() || 7)),
                        (e = i.getTime()),
                        i.setMonth(0),
                        i.setDate(1),
                        Math.floor(Math.round((e - i) / 864e5) / 7) + 1
                    );
                },
                parseDate: function (i, s, n) {
                    if (null == i || null == s) throw "Invalid arguments";
                    if (((s = "object" == typeof s ? "" + s : s + ""), "" === s)) return null;
                    var o,
                        a,
                        r,
                        h,
                        l = 0,
                        c = (n ? n.shortYearCutoff : null) || this._defaults.shortYearCutoff,
                        u = "string" != typeof c ? c : (new Date().getFullYear() % 100) + parseInt(c, 10),
                        d = (n ? n.dayNamesShort : null) || this._defaults.dayNamesShort,
                        p = (n ? n.dayNames : null) || this._defaults.dayNames,
                        f = (n ? n.monthNamesShort : null) || this._defaults.monthNamesShort,
                        g = (n ? n.monthNames : null) || this._defaults.monthNames,
                        m = -1,
                        v = -1,
                        _ = -1,
                        b = -1,
                        y = !1,
                        w = function (t) {
                            var e = i.length > o + 1 && i.charAt(o + 1) === t;
                            return e && o++, e;
                        },
                        k = function (t) {
                            var e = w(t),
                                i = "@" === t ? 14 : "!" === t ? 20 : "y" === t && e ? 4 : "o" === t ? 3 : 2,
                                n = RegExp("^\\d{1," + i + "}"),
                                o = s.substring(l).match(n);
                            if (!o) throw "Missing number at position " + l;
                            return (l += o[0].length), parseInt(o[0], 10);
                        },
                        x = function (i, n, o) {
                            var a = -1,
                                r = t
                                    .map(w(i) ? o : n, function (t, e) {
                                        return [[e, t]];
                                    })
                                    .sort(function (t, e) {
                                        return -(t[1].length - e[1].length);
                                    });
                            if (
                                (t.each(r, function (t, i) {
                                    var n = i[1];
                                    return s.substr(l, n.length).toLowerCase() === n.toLowerCase()
                                        ? ((a = i[0]), (l += n.length), !1)
                                        : e;
                                }),
                                -1 !== a)
                            )
                                return a + 1;
                            throw "Unknown name at position " + l;
                        },
                        D = function () {
                            if (s.charAt(l) !== i.charAt(o)) throw "Unexpected literal at position " + l;
                            l++;
                        };
                    for (o = 0; i.length > o; o++)
                        if (y) "'" !== i.charAt(o) || w("'") ? D() : (y = !1);
                        else
                            switch (i.charAt(o)) {
                                case "d":
                                    _ = k("d");
                                    break;
                                case "D":
                                    x("D", d, p);
                                    break;
                                case "o":
                                    b = k("o");
                                    break;
                                case "m":
                                    v = k("m");
                                    break;
                                case "M":
                                    v = x("M", f, g);
                                    break;
                                case "y":
                                    m = k("y");
                                    break;
                                case "@":
                                    (h = new Date(k("@"))),
                                        (m = h.getFullYear()),
                                        (v = h.getMonth() + 1),
                                        (_ = h.getDate());
                                    break;
                                case "!":
                                    (h = new Date((k("!") - this._ticksTo1970) / 1e4)),
                                        (m = h.getFullYear()),
                                        (v = h.getMonth() + 1),
                                        (_ = h.getDate());
                                    break;
                                case "'":
                                    w("'") ? D() : (y = !0);
                                    break;
                                default:
                                    D();
                            }
                    if (s.length > l && ((r = s.substr(l)), !/^\s+/.test(r)))
                        throw "Extra/unparsed characters found in date: " + r;
                    if (
                        (-1 === m
                            ? (m = new Date().getFullYear())
                            : 100 > m &&
                              (m += new Date().getFullYear() - (new Date().getFullYear() % 100) + (u >= m ? 0 : -100)),
                        b > -1)
                    )
                        for (v = 1, _ = b; ; ) {
                            if (((a = this._getDaysInMonth(m, v - 1)), a >= _)) break;
                            v++, (_ -= a);
                        }
                    if (
                        ((h = this._daylightSavingAdjust(new Date(m, v - 1, _))),
                        h.getFullYear() !== m || h.getMonth() + 1 !== v || h.getDate() !== _)
                    )
                        throw "Invalid date";
                    return h;
                },
                ATOM: "yy-mm-dd",
                COOKIE: "D, dd M yy",
                ISO_8601: "yy-mm-dd",
                RFC_822: "D, d M y",
                RFC_850: "DD, dd-M-y",
                RFC_1036: "D, d M y",
                RFC_1123: "D, d M yy",
                RFC_2822: "D, d M yy",
                RSS: "D, d M y",
                TICKS: "!",
                TIMESTAMP: "@",
                W3C: "yy-mm-dd",
                _ticksTo1970: 1e7 * 60 * 60 * 24 * (718685 + Math.floor(492.5) - Math.floor(19.7) + Math.floor(4.925)),
                formatDate: function (t, e, i) {
                    if (!e) return "";
                    var s,
                        n = (i ? i.dayNamesShort : null) || this._defaults.dayNamesShort,
                        o = (i ? i.dayNames : null) || this._defaults.dayNames,
                        a = (i ? i.monthNamesShort : null) || this._defaults.monthNamesShort,
                        r = (i ? i.monthNames : null) || this._defaults.monthNames,
                        h = function (e) {
                            var i = t.length > s + 1 && t.charAt(s + 1) === e;
                            return i && s++, i;
                        },
                        l = function (t, e, i) {
                            var s = "" + e;
                            if (h(t)) for (; i > s.length; ) s = "0" + s;
                            return s;
                        },
                        c = function (t, e, i, s) {
                            return h(t) ? s[e] : i[e];
                        },
                        u = "",
                        d = !1;
                    if (e)
                        for (s = 0; t.length > s; s++)
                            if (d) "'" !== t.charAt(s) || h("'") ? (u += t.charAt(s)) : (d = !1);
                            else
                                switch (t.charAt(s)) {
                                    case "d":
                                        u += l("d", e.getDate(), 2);
                                        break;
                                    case "D":
                                        u += c("D", e.getDay(), n, o);
                                        break;
                                    case "o":
                                        u += l(
                                            "o",
                                            Math.round(
                                                (new Date(e.getFullYear(), e.getMonth(), e.getDate()).getTime() -
                                                    new Date(e.getFullYear(), 0, 0).getTime()) /
                                                    864e5
                                            ),
                                            3
                                        );
                                        break;
                                    case "m":
                                        u += l("m", e.getMonth() + 1, 2);
                                        break;
                                    case "M":
                                        u += c("M", e.getMonth(), a, r);
                                        break;
                                    case "y":
                                        u += h("y")
                                            ? e.getFullYear()
                                            : (10 > e.getYear() % 100 ? "0" : "") + (e.getYear() % 100);
                                        break;
                                    case "@":
                                        u += e.getTime();
                                        break;
                                    case "!":
                                        u += 1e4 * e.getTime() + this._ticksTo1970;
                                        break;
                                    case "'":
                                        h("'") ? (u += "'") : (d = !0);
                                        break;
                                    default:
                                        u += t.charAt(s);
                                }
                    return u;
                },
                _possibleChars: function (t) {
                    var e,
                        i = "",
                        s = !1,
                        n = function (i) {
                            var s = t.length > e + 1 && t.charAt(e + 1) === i;
                            return s && e++, s;
                        };
                    for (e = 0; t.length > e; e++)
                        if (s) "'" !== t.charAt(e) || n("'") ? (i += t.charAt(e)) : (s = !1);
                        else
                            switch (t.charAt(e)) {
                                case "d":
                                case "m":
                                case "y":
                                case "@":
                                    i += "0123456789";
                                    break;
                                case "D":
                                case "M":
                                    return null;
                                case "'":
                                    n("'") ? (i += "'") : (s = !0);
                                    break;
                                default:
                                    i += t.charAt(e);
                            }
                    return i;
                },
                _get: function (t, i) {
                    return t.settings[i] !== e ? t.settings[i] : this._defaults[i];
                },
                _setDateFromField: function (t, e) {
                    if (t.input.val() !== t.lastVal) {
                        var i = this._get(t, "dateFormat"),
                            s = (t.lastVal = t.input ? t.input.val() : null),
                            n = this._getDefaultDate(t),
                            o = n,
                            a = this._getFormatConfig(t);
                        try {
                            o = this.parseDate(i, s, a) || n;
                        } catch (r) {
                            s = e ? "" : s;
                        }
                        (t.selectedDay = o.getDate()),
                            (t.drawMonth = t.selectedMonth = o.getMonth()),
                            (t.drawYear = t.selectedYear = o.getFullYear()),
                            (t.currentDay = s ? o.getDate() : 0),
                            (t.currentMonth = s ? o.getMonth() : 0),
                            (t.currentYear = s ? o.getFullYear() : 0),
                            this._adjustInstDate(t);
                    }
                },
                _getDefaultDate: function (t) {
                    return this._restrictMinMax(t, this._determineDate(t, this._get(t, "defaultDate"), new Date()));
                },
                _determineDate: function (e, i, s) {
                    var n = function (t) {
                            var e = new Date();
                            return e.setDate(e.getDate() + t), e;
                        },
                        o = function (i) {
                            try {
                                return t.datepicker.parseDate(
                                    t.datepicker._get(e, "dateFormat"),
                                    i,
                                    t.datepicker._getFormatConfig(e)
                                );
                            } catch (s) {}
                            for (
                                var n = (i.toLowerCase().match(/^c/) ? t.datepicker._getDate(e) : null) || new Date(),
                                    o = n.getFullYear(),
                                    a = n.getMonth(),
                                    r = n.getDate(),
                                    h = /([+\-]?[0-9]+)\s*(d|D|w|W|m|M|y|Y)?/g,
                                    l = h.exec(i);
                                l;

                            ) {
                                switch (l[2] || "d") {
                                    case "d":
                                    case "D":
                                        r += parseInt(l[1], 10);
                                        break;
                                    case "w":
                                    case "W":
                                        r += 7 * parseInt(l[1], 10);
                                        break;
                                    case "m":
                                    case "M":
                                        (a += parseInt(l[1], 10)),
                                            (r = Math.min(r, t.datepicker._getDaysInMonth(o, a)));
                                        break;
                                    case "y":
                                    case "Y":
                                        (o += parseInt(l[1], 10)),
                                            (r = Math.min(r, t.datepicker._getDaysInMonth(o, a)));
                                }
                                l = h.exec(i);
                            }
                            return new Date(o, a, r);
                        },
                        a =
                            null == i || "" === i
                                ? s
                                : "string" == typeof i
                                  ? o(i)
                                  : "number" == typeof i
                                    ? isNaN(i)
                                        ? s
                                        : n(i)
                                    : new Date(i.getTime());
                    return (
                        (a = a && "Invalid Date" == "" + a ? s : a),
                        a && (a.setHours(0), a.setMinutes(0), a.setSeconds(0), a.setMilliseconds(0)),
                        this._daylightSavingAdjust(a)
                    );
                },
                _daylightSavingAdjust: function (t) {
                    return t ? (t.setHours(t.getHours() > 12 ? t.getHours() + 2 : 0), t) : null;
                },
                _setDate: function (t, e, i) {
                    var s = !e,
                        n = t.selectedMonth,
                        o = t.selectedYear,
                        a = this._restrictMinMax(t, this._determineDate(t, e, new Date()));
                    (t.selectedDay = t.currentDay = a.getDate()),
                        (t.drawMonth = t.selectedMonth = t.currentMonth = a.getMonth()),
                        (t.drawYear = t.selectedYear = t.currentYear = a.getFullYear()),
                        (n === t.selectedMonth && o === t.selectedYear) || i || this._notifyChange(t),
                        this._adjustInstDate(t),
                        t.input && t.input.val(s ? "" : this._formatDate(t));
                },
                _getDate: function (t) {
                    var e =
                        !t.currentYear || (t.input && "" === t.input.val())
                            ? null
                            : this._daylightSavingAdjust(new Date(t.currentYear, t.currentMonth, t.currentDay));
                    return e;
                },
                _attachHandlers: function (e) {
                    var i = this._get(e, "stepMonths"),
                        s = "#" + e.id.replace(/\\\\/g, "\\");
                    e.dpDiv.find("[data-handler]").map(function () {
                        var e = {
                            prev: function () {
                                window["DP_jQuery_" + r].datepicker._adjustDate(s, -i, "M");
                            },
                            next: function () {
                                window["DP_jQuery_" + r].datepicker._adjustDate(s, +i, "M");
                            },
                            hide: function () {
                                window["DP_jQuery_" + r].datepicker._hideDatepicker();
                            },
                            today: function () {
                                window["DP_jQuery_" + r].datepicker._gotoToday(s);
                            },
                            selectDay: function () {
                                return (
                                    window["DP_jQuery_" + r].datepicker._selectDay(
                                        s,
                                        +this.getAttribute("data-month"),
                                        +this.getAttribute("data-year"),
                                        this
                                    ),
                                    !1
                                );
                            },
                            selectMonth: function () {
                                return window["DP_jQuery_" + r].datepicker._selectMonthYear(s, this, "M"), !1;
                            },
                            selectYear: function () {
                                return window["DP_jQuery_" + r].datepicker._selectMonthYear(s, this, "Y"), !1;
                            },
                        };
                        t(this).bind(this.getAttribute("data-event"), e[this.getAttribute("data-handler")]);
                    });
                },
                _generateHTML: function (t) {
                    var e,
                        i,
                        s,
                        n,
                        o,
                        a,
                        r,
                        h,
                        l,
                        c,
                        u,
                        d,
                        p,
                        f,
                        g,
                        m,
                        v,
                        _,
                        b,
                        y,
                        w,
                        k,
                        x,
                        D,
                        C,
                        I,
                        P,
                        T,
                        M,
                        S,
                        z,
                        A,
                        H,
                        N,
                        E,
                        W,
                        O,
                        F,
                        R,
                        j = new Date(),
                        L = this._daylightSavingAdjust(new Date(j.getFullYear(), j.getMonth(), j.getDate())),
                        Y = this._get(t, "isRTL"),
                        B = this._get(t, "showButtonPanel"),
                        V = this._get(t, "hideIfNoPrevNext"),
                        K = this._get(t, "navigationAsDateFormat"),
                        U = this._getNumberOfMonths(t),
                        q = this._get(t, "showCurrentAtPos"),
                        Q = this._get(t, "stepMonths"),
                        X = 1 !== U[0] || 1 !== U[1],
                        $ = this._daylightSavingAdjust(
                            t.currentDay ? new Date(t.currentYear, t.currentMonth, t.currentDay) : new Date(9999, 9, 9)
                        ),
                        G = this._getMinMaxDate(t, "min"),
                        J = this._getMinMaxDate(t, "max"),
                        Z = t.drawMonth - q,
                        te = t.drawYear;
                    if ((0 > Z && ((Z += 12), te--), J))
                        for (
                            e = this._daylightSavingAdjust(
                                new Date(J.getFullYear(), J.getMonth() - U[0] * U[1] + 1, J.getDate())
                            ),
                                e = G && G > e ? G : e;
                            this._daylightSavingAdjust(new Date(te, Z, 1)) > e;

                        )
                            Z--, 0 > Z && ((Z = 11), te--);
                    for (
                        t.drawMonth = Z,
                            t.drawYear = te,
                            i = this._get(t, "prevText"),
                            i = K
                                ? this.formatDate(
                                      i,
                                      this._daylightSavingAdjust(new Date(te, Z - Q, 1)),
                                      this._getFormatConfig(t)
                                  )
                                : i,
                            s = this._canAdjustMonth(t, -1, te, Z)
                                ? "<a class='ui-datepicker-prev ui-corner-all' data-handler='prev' data-event='click' title='" +
                                  i +
                                  "'><span class='ui-icon ui-icon-circle-triangle-" +
                                  (Y ? "e" : "w") +
                                  "'>" +
                                  i +
                                  "</span></a>"
                                : V
                                  ? ""
                                  : "<a class='ui-datepicker-prev ui-corner-all ui-state-disabled' title='" +
                                    i +
                                    "'><span class='ui-icon ui-icon-circle-triangle-" +
                                    (Y ? "e" : "w") +
                                    "'>" +
                                    i +
                                    "</span></a>",
                            n = this._get(t, "nextText"),
                            n = K
                                ? this.formatDate(
                                      n,
                                      this._daylightSavingAdjust(new Date(te, Z + Q, 1)),
                                      this._getFormatConfig(t)
                                  )
                                : n,
                            o = this._canAdjustMonth(t, 1, te, Z)
                                ? "<a class='ui-datepicker-next ui-corner-all' data-handler='next' data-event='click' title='" +
                                  n +
                                  "'><span class='ui-icon ui-icon-circle-triangle-" +
                                  (Y ? "w" : "e") +
                                  "'>" +
                                  n +
                                  "</span></a>"
                                : V
                                  ? ""
                                  : "<a class='ui-datepicker-next ui-corner-all ui-state-disabled' title='" +
                                    n +
                                    "'><span class='ui-icon ui-icon-circle-triangle-" +
                                    (Y ? "w" : "e") +
                                    "'>" +
                                    n +
                                    "</span></a>",
                            a = this._get(t, "currentText"),
                            r = this._get(t, "gotoCurrent") && t.currentDay ? $ : L,
                            a = K ? this.formatDate(a, r, this._getFormatConfig(t)) : a,
                            h = t.inline
                                ? ""
                                : "<button type='button' class='ui-datepicker-close ui-state-default ui-priority-primary ui-corner-all' data-handler='hide' data-event='click'>" +
                                  this._get(t, "closeText") +
                                  "</button>",
                            l = B
                                ? "<div class='ui-datepicker-buttonpane ui-widget-content'>" +
                                  (Y ? h : "") +
                                  (this._isInRange(t, r)
                                      ? "<button type='button' class='ui-datepicker-current ui-state-default ui-priority-secondary ui-corner-all' data-handler='today' data-event='click'>" +
                                        a +
                                        "</button>"
                                      : "") +
                                  (Y ? "" : h) +
                                  "</div>"
                                : "",
                            c = parseInt(this._get(t, "firstDay"), 10),
                            c = isNaN(c) ? 0 : c,
                            u = this._get(t, "showWeek"),
                            d = this._get(t, "dayNames"),
                            p = this._get(t, "dayNamesMin"),
                            f = this._get(t, "monthNames"),
                            g = this._get(t, "monthNamesShort"),
                            m = this._get(t, "beforeShowDay"),
                            v = this._get(t, "showOtherMonths"),
                            _ = this._get(t, "selectOtherMonths"),
                            b = this._getDefaultDate(t),
                            y = "",
                            k = 0;
                        U[0] > k;
                        k++
                    ) {
                        for (x = "", this.maxRows = 4, D = 0; U[1] > D; D++) {
                            if (
                                ((C = this._daylightSavingAdjust(new Date(te, Z, t.selectedDay))),
                                (I = " ui-corner-all"),
                                (P = ""),
                                X)
                            ) {
                                if (((P += "<div class='ui-datepicker-group"), U[1] > 1))
                                    switch (D) {
                                        case 0:
                                            (P += " ui-datepicker-group-first"),
                                                (I = " ui-corner-" + (Y ? "right" : "left"));
                                            break;
                                        case U[1] - 1:
                                            (P += " ui-datepicker-group-last"),
                                                (I = " ui-corner-" + (Y ? "left" : "right"));
                                            break;
                                        default:
                                            (P += " ui-datepicker-group-middle"), (I = "");
                                    }
                                P += "'>";
                            }
                            for (
                                P +=
                                    "<div class='ui-datepicker-header ui-widget-header ui-helper-clearfix" +
                                    I +
                                    "'>" +
                                    (/all|left/.test(I) && 0 === k ? (Y ? o : s) : "") +
                                    (/all|right/.test(I) && 0 === k ? (Y ? s : o) : "") +
                                    this._generateMonthYearHeader(t, Z, te, G, J, k > 0 || D > 0, f, g) +
                                    "</div><table class='ui-datepicker-calendar'><thead>" +
                                    "<tr>",
                                    T = u
                                        ? "<th class='ui-datepicker-week-col'>" + this._get(t, "weekHeader") + "</th>"
                                        : "",
                                    w = 0;
                                7 > w;
                                w++
                            )
                                (M = (w + c) % 7),
                                    (T +=
                                        "<th" +
                                        ((w + c + 6) % 7 >= 5 ? " class='ui-datepicker-week-end'" : "") +
                                        ">" +
                                        "<span title='" +
                                        d[M] +
                                        "'>" +
                                        p[M] +
                                        "</span></th>");
                            for (
                                P += T + "</tr></thead><tbody>",
                                    S = this._getDaysInMonth(te, Z),
                                    te === t.selectedYear &&
                                        Z === t.selectedMonth &&
                                        (t.selectedDay = Math.min(t.selectedDay, S)),
                                    z = (this._getFirstDayOfMonth(te, Z) - c + 7) % 7,
                                    A = Math.ceil((z + S) / 7),
                                    H = X ? (this.maxRows > A ? this.maxRows : A) : A,
                                    this.maxRows = H,
                                    N = this._daylightSavingAdjust(new Date(te, Z, 1 - z)),
                                    E = 0;
                                H > E;
                                E++
                            ) {
                                for (
                                    P += "<tr>",
                                        W = u
                                            ? "<td class='ui-datepicker-week-col'>" +
                                              this._get(t, "calculateWeek")(N) +
                                              "</td>"
                                            : "",
                                        w = 0;
                                    7 > w;
                                    w++
                                )
                                    (O = m ? m.apply(t.input ? t.input[0] : null, [N]) : [!0, ""]),
                                        (F = N.getMonth() !== Z),
                                        (R = (F && !_) || !O[0] || (G && G > N) || (J && N > J)),
                                        (W +=
                                            "<td class='" +
                                            ((w + c + 6) % 7 >= 5 ? " ui-datepicker-week-end" : "") +
                                            (F ? " ui-datepicker-other-month" : "") +
                                            ((N.getTime() === C.getTime() && Z === t.selectedMonth && t._keyEvent) ||
                                            (b.getTime() === N.getTime() && b.getTime() === C.getTime())
                                                ? " " + this._dayOverClass
                                                : "") +
                                            (R ? " " + this._unselectableClass + " ui-state-disabled" : "") +
                                            (F && !v
                                                ? ""
                                                : " " +
                                                  O[1] +
                                                  (N.getTime() === $.getTime() ? " " + this._currentClass : "") +
                                                  (N.getTime() === L.getTime() ? " ui-datepicker-today" : "")) +
                                            "'" +
                                            ((F && !v) || !O[2] ? "" : " title='" + O[2].replace(/'/g, "&#39;") + "'") +
                                            (R
                                                ? ""
                                                : " data-handler='selectDay' data-event='click' data-month='" +
                                                  N.getMonth() +
                                                  "' data-year='" +
                                                  N.getFullYear() +
                                                  "'") +
                                            ">" +
                                            (F && !v
                                                ? "&#xa0;"
                                                : R
                                                  ? "<span class='ui-state-default'>" + N.getDate() + "</span>"
                                                  : "<a class='ui-state-default" +
                                                    (N.getTime() === L.getTime() ? " ui-state-highlight" : "") +
                                                    (N.getTime() === $.getTime() ? " ui-state-active" : "") +
                                                    (F ? " ui-priority-secondary" : "") +
                                                    "' href='#'>" +
                                                    N.getDate() +
                                                    "</a>") +
                                            "</td>"),
                                        N.setDate(N.getDate() + 1),
                                        (N = this._daylightSavingAdjust(N));
                                P += W + "</tr>";
                            }
                            Z++,
                                Z > 11 && ((Z = 0), te++),
                                (P +=
                                    "</tbody></table>" +
                                    (X
                                        ? "</div>" +
                                          (U[0] > 0 && D === U[1] - 1
                                              ? "<div class='ui-datepicker-row-break'></div>"
                                              : "")
                                        : "")),
                                (x += P);
                        }
                        y += x;
                    }
                    return (y += l), (t._keyEvent = !1), y;
                },
                _generateMonthYearHeader: function (t, e, i, s, n, o, a, r) {
                    var h,
                        l,
                        c,
                        u,
                        d,
                        p,
                        f,
                        g,
                        m = this._get(t, "changeMonth"),
                        v = this._get(t, "changeYear"),
                        _ = this._get(t, "showMonthAfterYear"),
                        b = "<div class='ui-datepicker-title'>",
                        y = "";
                    if (o || !m) y += "<span class='ui-datepicker-month'>" + a[e] + "</span>";
                    else {
                        for (
                            h = s && s.getFullYear() === i,
                                l = n && n.getFullYear() === i,
                                y +=
                                    "<select class='ui-datepicker-month' data-handler='selectMonth' data-event='change'>",
                                c = 0;
                            12 > c;
                            c++
                        )
                            (!h || c >= s.getMonth()) &&
                                (!l || n.getMonth() >= c) &&
                                (y +=
                                    "<option value='" +
                                    c +
                                    "'" +
                                    (c === e ? " selected='selected'" : "") +
                                    ">" +
                                    r[c] +
                                    "</option>");
                        y += "</select>";
                    }
                    if ((_ || (b += y + (!o && m && v ? "" : "&#xa0;")), !t.yearshtml))
                        if (((t.yearshtml = ""), o || !v)) b += "<span class='ui-datepicker-year'>" + i + "</span>";
                        else {
                            for (
                                u = this._get(t, "yearRange").split(":"),
                                    d = new Date().getFullYear(),
                                    p = function (t) {
                                        var e = t.match(/c[+\-].*/)
                                            ? i + parseInt(t.substring(1), 10)
                                            : t.match(/[+\-].*/)
                                              ? d + parseInt(t, 10)
                                              : parseInt(t, 10);
                                        return isNaN(e) ? d : e;
                                    },
                                    f = p(u[0]),
                                    g = Math.max(f, p(u[1] || "")),
                                    f = s ? Math.max(f, s.getFullYear()) : f,
                                    g = n ? Math.min(g, n.getFullYear()) : g,
                                    t.yearshtml +=
                                        "<select class='ui-datepicker-year' data-handler='selectYear' data-event='change'>";
                                g >= f;
                                f++
                            )
                                t.yearshtml +=
                                    "<option value='" +
                                    f +
                                    "'" +
                                    (f === i ? " selected='selected'" : "") +
                                    ">" +
                                    f +
                                    "</option>";
                            (t.yearshtml += "</select>"), (b += t.yearshtml), (t.yearshtml = null);
                        }
                    return (
                        (b += this._get(t, "yearSuffix")),
                        _ && (b += (!o && m && v ? "" : "&#xa0;") + y),
                        (b += "</div>")
                    );
                },
                _adjustInstDate: function (t, e, i) {
                    var s = t.drawYear + ("Y" === i ? e : 0),
                        n = t.drawMonth + ("M" === i ? e : 0),
                        o = Math.min(t.selectedDay, this._getDaysInMonth(s, n)) + ("D" === i ? e : 0),
                        a = this._restrictMinMax(t, this._daylightSavingAdjust(new Date(s, n, o)));
                    (t.selectedDay = a.getDate()),
                        (t.drawMonth = t.selectedMonth = a.getMonth()),
                        (t.drawYear = t.selectedYear = a.getFullYear()),
                        ("M" === i || "Y" === i) && this._notifyChange(t);
                },
                _restrictMinMax: function (t, e) {
                    var i = this._getMinMaxDate(t, "min"),
                        s = this._getMinMaxDate(t, "max"),
                        n = i && i > e ? i : e;
                    return s && n > s ? s : n;
                },
                _notifyChange: function (t) {
                    var e = this._get(t, "onChangeMonthYear");
                    e && e.apply(t.input ? t.input[0] : null, [t.selectedYear, t.selectedMonth + 1, t]);
                },
                _getNumberOfMonths: function (t) {
                    var e = this._get(t, "numberOfMonths");
                    return null == e ? [1, 1] : "number" == typeof e ? [1, e] : e;
                },
                _getMinMaxDate: function (t, e) {
                    return this._determineDate(t, this._get(t, e + "Date"), null);
                },
                _getDaysInMonth: function (t, e) {
                    return 32 - this._daylightSavingAdjust(new Date(t, e, 32)).getDate();
                },
                _getFirstDayOfMonth: function (t, e) {
                    return new Date(t, e, 1).getDay();
                },
                _canAdjustMonth: function (t, e, i, s) {
                    var n = this._getNumberOfMonths(t),
                        o = this._daylightSavingAdjust(new Date(i, s + (0 > e ? e : n[0] * n[1]), 1));
                    return (
                        0 > e && o.setDate(this._getDaysInMonth(o.getFullYear(), o.getMonth())), this._isInRange(t, o)
                    );
                },
                _isInRange: function (t, e) {
                    var i,
                        s,
                        n = this._getMinMaxDate(t, "min"),
                        o = this._getMinMaxDate(t, "max"),
                        a = null,
                        r = null,
                        h = this._get(t, "yearRange");
                    return (
                        h &&
                            ((i = h.split(":")),
                            (s = new Date().getFullYear()),
                            (a = parseInt(i[0], 10)),
                            (r = parseInt(i[1], 10)),
                            i[0].match(/[+\-].*/) && (a += s),
                            i[1].match(/[+\-].*/) && (r += s)),
                        (!n || e.getTime() >= n.getTime()) &&
                            (!o || e.getTime() <= o.getTime()) &&
                            (!a || e.getFullYear() >= a) &&
                            (!r || r >= e.getFullYear())
                    );
                },
                _getFormatConfig: function (t) {
                    var e = this._get(t, "shortYearCutoff");
                    return (
                        (e = "string" != typeof e ? e : (new Date().getFullYear() % 100) + parseInt(e, 10)),
                        {
                            shortYearCutoff: e,
                            dayNamesShort: this._get(t, "dayNamesShort"),
                            dayNames: this._get(t, "dayNames"),
                            monthNamesShort: this._get(t, "monthNamesShort"),
                            monthNames: this._get(t, "monthNames"),
                        }
                    );
                },
                _formatDate: function (t, e, i, s) {
                    e ||
                        ((t.currentDay = t.selectedDay),
                        (t.currentMonth = t.selectedMonth),
                        (t.currentYear = t.selectedYear));
                    var n = e
                        ? "object" == typeof e
                            ? e
                            : this._daylightSavingAdjust(new Date(s, i, e))
                        : this._daylightSavingAdjust(new Date(t.currentYear, t.currentMonth, t.currentDay));
                    return this.formatDate(this._get(t, "dateFormat"), n, this._getFormatConfig(t));
                },
            }),
                (t.fn.datepicker = function (e) {
                    if (!this.length) return this;
                    t.datepicker.initialized ||
                        (t(document).mousedown(t.datepicker._checkExternalClick), (t.datepicker.initialized = !0)),
                        0 === t("#" + t.datepicker._mainDivId).length && t("body").append(t.datepicker.dpDiv);
                    var i = Array.prototype.slice.call(arguments, 1);
                    return "string" != typeof e || ("isDisabled" !== e && "getDate" !== e && "widget" !== e)
                        ? "option" === e && 2 === arguments.length && "string" == typeof arguments[1]
                            ? t.datepicker["_" + e + "Datepicker"].apply(t.datepicker, [this[0]].concat(i))
                            : this.each(function () {
                                  "string" == typeof e
                                      ? t.datepicker["_" + e + "Datepicker"].apply(t.datepicker, [this].concat(i))
                                      : t.datepicker._attachDatepicker(this, e);
                              })
                        : t.datepicker["_" + e + "Datepicker"].apply(t.datepicker, [this[0]].concat(i));
                }),
                (t.datepicker = new i()),
                (t.datepicker.initialized = !1),
                (t.datepicker.uuid = new Date().getTime()),
                (t.datepicker.version = "1.10.2"),
                (window["DP_jQuery_" + r] = t);
        })(jQuery),
        (function (t) {
            var e = { buttons: !0, height: !0, maxHeight: !0, maxWidth: !0, minHeight: !0, minWidth: !0, width: !0 },
                i = { maxHeight: !0, maxWidth: !0, minHeight: !0, minWidth: !0 };
            t.widget("ui.dialog", {
                version: "1.10.2",
                options: {
                    appendTo: "body",
                    autoOpen: !0,
                    buttons: [],
                    closeOnEscape: !0,
                    closeText: "close",
                    dialogClass: "",
                    draggable: !0,
                    hide: null,
                    height: "auto",
                    maxHeight: null,
                    maxWidth: null,
                    minHeight: 150,
                    minWidth: 150,
                    modal: !1,
                    position: {
                        my: "center",
                        at: "center",
                        of: window,
                        collision: "fit",
                        using: function (e) {
                            var i = t(this).css(e).offset().top;
                            0 > i && t(this).css("top", e.top - i);
                        },
                    },
                    resizable: !0,
                    show: null,
                    title: null,
                    width: 300,
                    beforeClose: null,
                    close: null,
                    drag: null,
                    dragStart: null,
                    dragStop: null,
                    focus: null,
                    open: null,
                    resize: null,
                    resizeStart: null,
                    resizeStop: null,
                },
                _create: function () {
                    (this.originalCss = {
                        display: this.element[0].style.display,
                        width: this.element[0].style.width,
                        minHeight: this.element[0].style.minHeight,
                        maxHeight: this.element[0].style.maxHeight,
                        height: this.element[0].style.height,
                    }),
                        (this.originalPosition = {
                            parent: this.element.parent(),
                            index: this.element.parent().children().index(this.element),
                        }),
                        (this.originalTitle = this.element.attr("title")),
                        (this.options.title = this.options.title || this.originalTitle),
                        this._createWrapper(),
                        this.element
                            .show()
                            .removeAttr("title")
                            .addClass("ui-dialog-content ui-widget-content")
                            .appendTo(this.uiDialog),
                        this._createTitlebar(),
                        this._createButtonPane(),
                        this.options.draggable && t.fn.draggable && this._makeDraggable(),
                        this.options.resizable && t.fn.resizable && this._makeResizable(),
                        (this._isOpen = !1);
                },
                _init: function () {
                    this.options.autoOpen && this.open();
                },
                _appendTo: function () {
                    var e = this.options.appendTo;
                    return e && (e.jquery || e.nodeType) ? t(e) : this.document.find(e || "body").eq(0);
                },
                _destroy: function () {
                    var t,
                        e = this.originalPosition;
                    this._destroyOverlay(),
                        this.element
                            .removeUniqueId()
                            .removeClass("ui-dialog-content ui-widget-content")
                            .css(this.originalCss)
                            .detach(),
                        this.uiDialog.stop(!0, !0).remove(),
                        this.originalTitle && this.element.attr("title", this.originalTitle),
                        (t = e.parent.children().eq(e.index)),
                        t.length && t[0] !== this.element[0] ? t.before(this.element) : e.parent.append(this.element);
                },
                widget: function () {
                    return this.uiDialog;
                },
                disable: t.noop,
                enable: t.noop,
                close: function (e) {
                    var i = this;
                    this._isOpen &&
                        this._trigger("beforeClose", e) !== !1 &&
                        ((this._isOpen = !1),
                        this._destroyOverlay(),
                        this.opener.filter(":focusable").focus().length || t(this.document[0].activeElement).blur(),
                        this._hide(this.uiDialog, this.options.hide, function () {
                            i._trigger("close", e);
                        }));
                },
                isOpen: function () {
                    return this._isOpen;
                },
                moveToTop: function () {
                    this._moveToTop();
                },
                _moveToTop: function (t, e) {
                    var i = !!this.uiDialog.nextAll(":visible").insertBefore(this.uiDialog).length;
                    return i && !e && this._trigger("focus", t), i;
                },
                open: function () {
                    var e = this;
                    return this._isOpen
                        ? (this._moveToTop() && this._focusTabbable(), undefined)
                        : ((this._isOpen = !0),
                          (this.opener = t(this.document[0].activeElement)),
                          this._size(),
                          this._position(),
                          this._createOverlay(),
                          this._moveToTop(null, !0),
                          this._show(this.uiDialog, this.options.show, function () {
                              e._focusTabbable(), e._trigger("focus");
                          }),
                          this._trigger("open"),
                          undefined);
                },
                _focusTabbable: function () {
                    var t = this.element.find("[autofocus]");
                    t.length || (t = this.element.find(":tabbable")),
                        t.length || (t = this.uiDialogButtonPane.find(":tabbable")),
                        t.length || (t = this.uiDialogTitlebarClose.filter(":tabbable")),
                        t.length || (t = this.uiDialog),
                        t.eq(0).focus();
                },
                _keepFocus: function (e) {
                    function i() {
                        var e = this.document[0].activeElement,
                            i = this.uiDialog[0] === e || t.contains(this.uiDialog[0], e);
                        i || this._focusTabbable();
                    }
                    e.preventDefault(), i.call(this), this._delay(i);
                },
                _createWrapper: function () {
                    (this.uiDialog = t("<div>")
                        .addClass(
                            "ui-dialog ui-widget ui-widget-content ui-corner-all ui-front " + this.options.dialogClass
                        )
                        .hide()
                        .attr({ tabIndex: -1, role: "dialog" })
                        .appendTo(this._appendTo())),
                        this._on(this.uiDialog, {
                            keydown: function (e) {
                                if (
                                    this.options.closeOnEscape &&
                                    !e.isDefaultPrevented() &&
                                    e.keyCode &&
                                    e.keyCode === t.ui.keyCode.ESCAPE
                                )
                                    return e.preventDefault(), this.close(e), undefined;
                                if (e.keyCode === t.ui.keyCode.TAB) {
                                    var i = this.uiDialog.find(":tabbable"),
                                        s = i.filter(":first"),
                                        n = i.filter(":last");
                                    (e.target !== n[0] && e.target !== this.uiDialog[0]) || e.shiftKey
                                        ? (e.target !== s[0] && e.target !== this.uiDialog[0]) ||
                                          !e.shiftKey ||
                                          (n.focus(1), e.preventDefault())
                                        : (s.focus(1), e.preventDefault());
                                }
                            },
                            mousedown: function (t) {
                                this._moveToTop(t) && this._focusTabbable();
                            },
                        }),
                        this.element.find("[aria-describedby]").length ||
                            this.uiDialog.attr({ "aria-describedby": this.element.uniqueId().attr("id") });
                },
                _createTitlebar: function () {
                    var e;
                    (this.uiDialogTitlebar = t("<div>")
                        .addClass("ui-dialog-titlebar ui-widget-header ui-corner-all ui-helper-clearfix")
                        .prependTo(this.uiDialog)),
                        this._on(this.uiDialogTitlebar, {
                            mousedown: function (e) {
                                t(e.target).closest(".ui-dialog-titlebar-close") || this.uiDialog.focus();
                            },
                        }),
                        (this.uiDialogTitlebarClose = t("<button></button>")
                            .button({
                                label: this.options.closeText,
                                icons: { primary: "ui-icon-closethick" },
                                text: !1,
                            })
                            .addClass("ui-dialog-titlebar-close")
                            .appendTo(this.uiDialogTitlebar)),
                        this._on(this.uiDialogTitlebarClose, {
                            click: function (t) {
                                t.preventDefault(), this.close(t);
                            },
                        }),
                        (e = t("<span>").uniqueId().addClass("ui-dialog-title").prependTo(this.uiDialogTitlebar)),
                        this._title(e),
                        this.uiDialog.attr({ "aria-labelledby": e.attr("id") });
                },
                _title: function (t) {
                    this.options.title || t.html("&#160;"), t.text(this.options.title);
                },
                _createButtonPane: function () {
                    (this.uiDialogButtonPane = t("<div>").addClass(
                        "ui-dialog-buttonpane ui-widget-content ui-helper-clearfix"
                    )),
                        (this.uiButtonSet = t("<div>")
                            .addClass("ui-dialog-buttonset")
                            .appendTo(this.uiDialogButtonPane)),
                        this._createButtons();
                },
                _createButtons: function () {
                    var e = this,
                        i = this.options.buttons;
                    return (
                        this.uiDialogButtonPane.remove(),
                        this.uiButtonSet.empty(),
                        t.isEmptyObject(i) || (t.isArray(i) && !i.length)
                            ? (this.uiDialog.removeClass("ui-dialog-buttons"), undefined)
                            : (t.each(i, function (i, s) {
                                  var n, o;
                                  (s = t.isFunction(s) ? { click: s, text: i } : s),
                                      (s = t.extend({ type: "button" }, s)),
                                      (n = s.click),
                                      (s.click = function () {
                                          n.apply(e.element[0], arguments);
                                      }),
                                      (o = { icons: s.icons, text: s.showText }),
                                      delete s.icons,
                                      delete s.showText,
                                      t("<button></button>", s).button(o).appendTo(e.uiButtonSet);
                              }),
                              this.uiDialog.addClass("ui-dialog-buttons"),
                              this.uiDialogButtonPane.appendTo(this.uiDialog),
                              undefined)
                    );
                },
                _makeDraggable: function () {
                    function e(t) {
                        return { position: t.position, offset: t.offset };
                    }
                    var i = this,
                        s = this.options;
                    this.uiDialog.draggable({
                        cancel: ".ui-dialog-content, .ui-dialog-titlebar-close",
                        handle: ".ui-dialog-titlebar",
                        containment: "document",
                        start: function (s, n) {
                            t(this).addClass("ui-dialog-dragging"), i._blockFrames(), i._trigger("dragStart", s, e(n));
                        },
                        drag: function (t, s) {
                            i._trigger("drag", t, e(s));
                        },
                        stop: function (n, o) {
                            (s.position = [
                                o.position.left - i.document.scrollLeft(),
                                o.position.top - i.document.scrollTop(),
                            ]),
                                t(this).removeClass("ui-dialog-dragging"),
                                i._unblockFrames(),
                                i._trigger("dragStop", n, e(o));
                        },
                    });
                },
                _makeResizable: function () {
                    function e(t) {
                        return {
                            originalPosition: t.originalPosition,
                            originalSize: t.originalSize,
                            position: t.position,
                            size: t.size,
                        };
                    }
                    var i = this,
                        s = this.options,
                        n = s.resizable,
                        o = this.uiDialog.css("position"),
                        a = "string" == typeof n ? n : "n,e,s,w,se,sw,ne,nw";
                    this.uiDialog
                        .resizable({
                            cancel: ".ui-dialog-content",
                            containment: "document",
                            alsoResize: this.element,
                            maxWidth: s.maxWidth,
                            maxHeight: s.maxHeight,
                            minWidth: s.minWidth,
                            minHeight: this._minHeight(),
                            handles: a,
                            start: function (s, n) {
                                t(this).addClass("ui-dialog-resizing"),
                                    i._blockFrames(),
                                    i._trigger("resizeStart", s, e(n));
                            },
                            resize: function (t, s) {
                                i._trigger("resize", t, e(s));
                            },
                            stop: function (n, o) {
                                (s.height = t(this).height()),
                                    (s.width = t(this).width()),
                                    t(this).removeClass("ui-dialog-resizing"),
                                    i._unblockFrames(),
                                    i._trigger("resizeStop", n, e(o));
                            },
                        })
                        .css("position", o);
                },
                _minHeight: function () {
                    var t = this.options;
                    return "auto" === t.height ? t.minHeight : Math.min(t.minHeight, t.height);
                },
                _position: function () {
                    var t = this.uiDialog.is(":visible");
                    t || this.uiDialog.show(), this.uiDialog.position(this.options.position), t || this.uiDialog.hide();
                },
                _setOptions: function (s) {
                    var n = this,
                        o = !1,
                        a = {};
                    t.each(s, function (t, s) {
                        n._setOption(t, s), t in e && (o = !0), t in i && (a[t] = s);
                    }),
                        o && (this._size(), this._position()),
                        this.uiDialog.is(":data(ui-resizable)") && this.uiDialog.resizable("option", a);
                },
                _setOption: function (t, e) {
                    var i,
                        s,
                        n = this.uiDialog;
                    "dialogClass" === t && n.removeClass(this.options.dialogClass).addClass(e),
                        "disabled" !== t &&
                            (this._super(t, e),
                            "appendTo" === t && this.uiDialog.appendTo(this._appendTo()),
                            "buttons" === t && this._createButtons(),
                            "closeText" === t && this.uiDialogTitlebarClose.button({ label: "" + e }),
                            "draggable" === t &&
                                ((i = n.is(":data(ui-draggable)")),
                                i && !e && n.draggable("destroy"),
                                !i && e && this._makeDraggable()),
                            "position" === t && this._position(),
                            "resizable" === t &&
                                ((s = n.is(":data(ui-resizable)")),
                                s && !e && n.resizable("destroy"),
                                s && "string" == typeof e && n.resizable("option", "handles", e),
                                s || e === !1 || this._makeResizable()),
                            "title" === t && this._title(this.uiDialogTitlebar.find(".ui-dialog-title")));
                },
                _size: function () {
                    var t,
                        e,
                        i,
                        s = this.options;
                    this.element.show().css({ width: "auto", minHeight: 0, maxHeight: "none", height: 0 }),
                        s.minWidth > s.width && (s.width = s.minWidth),
                        (t = this.uiDialog.css({ height: "auto", width: s.width }).outerHeight()),
                        (e = Math.max(0, s.minHeight - t)),
                        (i = "number" == typeof s.maxHeight ? Math.max(0, s.maxHeight - t) : "none"),
                        "auto" === s.height
                            ? this.element.css({ minHeight: e, maxHeight: i, height: "auto" })
                            : this.element.height(Math.max(0, s.height - t)),
                        this.uiDialog.is(":data(ui-resizable)") &&
                            this.uiDialog.resizable("option", "minHeight", this._minHeight());
                },
                _blockFrames: function () {
                    this.iframeBlocks = this.document.find("iframe").map(function () {
                        var e = t(this);
                        return t("<div>")
                            .css({ position: "absolute", width: e.outerWidth(), height: e.outerHeight() })
                            .appendTo(e.parent())
                            .offset(e.offset())[0];
                    });
                },
                _unblockFrames: function () {
                    this.iframeBlocks && (this.iframeBlocks.remove(), delete this.iframeBlocks);
                },
                _allowInteraction: function (e) {
                    return t(e.target).closest(".ui-dialog").length
                        ? !0
                        : !!t(e.target).closest(".ui-datepicker").length;
                },
                _createOverlay: function () {
                    if (this.options.modal) {
                        var e = this,
                            i = this.widgetFullName;
                        t.ui.dialog.overlayInstances ||
                            this._delay(function () {
                                t.ui.dialog.overlayInstances &&
                                    this.document.bind("focusin.dialog", function (s) {
                                        e._allowInteraction(s) ||
                                            (s.preventDefault(),
                                            t(".ui-dialog:visible:last .ui-dialog-content").data(i)._focusTabbable());
                                    });
                            }),
                            (this.overlay = t("<div>")
                                .addClass("ui-widget-overlay ui-front")
                                .appendTo(this._appendTo())),
                            this._on(this.overlay, { mousedown: "_keepFocus" }),
                            t.ui.dialog.overlayInstances++;
                    }
                },
                _destroyOverlay: function () {
                    this.options.modal &&
                        this.overlay &&
                        (t.ui.dialog.overlayInstances--,
                        t.ui.dialog.overlayInstances || this.document.unbind("focusin.dialog"),
                        this.overlay.remove(),
                        (this.overlay = null));
                },
            }),
                (t.ui.dialog.overlayInstances = 0),
                t.uiBackCompat !== !1 &&
                    t.widget("ui.dialog", t.ui.dialog, {
                        _position: function () {
                            var e,
                                i = this.options.position,
                                s = [],
                                n = [0, 0];
                            i
                                ? (("string" == typeof i || ("object" == typeof i && "0" in i)) &&
                                      ((s = i.split ? i.split(" ") : [i[0], i[1]]),
                                      1 === s.length && (s[1] = s[0]),
                                      t.each(["left", "top"], function (t, e) {
                                          +s[t] === s[t] && ((n[t] = s[t]), (s[t] = e));
                                      }),
                                      (i = {
                                          my:
                                              s[0] +
                                              (0 > n[0] ? n[0] : "+" + n[0]) +
                                              " " +
                                              s[1] +
                                              (0 > n[1] ? n[1] : "+" + n[1]),
                                          at: s.join(" "),
                                      })),
                                  (i = t.extend({}, t.ui.dialog.prototype.options.position, i)))
                                : (i = t.ui.dialog.prototype.options.position),
                                (e = this.uiDialog.is(":visible")),
                                e || this.uiDialog.show(),
                                this.uiDialog.position(i),
                                e || this.uiDialog.hide();
                        },
                    });
        })(jQuery),
        (function (t) {
            var e = /up|down|vertical/,
                i = /up|left|vertical|horizontal/;
            t.effects.effect.blind = function (s, n) {
                var o,
                    a,
                    r,
                    h = t(this),
                    l = ["position", "top", "bottom", "left", "right", "height", "width"],
                    c = t.effects.setMode(h, s.mode || "hide"),
                    u = s.direction || "up",
                    d = e.test(u),
                    p = d ? "height" : "width",
                    f = d ? "top" : "left",
                    g = i.test(u),
                    m = {},
                    v = "show" === c;
                h.parent().is(".ui-effects-wrapper") ? t.effects.save(h.parent(), l) : t.effects.save(h, l),
                    h.show(),
                    (o = t.effects.createWrapper(h).css({ overflow: "hidden" })),
                    (a = o[p]()),
                    (r = parseFloat(o.css(f)) || 0),
                    (m[p] = v ? a : 0),
                    g ||
                        (h
                            .css(d ? "bottom" : "right", 0)
                            .css(d ? "top" : "left", "auto")
                            .css({ position: "absolute" }),
                        (m[f] = v ? r : a + r)),
                    v && (o.css(p, 0), g || o.css(f, r + a)),
                    o.animate(m, {
                        duration: s.duration,
                        easing: s.easing,
                        queue: !1,
                        complete: function () {
                            "hide" === c && h.hide(), t.effects.restore(h, l), t.effects.removeWrapper(h), n();
                        },
                    });
            };
        })(jQuery),
        (function (t) {
            t.effects.effect.bounce = function (e, i) {
                var s,
                    n,
                    o,
                    a = t(this),
                    r = ["position", "top", "bottom", "left", "right", "height", "width"],
                    h = t.effects.setMode(a, e.mode || "effect"),
                    l = "hide" === h,
                    c = "show" === h,
                    u = e.direction || "up",
                    d = e.distance,
                    p = e.times || 5,
                    f = 2 * p + (c || l ? 1 : 0),
                    g = e.duration / f,
                    m = e.easing,
                    v = "up" === u || "down" === u ? "top" : "left",
                    _ = "up" === u || "left" === u,
                    b = a.queue(),
                    y = b.length;
                for (
                    (c || l) && r.push("opacity"),
                        t.effects.save(a, r),
                        a.show(),
                        t.effects.createWrapper(a),
                        d || (d = a["top" === v ? "outerHeight" : "outerWidth"]() / 3),
                        c &&
                            ((o = { opacity: 1 }),
                            (o[v] = 0),
                            a
                                .css("opacity", 0)
                                .css(v, _ ? 2 * -d : 2 * d)
                                .animate(o, g, m)),
                        l && (d /= Math.pow(2, p - 1)),
                        o = {},
                        o[v] = 0,
                        s = 0;
                    p > s;
                    s++
                )
                    (n = {}),
                        (n[v] = (_ ? "-=" : "+=") + d),
                        a.animate(n, g, m).animate(o, g, m),
                        (d = l ? 2 * d : d / 2);
                l && ((n = { opacity: 0 }), (n[v] = (_ ? "-=" : "+=") + d), a.animate(n, g, m)),
                    a.queue(function () {
                        l && a.hide(), t.effects.restore(a, r), t.effects.removeWrapper(a), i();
                    }),
                    y > 1 && b.splice.apply(b, [1, 0].concat(b.splice(y, f + 1))),
                    a.dequeue();
            };
        })(jQuery),
        (function (t) {
            t.effects.effect.clip = function (e, i) {
                var s,
                    n,
                    o,
                    a = t(this),
                    r = ["position", "top", "bottom", "left", "right", "height", "width"],
                    h = t.effects.setMode(a, e.mode || "hide"),
                    l = "show" === h,
                    c = e.direction || "vertical",
                    u = "vertical" === c,
                    d = u ? "height" : "width",
                    p = u ? "top" : "left",
                    f = {};
                t.effects.save(a, r),
                    a.show(),
                    (s = t.effects.createWrapper(a).css({ overflow: "hidden" })),
                    (n = "IMG" === a[0].tagName ? s : a),
                    (o = n[d]()),
                    l && (n.css(d, 0), n.css(p, o / 2)),
                    (f[d] = l ? o : 0),
                    (f[p] = l ? 0 : o / 2),
                    n.animate(f, {
                        queue: !1,
                        duration: e.duration,
                        easing: e.easing,
                        complete: function () {
                            l || a.hide(), t.effects.restore(a, r), t.effects.removeWrapper(a), i();
                        },
                    });
            };
        })(jQuery),
        (function (t) {
            t.effects.effect.drop = function (e, i) {
                var s,
                    n = t(this),
                    o = ["position", "top", "bottom", "left", "right", "opacity", "height", "width"],
                    a = t.effects.setMode(n, e.mode || "hide"),
                    r = "show" === a,
                    h = e.direction || "left",
                    l = "up" === h || "down" === h ? "top" : "left",
                    c = "up" === h || "left" === h ? "pos" : "neg",
                    u = { opacity: r ? 1 : 0 };
                t.effects.save(n, o),
                    n.show(),
                    t.effects.createWrapper(n),
                    (s = e.distance || n["top" === l ? "outerHeight" : "outerWidth"](!0) / 2),
                    r && n.css("opacity", 0).css(l, "pos" === c ? -s : s),
                    (u[l] = (r ? ("pos" === c ? "+=" : "-=") : "pos" === c ? "-=" : "+=") + s),
                    n.animate(u, {
                        queue: !1,
                        duration: e.duration,
                        easing: e.easing,
                        complete: function () {
                            "hide" === a && n.hide(), t.effects.restore(n, o), t.effects.removeWrapper(n), i();
                        },
                    });
            };
        })(jQuery),
        (function (t) {
            t.effects.effect.explode = function (e, i) {
                function s() {
                    b.push(this), b.length === u * d && n();
                }
                function n() {
                    p.css({ visibility: "visible" }), t(b).remove(), g || p.hide(), i();
                }
                var o,
                    a,
                    r,
                    h,
                    l,
                    c,
                    u = e.pieces ? Math.round(Math.sqrt(e.pieces)) : 3,
                    d = u,
                    p = t(this),
                    f = t.effects.setMode(p, e.mode || "hide"),
                    g = "show" === f,
                    m = p.show().css("visibility", "hidden").offset(),
                    v = Math.ceil(p.outerWidth() / d),
                    _ = Math.ceil(p.outerHeight() / u),
                    b = [];
                for (o = 0; u > o; o++)
                    for (h = m.top + o * _, c = o - (u - 1) / 2, a = 0; d > a; a++)
                        (r = m.left + a * v),
                            (l = a - (d - 1) / 2),
                            p
                                .clone()
                                .appendTo("body")
                                .wrap("<div></div>")
                                .css({ position: "absolute", visibility: "visible", left: -a * v, top: -o * _ })
                                .parent()
                                .addClass("ui-effects-explode")
                                .css({
                                    position: "absolute",
                                    overflow: "hidden",
                                    width: v,
                                    height: _,
                                    left: r + (g ? l * v : 0),
                                    top: h + (g ? c * _ : 0),
                                    opacity: g ? 0 : 1,
                                })
                                .animate(
                                    { left: r + (g ? 0 : l * v), top: h + (g ? 0 : c * _), opacity: g ? 1 : 0 },
                                    e.duration || 500,
                                    e.easing,
                                    s
                                );
            };
        })(jQuery),
        (function (t) {
            t.effects.effect.fade = function (e, i) {
                var s = t(this),
                    n = t.effects.setMode(s, e.mode || "toggle");
                s.animate({ opacity: n }, { queue: !1, duration: e.duration, easing: e.easing, complete: i });
            };
        })(jQuery),
        (function (t) {
            t.effects.effect.fold = function (e, i) {
                var s,
                    n,
                    o = t(this),
                    a = ["position", "top", "bottom", "left", "right", "height", "width"],
                    r = t.effects.setMode(o, e.mode || "hide"),
                    h = "show" === r,
                    l = "hide" === r,
                    c = e.size || 15,
                    u = /([0-9]+)%/.exec(c),
                    d = !!e.horizFirst,
                    p = h !== d,
                    f = p ? ["width", "height"] : ["height", "width"],
                    g = e.duration / 2,
                    m = {},
                    v = {};
                t.effects.save(o, a),
                    o.show(),
                    (s = t.effects.createWrapper(o).css({ overflow: "hidden" })),
                    (n = p ? [s.width(), s.height()] : [s.height(), s.width()]),
                    u && (c = (parseInt(u[1], 10) / 100) * n[l ? 0 : 1]),
                    h && s.css(d ? { height: 0, width: c } : { height: c, width: 0 }),
                    (m[f[0]] = h ? n[0] : c),
                    (v[f[1]] = h ? n[1] : 0),
                    s.animate(m, g, e.easing).animate(v, g, e.easing, function () {
                        l && o.hide(), t.effects.restore(o, a), t.effects.removeWrapper(o), i();
                    });
            };
        })(jQuery),
        (function (t) {
            t.effects.effect.highlight = function (e, i) {
                var s = t(this),
                    n = ["backgroundImage", "backgroundColor", "opacity"],
                    o = t.effects.setMode(s, e.mode || "show"),
                    a = { backgroundColor: s.css("backgroundColor") };
                "hide" === o && (a.opacity = 0),
                    t.effects.save(s, n),
                    s
                        .show()
                        .css({ backgroundImage: "none", backgroundColor: e.color || "#ffff99" })
                        .animate(a, {
                            queue: !1,
                            duration: e.duration,
                            easing: e.easing,
                            complete: function () {
                                "hide" === o && s.hide(), t.effects.restore(s, n), i();
                            },
                        });
            };
        })(jQuery),
        (function (t) {
            t.effects.effect.pulsate = function (e, i) {
                var s,
                    n = t(this),
                    o = t.effects.setMode(n, e.mode || "show"),
                    a = "show" === o,
                    r = "hide" === o,
                    h = a || "hide" === o,
                    l = 2 * (e.times || 5) + (h ? 1 : 0),
                    c = e.duration / l,
                    u = 0,
                    d = n.queue(),
                    p = d.length;
                for ((a || !n.is(":visible")) && (n.css("opacity", 0).show(), (u = 1)), s = 1; l > s; s++)
                    n.animate({ opacity: u }, c, e.easing), (u = 1 - u);
                n.animate({ opacity: u }, c, e.easing),
                    n.queue(function () {
                        r && n.hide(), i();
                    }),
                    p > 1 && d.splice.apply(d, [1, 0].concat(d.splice(p, l + 1))),
                    n.dequeue();
            };
        })(jQuery),
        (function (t) {
            (t.effects.effect.puff = function (e, i) {
                var s = t(this),
                    n = t.effects.setMode(s, e.mode || "hide"),
                    o = "hide" === n,
                    a = parseInt(e.percent, 10) || 150,
                    r = a / 100,
                    h = {
                        height: s.height(),
                        width: s.width(),
                        outerHeight: s.outerHeight(),
                        outerWidth: s.outerWidth(),
                    };
                t.extend(e, {
                    effect: "scale",
                    queue: !1,
                    fade: !0,
                    mode: n,
                    complete: i,
                    percent: o ? a : 100,
                    from: o
                        ? h
                        : {
                              height: h.height * r,
                              width: h.width * r,
                              outerHeight: h.outerHeight * r,
                              outerWidth: h.outerWidth * r,
                          },
                }),
                    s.effect(e);
            }),
                (t.effects.effect.scale = function (e, i) {
                    var s = t(this),
                        n = t.extend(!0, {}, e),
                        o = t.effects.setMode(s, e.mode || "effect"),
                        a = parseInt(e.percent, 10) || (0 === parseInt(e.percent, 10) ? 0 : "hide" === o ? 0 : 100),
                        r = e.direction || "both",
                        h = e.origin,
                        l = {
                            height: s.height(),
                            width: s.width(),
                            outerHeight: s.outerHeight(),
                            outerWidth: s.outerWidth(),
                        },
                        c = { y: "horizontal" !== r ? a / 100 : 1, x: "vertical" !== r ? a / 100 : 1 };
                    (n.effect = "size"),
                        (n.queue = !1),
                        (n.complete = i),
                        "effect" !== o && ((n.origin = h || ["middle", "center"]), (n.restore = !0)),
                        (n.from =
                            e.from || ("show" === o ? { height: 0, width: 0, outerHeight: 0, outerWidth: 0 } : l)),
                        (n.to = {
                            height: l.height * c.y,
                            width: l.width * c.x,
                            outerHeight: l.outerHeight * c.y,
                            outerWidth: l.outerWidth * c.x,
                        }),
                        n.fade &&
                            ("show" === o && ((n.from.opacity = 0), (n.to.opacity = 1)),
                            "hide" === o && ((n.from.opacity = 1), (n.to.opacity = 0))),
                        s.effect(n);
                }),
                (t.effects.effect.size = function (e, i) {
                    var s,
                        n,
                        o,
                        a = t(this),
                        r = ["position", "top", "bottom", "left", "right", "width", "height", "overflow", "opacity"],
                        h = ["position", "top", "bottom", "left", "right", "overflow", "opacity"],
                        l = ["width", "height", "overflow"],
                        c = ["fontSize"],
                        u = ["borderTopWidth", "borderBottomWidth", "paddingTop", "paddingBottom"],
                        d = ["borderLeftWidth", "borderRightWidth", "paddingLeft", "paddingRight"],
                        p = t.effects.setMode(a, e.mode || "effect"),
                        f = e.restore || "effect" !== p,
                        g = e.scale || "both",
                        m = e.origin || ["middle", "center"],
                        v = a.css("position"),
                        _ = f ? r : h,
                        b = { height: 0, width: 0, outerHeight: 0, outerWidth: 0 };
                    "show" === p && a.show(),
                        (s = {
                            height: a.height(),
                            width: a.width(),
                            outerHeight: a.outerHeight(),
                            outerWidth: a.outerWidth(),
                        }),
                        "toggle" === e.mode && "show" === p
                            ? ((a.from = e.to || b), (a.to = e.from || s))
                            : ((a.from = e.from || ("show" === p ? b : s)), (a.to = e.to || ("hide" === p ? b : s))),
                        (o = {
                            from: { y: a.from.height / s.height, x: a.from.width / s.width },
                            to: { y: a.to.height / s.height, x: a.to.width / s.width },
                        }),
                        ("box" === g || "both" === g) &&
                            (o.from.y !== o.to.y &&
                                ((_ = _.concat(u)),
                                (a.from = t.effects.setTransition(a, u, o.from.y, a.from)),
                                (a.to = t.effects.setTransition(a, u, o.to.y, a.to))),
                            o.from.x !== o.to.x &&
                                ((_ = _.concat(d)),
                                (a.from = t.effects.setTransition(a, d, o.from.x, a.from)),
                                (a.to = t.effects.setTransition(a, d, o.to.x, a.to)))),
                        ("content" === g || "both" === g) &&
                            o.from.y !== o.to.y &&
                            ((_ = _.concat(c).concat(l)),
                            (a.from = t.effects.setTransition(a, c, o.from.y, a.from)),
                            (a.to = t.effects.setTransition(a, c, o.to.y, a.to))),
                        t.effects.save(a, _),
                        a.show(),
                        t.effects.createWrapper(a),
                        a.css("overflow", "hidden").css(a.from),
                        m &&
                            ((n = t.effects.getBaseline(m, s)),
                            (a.from.top = (s.outerHeight - a.outerHeight()) * n.y),
                            (a.from.left = (s.outerWidth - a.outerWidth()) * n.x),
                            (a.to.top = (s.outerHeight - a.to.outerHeight) * n.y),
                            (a.to.left = (s.outerWidth - a.to.outerWidth) * n.x)),
                        a.css(a.from),
                        ("content" === g || "both" === g) &&
                            ((u = u.concat(["marginTop", "marginBottom"]).concat(c)),
                            (d = d.concat(["marginLeft", "marginRight"])),
                            (l = r.concat(u).concat(d)),
                            a.find("*[width]").each(function () {
                                var i = t(this),
                                    s = {
                                        height: i.height(),
                                        width: i.width(),
                                        outerHeight: i.outerHeight(),
                                        outerWidth: i.outerWidth(),
                                    };
                                f && t.effects.save(i, l),
                                    (i.from = {
                                        height: s.height * o.from.y,
                                        width: s.width * o.from.x,
                                        outerHeight: s.outerHeight * o.from.y,
                                        outerWidth: s.outerWidth * o.from.x,
                                    }),
                                    (i.to = {
                                        height: s.height * o.to.y,
                                        width: s.width * o.to.x,
                                        outerHeight: s.height * o.to.y,
                                        outerWidth: s.width * o.to.x,
                                    }),
                                    o.from.y !== o.to.y &&
                                        ((i.from = t.effects.setTransition(i, u, o.from.y, i.from)),
                                        (i.to = t.effects.setTransition(i, u, o.to.y, i.to))),
                                    o.from.x !== o.to.x &&
                                        ((i.from = t.effects.setTransition(i, d, o.from.x, i.from)),
                                        (i.to = t.effects.setTransition(i, d, o.to.x, i.to))),
                                    i.css(i.from),
                                    i.animate(i.to, e.duration, e.easing, function () {
                                        f && t.effects.restore(i, l);
                                    });
                            })),
                        a.animate(a.to, {
                            queue: !1,
                            duration: e.duration,
                            easing: e.easing,
                            complete: function () {
                                0 === a.to.opacity && a.css("opacity", a.from.opacity),
                                    "hide" === p && a.hide(),
                                    t.effects.restore(a, _),
                                    f ||
                                        ("static" === v
                                            ? a.css({ position: "relative", top: a.to.top, left: a.to.left })
                                            : t.each(["top", "left"], function (t, e) {
                                                  a.css(e, function (e, i) {
                                                      var s = parseInt(i, 10),
                                                          n = t ? a.to.left : a.to.top;
                                                      return "auto" === i ? n + "px" : s + n + "px";
                                                  });
                                              })),
                                    t.effects.removeWrapper(a),
                                    i();
                            },
                        });
                });
        })(jQuery),
        (function (t) {
            t.effects.effect.shake = function (e, i) {
                var s,
                    n = t(this),
                    o = ["position", "top", "bottom", "left", "right", "height", "width"],
                    a = t.effects.setMode(n, e.mode || "effect"),
                    r = e.direction || "left",
                    h = e.distance || 20,
                    l = e.times || 3,
                    c = 2 * l + 1,
                    u = Math.round(e.duration / c),
                    d = "up" === r || "down" === r ? "top" : "left",
                    p = "up" === r || "left" === r,
                    f = {},
                    g = {},
                    m = {},
                    v = n.queue(),
                    _ = v.length;
                for (
                    t.effects.save(n, o),
                        n.show(),
                        t.effects.createWrapper(n),
                        f[d] = (p ? "-=" : "+=") + h,
                        g[d] = (p ? "+=" : "-=") + 2 * h,
                        m[d] = (p ? "-=" : "+=") + 2 * h,
                        n.animate(f, u, e.easing),
                        s = 1;
                    l > s;
                    s++
                )
                    n.animate(g, u, e.easing).animate(m, u, e.easing);
                n
                    .animate(g, u, e.easing)
                    .animate(f, u / 2, e.easing)
                    .queue(function () {
                        "hide" === a && n.hide(), t.effects.restore(n, o), t.effects.removeWrapper(n), i();
                    }),
                    _ > 1 && v.splice.apply(v, [1, 0].concat(v.splice(_, c + 1))),
                    n.dequeue();
            };
        })(jQuery),
        (function (t) {
            t.effects.effect.slide = function (e, i) {
                var s,
                    n = t(this),
                    o = ["position", "top", "bottom", "left", "right", "width", "height"],
                    a = t.effects.setMode(n, e.mode || "show"),
                    r = "show" === a,
                    h = e.direction || "left",
                    l = "up" === h || "down" === h ? "top" : "left",
                    c = "up" === h || "left" === h,
                    u = {};
                t.effects.save(n, o),
                    n.show(),
                    (s = e.distance || n["top" === l ? "outerHeight" : "outerWidth"](!0)),
                    t.effects.createWrapper(n).css({ overflow: "hidden" }),
                    r && n.css(l, c ? (isNaN(s) ? "-" + s : -s) : s),
                    (u[l] = (r ? (c ? "+=" : "-=") : c ? "-=" : "+=") + s),
                    n.animate(u, {
                        queue: !1,
                        duration: e.duration,
                        easing: e.easing,
                        complete: function () {
                            "hide" === a && n.hide(), t.effects.restore(n, o), t.effects.removeWrapper(n), i();
                        },
                    });
            };
        })(jQuery),
        (function (t) {
            t.effects.effect.transfer = function (e, i) {
                var s = t(this),
                    n = t(e.to),
                    o = "fixed" === n.css("position"),
                    a = t("body"),
                    r = o ? a.scrollTop() : 0,
                    h = o ? a.scrollLeft() : 0,
                    l = n.offset(),
                    c = { top: l.top - r, left: l.left - h, height: n.innerHeight(), width: n.innerWidth() },
                    u = s.offset(),
                    d = t("<div class='ui-effects-transfer'></div>")
                        .appendTo(document.body)
                        .addClass(e.className)
                        .css({
                            top: u.top - r,
                            left: u.left - h,
                            height: s.innerHeight(),
                            width: s.innerWidth(),
                            position: o ? "fixed" : "absolute",
                        })
                        .animate(c, e.duration, e.easing, function () {
                            d.remove(), i();
                        });
            };
        })(jQuery),
        (function (t) {
            t.widget("ui.menu", {
                version: "1.10.2",
                defaultElement: "<ul>",
                delay: 300,
                options: {
                    icons: { submenu: "ui-icon-carat-1-e" },
                    menus: "ul",
                    position: { my: "left top", at: "right top" },
                    role: "menu",
                    blur: null,
                    focus: null,
                    select: null,
                },
                _create: function () {
                    (this.activeMenu = this.element),
                        (this.mouseHandled = !1),
                        this.element
                            .uniqueId()
                            .addClass("ui-menu ui-widget ui-widget-content ui-corner-all")
                            .toggleClass("ui-menu-icons", !!this.element.find(".ui-icon").length)
                            .attr({ role: this.options.role, tabIndex: 0 })
                            .bind(
                                "click" + this.eventNamespace,
                                t.proxy(function (t) {
                                    this.options.disabled && t.preventDefault();
                                }, this)
                            ),
                        this.options.disabled &&
                            this.element.addClass("ui-state-disabled").attr("aria-disabled", "true"),
                        this._on({
                            "mousedown .ui-menu-item > a": function (t) {
                                t.preventDefault();
                            },
                            "click .ui-state-disabled > a": function (t) {
                                t.preventDefault();
                            },
                            "click .ui-menu-item:has(a)": function (e) {
                                var i = t(e.target).closest(".ui-menu-item");
                                !this.mouseHandled &&
                                    i.not(".ui-state-disabled").length &&
                                    ((this.mouseHandled = !0),
                                    this.select(e),
                                    i.has(".ui-menu").length
                                        ? this.expand(e)
                                        : this.element.is(":focus") ||
                                          (this.element.trigger("focus", [!0]),
                                          this.active &&
                                              1 === this.active.parents(".ui-menu").length &&
                                              clearTimeout(this.timer)));
                            },
                            "mouseenter .ui-menu-item": function (e) {
                                var i = t(e.currentTarget);
                                i.siblings().children(".ui-state-active").removeClass("ui-state-active"),
                                    this.focus(e, i);
                            },
                            mouseleave: "collapseAll",
                            "mouseleave .ui-menu": "collapseAll",
                            focus: function (t, e) {
                                var i = this.active || this.element.children(".ui-menu-item").eq(0);
                                e || this.focus(t, i);
                            },
                            blur: function (e) {
                                this._delay(function () {
                                    t.contains(this.element[0], this.document[0].activeElement) || this.collapseAll(e);
                                });
                            },
                            keydown: "_keydown",
                        }),
                        this.refresh(),
                        this._on(this.document, {
                            click: function (e) {
                                t(e.target).closest(".ui-menu").length || this.collapseAll(e), (this.mouseHandled = !1);
                            },
                        });
                },
                _destroy: function () {
                    this.element
                        .removeAttr("aria-activedescendant")
                        .find(".ui-menu")
                        .addBack()
                        .removeClass("ui-menu ui-widget ui-widget-content ui-corner-all ui-menu-icons")
                        .removeAttr("role")
                        .removeAttr("tabIndex")
                        .removeAttr("aria-labelledby")
                        .removeAttr("aria-expanded")
                        .removeAttr("aria-hidden")
                        .removeAttr("aria-disabled")
                        .removeUniqueId()
                        .show(),
                        this.element
                            .find(".ui-menu-item")
                            .removeClass("ui-menu-item")
                            .removeAttr("role")
                            .removeAttr("aria-disabled")
                            .children("a")
                            .removeUniqueId()
                            .removeClass("ui-corner-all ui-state-hover")
                            .removeAttr("tabIndex")
                            .removeAttr("role")
                            .removeAttr("aria-haspopup")
                            .children()
                            .each(function () {
                                var e = t(this);
                                e.data("ui-menu-submenu-carat") && e.remove();
                            }),
                        this.element.find(".ui-menu-divider").removeClass("ui-menu-divider ui-widget-content");
                },
                _keydown: function (e) {
                    function i(t) {
                        return t.replace(/[\-\[\]{}()*+?.,\\\^$|#\s]/g, "\\$&");
                    }
                    var s,
                        n,
                        o,
                        a,
                        r,
                        h = !0;
                    switch (e.keyCode) {
                        case t.ui.keyCode.PAGE_UP:
                            this.previousPage(e);
                            break;
                        case t.ui.keyCode.PAGE_DOWN:
                            this.nextPage(e);
                            break;
                        case t.ui.keyCode.HOME:
                            this._move("first", "first", e);
                            break;
                        case t.ui.keyCode.END:
                            this._move("last", "last", e);
                            break;
                        case t.ui.keyCode.UP:
                            this.previous(e);
                            break;
                        case t.ui.keyCode.DOWN:
                            this.next(e);
                            break;
                        case t.ui.keyCode.LEFT:
                            this.collapse(e);
                            break;
                        case t.ui.keyCode.RIGHT:
                            this.active && !this.active.is(".ui-state-disabled") && this.expand(e);
                            break;
                        case t.ui.keyCode.ENTER:
                        case t.ui.keyCode.SPACE:
                            this._activate(e);
                            break;
                        case t.ui.keyCode.ESCAPE:
                            this.collapse(e);
                            break;
                        default:
                            (h = !1),
                                (n = this.previousFilter || ""),
                                (o = String.fromCharCode(e.keyCode)),
                                (a = !1),
                                clearTimeout(this.filterTimer),
                                o === n ? (a = !0) : (o = n + o),
                                (r = RegExp("^" + i(o), "i")),
                                (s = this.activeMenu.children(".ui-menu-item").filter(function () {
                                    return r.test(t(this).children("a").text());
                                })),
                                (s =
                                    a && -1 !== s.index(this.active.next()) ? this.active.nextAll(".ui-menu-item") : s),
                                s.length ||
                                    ((o = String.fromCharCode(e.keyCode)),
                                    (r = RegExp("^" + i(o), "i")),
                                    (s = this.activeMenu.children(".ui-menu-item").filter(function () {
                                        return r.test(t(this).children("a").text());
                                    }))),
                                s.length
                                    ? (this.focus(e, s),
                                      s.length > 1
                                          ? ((this.previousFilter = o),
                                            (this.filterTimer = this._delay(function () {
                                                delete this.previousFilter;
                                            }, 1e3)))
                                          : delete this.previousFilter)
                                    : delete this.previousFilter;
                    }
                    h && e.preventDefault();
                },
                _activate: function (t) {
                    this.active.is(".ui-state-disabled") ||
                        (this.active.children("a[aria-haspopup='true']").length ? this.expand(t) : this.select(t));
                },
                refresh: function () {
                    var e,
                        i = this.options.icons.submenu,
                        s = this.element.find(this.options.menus);
                    s
                        .filter(":not(.ui-menu)")
                        .addClass("ui-menu ui-widget ui-widget-content ui-corner-all")
                        .hide()
                        .attr({ role: this.options.role, "aria-hidden": "true", "aria-expanded": "false" })
                        .each(function () {
                            var e = t(this),
                                s = e.prev("a"),
                                n = t("<span>")
                                    .addClass("ui-menu-icon ui-icon " + i)
                                    .data("ui-menu-submenu-carat", !0);
                            s.attr("aria-haspopup", "true").prepend(n), e.attr("aria-labelledby", s.attr("id"));
                        }),
                        (e = s.add(this.element)),
                        e
                            .children(":not(.ui-menu-item):has(a)")
                            .addClass("ui-menu-item")
                            .attr("role", "presentation")
                            .children("a")
                            .uniqueId()
                            .addClass("ui-corner-all")
                            .attr({ tabIndex: -1, role: this._itemRole() }),
                        e.children(":not(.ui-menu-item)").each(function () {
                            var e = t(this);
                            /[^\-\u2014\u2013\s]/.test(e.text()) || e.addClass("ui-widget-content ui-menu-divider");
                        }),
                        e.children(".ui-state-disabled").attr("aria-disabled", "true"),
                        this.active && !t.contains(this.element[0], this.active[0]) && this.blur();
                },
                _itemRole: function () {
                    return { menu: "menuitem", listbox: "option" }[this.options.role];
                },
                _setOption: function (t, e) {
                    "icons" === t &&
                        this.element.find(".ui-menu-icon").removeClass(this.options.icons.submenu).addClass(e.submenu),
                        this._super(t, e);
                },
                focus: function (t, e) {
                    var i, s;
                    this.blur(t, t && "focus" === t.type),
                        this._scrollIntoView(e),
                        (this.active = e.first()),
                        (s = this.active.children("a").addClass("ui-state-focus")),
                        this.options.role && this.element.attr("aria-activedescendant", s.attr("id")),
                        this.active.parent().closest(".ui-menu-item").children("a:first").addClass("ui-state-active"),
                        t && "keydown" === t.type
                            ? this._close()
                            : (this.timer = this._delay(function () {
                                  this._close();
                              }, this.delay)),
                        (i = e.children(".ui-menu")),
                        i.length && /^mouse/.test(t.type) && this._startOpening(i),
                        (this.activeMenu = e.parent()),
                        this._trigger("focus", t, { item: e });
                },
                _scrollIntoView: function (e) {
                    var i, s, n, o, a, r;
                    this._hasScroll() &&
                        ((i = parseFloat(t.css(this.activeMenu[0], "borderTopWidth")) || 0),
                        (s = parseFloat(t.css(this.activeMenu[0], "paddingTop")) || 0),
                        (n = e.offset().top - this.activeMenu.offset().top - i - s),
                        (o = this.activeMenu.scrollTop()),
                        (a = this.activeMenu.height()),
                        (r = e.height()),
                        0 > n
                            ? this.activeMenu.scrollTop(o + n)
                            : n + r > a && this.activeMenu.scrollTop(o + n - a + r));
                },
                blur: function (t, e) {
                    e || clearTimeout(this.timer),
                        this.active &&
                            (this.active.children("a").removeClass("ui-state-focus"),
                            (this.active = null),
                            this._trigger("blur", t, { item: this.active }));
                },
                _startOpening: function (t) {
                    clearTimeout(this.timer),
                        "true" === t.attr("aria-hidden") &&
                            (this.timer = this._delay(function () {
                                this._close(), this._open(t);
                            }, this.delay));
                },
                _open: function (e) {
                    var i = t.extend({ of: this.active }, this.options.position);
                    clearTimeout(this.timer),
                        this.element.find(".ui-menu").not(e.parents(".ui-menu")).hide().attr("aria-hidden", "true"),
                        e.show().removeAttr("aria-hidden").attr("aria-expanded", "true").position(i);
                },
                collapseAll: function (e, i) {
                    clearTimeout(this.timer),
                        (this.timer = this._delay(function () {
                            var s = i ? this.element : t(e && e.target).closest(this.element.find(".ui-menu"));
                            s.length || (s = this.element), this._close(s), this.blur(e), (this.activeMenu = s);
                        }, this.delay));
                },
                _close: function (t) {
                    t || (t = this.active ? this.active.parent() : this.element),
                        t
                            .find(".ui-menu")
                            .hide()
                            .attr("aria-hidden", "true")
                            .attr("aria-expanded", "false")
                            .end()
                            .find("a.ui-state-active")
                            .removeClass("ui-state-active");
                },
                collapse: function (t) {
                    var e = this.active && this.active.parent().closest(".ui-menu-item", this.element);
                    e && e.length && (this._close(), this.focus(t, e));
                },
                expand: function (t) {
                    var e = this.active && this.active.children(".ui-menu ").children(".ui-menu-item").first();
                    e &&
                        e.length &&
                        (this._open(e.parent()),
                        this._delay(function () {
                            this.focus(t, e);
                        }));
                },
                next: function (t) {
                    this._move("next", "first", t);
                },
                previous: function (t) {
                    this._move("prev", "last", t);
                },
                isFirstItem: function () {
                    return this.active && !this.active.prevAll(".ui-menu-item").length;
                },
                isLastItem: function () {
                    return this.active && !this.active.nextAll(".ui-menu-item").length;
                },
                _move: function (t, e, i) {
                    var s;
                    this.active &&
                        (s =
                            "first" === t || "last" === t
                                ? this.active["first" === t ? "prevAll" : "nextAll"](".ui-menu-item").eq(-1)
                                : this.active[t + "All"](".ui-menu-item").eq(0)),
                        (s && s.length && this.active) || (s = this.activeMenu.children(".ui-menu-item")[e]()),
                        this.focus(i, s);
                },
                nextPage: function (e) {
                    var i, s, n;
                    return this.active
                        ? (this.isLastItem() ||
                              (this._hasScroll()
                                  ? ((s = this.active.offset().top),
                                    (n = this.element.height()),
                                    this.active.nextAll(".ui-menu-item").each(function () {
                                        return (i = t(this)), 0 > i.offset().top - s - n;
                                    }),
                                    this.focus(e, i))
                                  : this.focus(
                                        e,
                                        this.activeMenu.children(".ui-menu-item")[this.active ? "last" : "first"]()
                                    )),
                          undefined)
                        : (this.next(e), undefined);
                },
                previousPage: function (e) {
                    var i, s, n;
                    return this.active
                        ? (this.isFirstItem() ||
                              (this._hasScroll()
                                  ? ((s = this.active.offset().top),
                                    (n = this.element.height()),
                                    this.active.prevAll(".ui-menu-item").each(function () {
                                        return (i = t(this)), i.offset().top - s + n > 0;
                                    }),
                                    this.focus(e, i))
                                  : this.focus(e, this.activeMenu.children(".ui-menu-item").first())),
                          undefined)
                        : (this.next(e), undefined);
                },
                _hasScroll: function () {
                    return this.element.outerHeight() < this.element.prop("scrollHeight");
                },
                select: function (e) {
                    this.active = this.active || t(e.target).closest(".ui-menu-item");
                    var i = { item: this.active };
                    this.active.has(".ui-menu").length || this.collapseAll(e, !0), this._trigger("select", e, i);
                },
            });
        })(jQuery),
        (function (t, e) {
            function i(t, e, i) {
                return [
                    parseFloat(t[0]) * (p.test(t[0]) ? e / 100 : 1),
                    parseFloat(t[1]) * (p.test(t[1]) ? i / 100 : 1),
                ];
            }
            function s(e, i) {
                return parseInt(t.css(e, i), 10) || 0;
            }
            function n(e) {
                var i = e[0];
                return 9 === i.nodeType
                    ? { width: e.width(), height: e.height(), offset: { top: 0, left: 0 } }
                    : t.isWindow(i)
                      ? { width: e.width(), height: e.height(), offset: { top: e.scrollTop(), left: e.scrollLeft() } }
                      : i.preventDefault
                        ? { width: 0, height: 0, offset: { top: i.pageY, left: i.pageX } }
                        : { width: e.outerWidth(), height: e.outerHeight(), offset: e.offset() };
            }
            t.ui = t.ui || {};
            var o,
                a = Math.max,
                r = Math.abs,
                h = Math.round,
                l = /left|center|right/,
                c = /top|center|bottom/,
                u = /[\+\-]\d+(\.[\d]+)?%?/,
                d = /^\w+/,
                p = /%$/,
                f = t.fn.position;
            (t.position = {
                scrollbarWidth: function () {
                    if (o !== e) return o;
                    var i,
                        s,
                        n = t(
                            "<div style='display:block;width:50px;height:50px;overflow:hidden;'><div style='height:100px;width:auto;'></div></div>"
                        ),
                        a = n.children()[0];
                    return (
                        t("body").append(n),
                        (i = a.offsetWidth),
                        n.css("overflow", "scroll"),
                        (s = a.offsetWidth),
                        i === s && (s = n[0].clientWidth),
                        n.remove(),
                        (o = i - s)
                    );
                },
                getScrollInfo: function (e) {
                    var i = e.isWindow ? "" : e.element.css("overflow-x"),
                        s = e.isWindow ? "" : e.element.css("overflow-y"),
                        n = "scroll" === i || ("auto" === i && e.width < e.element[0].scrollWidth),
                        o = "scroll" === s || ("auto" === s && e.height < e.element[0].scrollHeight);
                    return { width: o ? t.position.scrollbarWidth() : 0, height: n ? t.position.scrollbarWidth() : 0 };
                },
                getWithinInfo: function (e) {
                    var i = t(e || window),
                        s = t.isWindow(i[0]);
                    return {
                        element: i,
                        isWindow: s,
                        offset: i.offset() || { left: 0, top: 0 },
                        scrollLeft: i.scrollLeft(),
                        scrollTop: i.scrollTop(),
                        width: s ? i.width() : i.outerWidth(),
                        height: s ? i.height() : i.outerHeight(),
                    };
                },
            }),
                (t.fn.position = function (e) {
                    if (!e || !e.of) return f.apply(this, arguments);
                    e = t.extend({}, e);
                    var o,
                        p,
                        g,
                        m,
                        v,
                        _,
                        b = t(e.of),
                        y = t.position.getWithinInfo(e.within),
                        w = t.position.getScrollInfo(y),
                        k = (e.collision || "flip").split(" "),
                        x = {};
                    return (
                        (_ = n(b)),
                        b[0].preventDefault && (e.at = "left top"),
                        (p = _.width),
                        (g = _.height),
                        (m = _.offset),
                        (v = t.extend({}, m)),
                        t.each(["my", "at"], function () {
                            var t,
                                i,
                                s = (e[this] || "").split(" ");
                            1 === s.length &&
                                (s = l.test(s[0])
                                    ? s.concat(["center"])
                                    : c.test(s[0])
                                      ? ["center"].concat(s)
                                      : ["center", "center"]),
                                (s[0] = l.test(s[0]) ? s[0] : "center"),
                                (s[1] = c.test(s[1]) ? s[1] : "center"),
                                (t = u.exec(s[0])),
                                (i = u.exec(s[1])),
                                (x[this] = [t ? t[0] : 0, i ? i[0] : 0]),
                                (e[this] = [d.exec(s[0])[0], d.exec(s[1])[0]]);
                        }),
                        1 === k.length && (k[1] = k[0]),
                        "right" === e.at[0] ? (v.left += p) : "center" === e.at[0] && (v.left += p / 2),
                        "bottom" === e.at[1] ? (v.top += g) : "center" === e.at[1] && (v.top += g / 2),
                        (o = i(x.at, p, g)),
                        (v.left += o[0]),
                        (v.top += o[1]),
                        this.each(function () {
                            var n,
                                l,
                                c = t(this),
                                u = c.outerWidth(),
                                d = c.outerHeight(),
                                f = s(this, "marginLeft"),
                                _ = s(this, "marginTop"),
                                D = u + f + s(this, "marginRight") + w.width,
                                C = d + _ + s(this, "marginBottom") + w.height,
                                I = t.extend({}, v),
                                P = i(x.my, c.outerWidth(), c.outerHeight());
                            "right" === e.my[0] ? (I.left -= u) : "center" === e.my[0] && (I.left -= u / 2),
                                "bottom" === e.my[1] ? (I.top -= d) : "center" === e.my[1] && (I.top -= d / 2),
                                (I.left += P[0]),
                                (I.top += P[1]),
                                t.support.offsetFractions || ((I.left = h(I.left)), (I.top = h(I.top))),
                                (n = { marginLeft: f, marginTop: _ }),
                                t.each(["left", "top"], function (i, s) {
                                    t.ui.position[k[i]] &&
                                        t.ui.position[k[i]][s](I, {
                                            targetWidth: p,
                                            targetHeight: g,
                                            elemWidth: u,
                                            elemHeight: d,
                                            collisionPosition: n,
                                            collisionWidth: D,
                                            collisionHeight: C,
                                            offset: [o[0] + P[0], o[1] + P[1]],
                                            my: e.my,
                                            at: e.at,
                                            within: y,
                                            elem: c,
                                        });
                                }),
                                e.using &&
                                    (l = function (t) {
                                        var i = m.left - I.left,
                                            s = i + p - u,
                                            n = m.top - I.top,
                                            o = n + g - d,
                                            h = {
                                                target: { element: b, left: m.left, top: m.top, width: p, height: g },
                                                element: { element: c, left: I.left, top: I.top, width: u, height: d },
                                                horizontal: 0 > s ? "left" : i > 0 ? "right" : "center",
                                                vertical: 0 > o ? "top" : n > 0 ? "bottom" : "middle",
                                            };
                                        u > p && p > r(i + s) && (h.horizontal = "center"),
                                            d > g && g > r(n + o) && (h.vertical = "middle"),
                                            (h.important = a(r(i), r(s)) > a(r(n), r(o)) ? "horizontal" : "vertical"),
                                            e.using.call(this, t, h);
                                    }),
                                c.offset(t.extend(I, { using: l }));
                        })
                    );
                }),
                (t.ui.position = {
                    fit: {
                        left: function (t, e) {
                            var i,
                                s = e.within,
                                n = s.isWindow ? s.scrollLeft : s.offset.left,
                                o = s.width,
                                r = t.left - e.collisionPosition.marginLeft,
                                h = n - r,
                                l = r + e.collisionWidth - o - n;
                            e.collisionWidth > o
                                ? h > 0 && 0 >= l
                                    ? ((i = t.left + h + e.collisionWidth - o - n), (t.left += h - i))
                                    : (t.left = l > 0 && 0 >= h ? n : h > l ? n + o - e.collisionWidth : n)
                                : h > 0
                                  ? (t.left += h)
                                  : l > 0
                                    ? (t.left -= l)
                                    : (t.left = a(t.left - r, t.left));
                        },
                        top: function (t, e) {
                            var i,
                                s = e.within,
                                n = s.isWindow ? s.scrollTop : s.offset.top,
                                o = e.within.height,
                                r = t.top - e.collisionPosition.marginTop,
                                h = n - r,
                                l = r + e.collisionHeight - o - n;
                            e.collisionHeight > o
                                ? h > 0 && 0 >= l
                                    ? ((i = t.top + h + e.collisionHeight - o - n), (t.top += h - i))
                                    : (t.top = l > 0 && 0 >= h ? n : h > l ? n + o - e.collisionHeight : n)
                                : h > 0
                                  ? (t.top += h)
                                  : l > 0
                                    ? (t.top -= l)
                                    : (t.top = a(t.top - r, t.top));
                        },
                    },
                    flip: {
                        left: function (t, e) {
                            var i,
                                s,
                                n = e.within,
                                o = n.offset.left + n.scrollLeft,
                                a = n.width,
                                h = n.isWindow ? n.scrollLeft : n.offset.left,
                                l = t.left - e.collisionPosition.marginLeft,
                                c = l - h,
                                u = l + e.collisionWidth - a - h,
                                d = "left" === e.my[0] ? -e.elemWidth : "right" === e.my[0] ? e.elemWidth : 0,
                                p = "left" === e.at[0] ? e.targetWidth : "right" === e.at[0] ? -e.targetWidth : 0,
                                f = -2 * e.offset[0];
                            0 > c
                                ? ((i = t.left + d + p + f + e.collisionWidth - a - o),
                                  (0 > i || r(c) > i) && (t.left += d + p + f))
                                : u > 0 &&
                                  ((s = t.left - e.collisionPosition.marginLeft + d + p + f - h),
                                  (s > 0 || u > r(s)) && (t.left += d + p + f));
                        },
                        top: function (t, e) {
                            var i,
                                s,
                                n = e.within,
                                o = n.offset.top + n.scrollTop,
                                a = n.height,
                                h = n.isWindow ? n.scrollTop : n.offset.top,
                                l = t.top - e.collisionPosition.marginTop,
                                c = l - h,
                                u = l + e.collisionHeight - a - h,
                                d = "top" === e.my[1],
                                p = d ? -e.elemHeight : "bottom" === e.my[1] ? e.elemHeight : 0,
                                f = "top" === e.at[1] ? e.targetHeight : "bottom" === e.at[1] ? -e.targetHeight : 0,
                                g = -2 * e.offset[1];
                            0 > c
                                ? ((s = t.top + p + f + g + e.collisionHeight - a - o),
                                  t.top + p + f + g > c && (0 > s || r(c) > s) && (t.top += p + f + g))
                                : u > 0 &&
                                  ((i = t.top - e.collisionPosition.marginTop + p + f + g - h),
                                  t.top + p + f + g > u && (i > 0 || u > r(i)) && (t.top += p + f + g));
                        },
                    },
                    flipfit: {
                        left: function () {
                            t.ui.position.flip.left.apply(this, arguments),
                                t.ui.position.fit.left.apply(this, arguments);
                        },
                        top: function () {
                            t.ui.position.flip.top.apply(this, arguments), t.ui.position.fit.top.apply(this, arguments);
                        },
                    },
                }),
                (function () {
                    var e,
                        i,
                        s,
                        n,
                        o,
                        a = document.getElementsByTagName("body")[0],
                        r = document.createElement("div");
                    (e = document.createElement(a ? "div" : "body")),
                        (s = { visibility: "hidden", width: 0, height: 0, border: 0, margin: 0, background: "none" }),
                        a && t.extend(s, { position: "absolute", left: "-1000px", top: "-1000px" });
                    for (o in s) e.style[o] = s[o];
                    e.appendChild(r),
                        (i = a || document.documentElement),
                        i.insertBefore(e, i.firstChild),
                        (r.style.cssText = "position: absolute; left: 10.7432222px;"),
                        (n = t(r).offset().left),
                        (t.support.offsetFractions = n > 10 && 11 > n),
                        (e.innerHTML = ""),
                        i.removeChild(e);
                })();
        })(jQuery),
        (function (t, e) {
            t.widget("ui.progressbar", {
                version: "1.10.2",
                options: { max: 100, value: 0, change: null, complete: null },
                min: 0,
                _create: function () {
                    (this.oldValue = this.options.value = this._constrainedValue()),
                        this.element
                            .addClass("ui-progressbar ui-widget ui-widget-content ui-corner-all")
                            .attr({ role: "progressbar", "aria-valuemin": this.min }),
                        (this.valueDiv = t(
                            "<div class='ui-progressbar-value ui-widget-header ui-corner-left'></div>"
                        ).appendTo(this.element)),
                        this._refreshValue();
                },
                _destroy: function () {
                    this.element
                        .removeClass("ui-progressbar ui-widget ui-widget-content ui-corner-all")
                        .removeAttr("role")
                        .removeAttr("aria-valuemin")
                        .removeAttr("aria-valuemax")
                        .removeAttr("aria-valuenow"),
                        this.valueDiv.remove();
                },
                value: function (t) {
                    return t === e
                        ? this.options.value
                        : ((this.options.value = this._constrainedValue(t)), this._refreshValue(), e);
                },
                _constrainedValue: function (t) {
                    return (
                        t === e && (t = this.options.value),
                        (this.indeterminate = t === !1),
                        "number" != typeof t && (t = 0),
                        this.indeterminate ? !1 : Math.min(this.options.max, Math.max(this.min, t))
                    );
                },
                _setOptions: function (t) {
                    var e = t.value;
                    delete t.value,
                        this._super(t),
                        (this.options.value = this._constrainedValue(e)),
                        this._refreshValue();
                },
                _setOption: function (t, e) {
                    "max" === t && (e = Math.max(this.min, e)), this._super(t, e);
                },
                _percentage: function () {
                    return this.indeterminate
                        ? 100
                        : (100 * (this.options.value - this.min)) / (this.options.max - this.min);
                },
                _refreshValue: function () {
                    var e = this.options.value,
                        i = this._percentage();
                    this.valueDiv
                        .toggle(this.indeterminate || e > this.min)
                        .toggleClass("ui-corner-right", e === this.options.max)
                        .width(i.toFixed(0) + "%"),
                        this.element.toggleClass("ui-progressbar-indeterminate", this.indeterminate),
                        this.indeterminate
                            ? (this.element.removeAttr("aria-valuenow"),
                              this.overlayDiv ||
                                  (this.overlayDiv = t("<div class='ui-progressbar-overlay'></div>").appendTo(
                                      this.valueDiv
                                  )))
                            : (this.element.attr({ "aria-valuemax": this.options.max, "aria-valuenow": e }),
                              this.overlayDiv && (this.overlayDiv.remove(), (this.overlayDiv = null))),
                        this.oldValue !== e && ((this.oldValue = e), this._trigger("change")),
                        e === this.options.max && this._trigger("complete");
                },
            });
        })(jQuery),
        (function (t) {
            var e = 5;
            t.widget("ui.slider", t.ui.mouse, {
                version: "1.10.2",
                widgetEventPrefix: "slide",
                options: {
                    animate: !1,
                    distance: 0,
                    max: 100,
                    min: 0,
                    orientation: "horizontal",
                    range: !1,
                    step: 1,
                    value: 0,
                    values: null,
                    change: null,
                    slide: null,
                    start: null,
                    stop: null,
                },
                _create: function () {
                    (this._keySliding = !1),
                        (this._mouseSliding = !1),
                        (this._animateOff = !0),
                        (this._handleIndex = null),
                        this._detectOrientation(),
                        this._mouseInit(),
                        this.element.addClass(
                            "ui-slider ui-slider-" +
                                this.orientation +
                                " ui-widget" +
                                " ui-widget-content" +
                                " ui-corner-all"
                        ),
                        this._refresh(),
                        this._setOption("disabled", this.options.disabled),
                        (this._animateOff = !1);
                },
                _refresh: function () {
                    this._createRange(), this._createHandles(), this._setupEvents(), this._refreshValue();
                },
                _createHandles: function () {
                    var e,
                        i,
                        s = this.options,
                        n = this.element.find(".ui-slider-handle").addClass("ui-state-default ui-corner-all"),
                        o = "<a class='ui-slider-handle ui-state-default ui-corner-all' href='#'></a>",
                        a = [];
                    for (
                        i = (s.values && s.values.length) || 1,
                            n.length > i && (n.slice(i).remove(), (n = n.slice(0, i))),
                            e = n.length;
                        i > e;
                        e++
                    )
                        a.push(o);
                    (this.handles = n.add(t(a.join("")).appendTo(this.element))),
                        (this.handle = this.handles.eq(0)),
                        this.handles.each(function (e) {
                            t(this).data("ui-slider-handle-index", e);
                        });
                },
                _createRange: function () {
                    var e = this.options,
                        i = "";
                    e.range
                        ? (e.range === !0 &&
                              (e.values
                                  ? e.values.length && 2 !== e.values.length
                                      ? (e.values = [e.values[0], e.values[0]])
                                      : t.isArray(e.values) && (e.values = e.values.slice(0))
                                  : (e.values = [this._valueMin(), this._valueMin()])),
                          this.range && this.range.length
                              ? this.range
                                    .removeClass("ui-slider-range-min ui-slider-range-max")
                                    .css({ left: "", bottom: "" })
                              : ((this.range = t("<div></div>").appendTo(this.element)),
                                (i = "ui-slider-range ui-widget-header ui-corner-all")),
                          this.range.addClass(
                              i + ("min" === e.range || "max" === e.range ? " ui-slider-range-" + e.range : "")
                          ))
                        : (this.range = t([]));
                },
                _setupEvents: function () {
                    var t = this.handles.add(this.range).filter("a");
                    this._off(t), this._on(t, this._handleEvents), this._hoverable(t), this._focusable(t);
                },
                _destroy: function () {
                    this.handles.remove(),
                        this.range.remove(),
                        this.element.removeClass(
                            "ui-slider ui-slider-horizontal ui-slider-vertical ui-widget ui-widget-content ui-corner-all"
                        ),
                        this._mouseDestroy();
                },
                _mouseCapture: function (e) {
                    var i,
                        s,
                        n,
                        o,
                        a,
                        r,
                        h,
                        l,
                        c = this,
                        u = this.options;
                    return u.disabled
                        ? !1
                        : ((this.elementSize = {
                              width: this.element.outerWidth(),
                              height: this.element.outerHeight(),
                          }),
                          (this.elementOffset = this.element.offset()),
                          (i = { x: e.pageX, y: e.pageY }),
                          (s = this._normValueFromMouse(i)),
                          (n = this._valueMax() - this._valueMin() + 1),
                          this.handles.each(function (e) {
                              var i = Math.abs(s - c.values(e));
                              (n > i || (n === i && (e === c._lastChangedValue || c.values(e) === u.min))) &&
                                  ((n = i), (o = t(this)), (a = e));
                          }),
                          (r = this._start(e, a)),
                          r === !1
                              ? !1
                              : ((this._mouseSliding = !0),
                                (this._handleIndex = a),
                                o.addClass("ui-state-active").focus(),
                                (h = o.offset()),
                                (l = !t(e.target).parents().addBack().is(".ui-slider-handle")),
                                (this._clickOffset = l
                                    ? { left: 0, top: 0 }
                                    : {
                                          left: e.pageX - h.left - o.width() / 2,
                                          top:
                                              e.pageY -
                                              h.top -
                                              o.height() / 2 -
                                              (parseInt(o.css("borderTopWidth"), 10) || 0) -
                                              (parseInt(o.css("borderBottomWidth"), 10) || 0) +
                                              (parseInt(o.css("marginTop"), 10) || 0),
                                      }),
                                this.handles.hasClass("ui-state-hover") || this._slide(e, a, s),
                                (this._animateOff = !0),
                                !0));
                },
                _mouseStart: function () {
                    return !0;
                },
                _mouseDrag: function (t) {
                    var e = { x: t.pageX, y: t.pageY },
                        i = this._normValueFromMouse(e);
                    return this._slide(t, this._handleIndex, i), !1;
                },
                _mouseStop: function (t) {
                    return (
                        this.handles.removeClass("ui-state-active"),
                        (this._mouseSliding = !1),
                        this._stop(t, this._handleIndex),
                        this._change(t, this._handleIndex),
                        (this._handleIndex = null),
                        (this._clickOffset = null),
                        (this._animateOff = !1),
                        !1
                    );
                },
                _detectOrientation: function () {
                    this.orientation = "vertical" === this.options.orientation ? "vertical" : "horizontal";
                },
                _normValueFromMouse: function (t) {
                    var e, i, s, n, o;
                    return (
                        "horizontal" === this.orientation
                            ? ((e = this.elementSize.width),
                              (i = t.x - this.elementOffset.left - (this._clickOffset ? this._clickOffset.left : 0)))
                            : ((e = this.elementSize.height),
                              (i = t.y - this.elementOffset.top - (this._clickOffset ? this._clickOffset.top : 0))),
                        (s = i / e),
                        s > 1 && (s = 1),
                        0 > s && (s = 0),
                        "vertical" === this.orientation && (s = 1 - s),
                        (n = this._valueMax() - this._valueMin()),
                        (o = this._valueMin() + s * n),
                        this._trimAlignValue(o)
                    );
                },
                _start: function (t, e) {
                    var i = { handle: this.handles[e], value: this.value() };
                    return (
                        this.options.values &&
                            this.options.values.length &&
                            ((i.value = this.values(e)), (i.values = this.values())),
                        this._trigger("start", t, i)
                    );
                },
                _slide: function (t, e, i) {
                    var s, n, o;
                    this.options.values && this.options.values.length
                        ? ((s = this.values(e ? 0 : 1)),
                          2 === this.options.values.length &&
                              this.options.range === !0 &&
                              ((0 === e && i > s) || (1 === e && s > i)) &&
                              (i = s),
                          i !== this.values(e) &&
                              ((n = this.values()),
                              (n[e] = i),
                              (o = this._trigger("slide", t, { handle: this.handles[e], value: i, values: n })),
                              (s = this.values(e ? 0 : 1)),
                              o !== !1 && this.values(e, i, !0)))
                        : i !== this.value() &&
                          ((o = this._trigger("slide", t, { handle: this.handles[e], value: i })),
                          o !== !1 && this.value(i));
                },
                _stop: function (t, e) {
                    var i = { handle: this.handles[e], value: this.value() };
                    this.options.values &&
                        this.options.values.length &&
                        ((i.value = this.values(e)), (i.values = this.values())),
                        this._trigger("stop", t, i);
                },
                _change: function (t, e) {
                    if (!this._keySliding && !this._mouseSliding) {
                        var i = { handle: this.handles[e], value: this.value() };
                        this.options.values &&
                            this.options.values.length &&
                            ((i.value = this.values(e)), (i.values = this.values())),
                            (this._lastChangedValue = e),
                            this._trigger("change", t, i);
                    }
                },
                value: function (t) {
                    return arguments.length
                        ? ((this.options.value = this._trimAlignValue(t)),
                          this._refreshValue(),
                          this._change(null, 0),
                          undefined)
                        : this._value();
                },
                values: function (e, i) {
                    var s, n, o;
                    if (arguments.length > 1)
                        return (
                            (this.options.values[e] = this._trimAlignValue(i)),
                            this._refreshValue(),
                            this._change(null, e),
                            undefined
                        );
                    if (!arguments.length) return this._values();
                    if (!t.isArray(arguments[0]))
                        return this.options.values && this.options.values.length ? this._values(e) : this.value();
                    for (s = this.options.values, n = arguments[0], o = 0; s.length > o; o += 1)
                        (s[o] = this._trimAlignValue(n[o])), this._change(null, o);
                    this._refreshValue();
                },
                _setOption: function (e, i) {
                    var s,
                        n = 0;
                    switch (
                        ("range" === e &&
                            this.options.range === !0 &&
                            ("min" === i
                                ? ((this.options.value = this._values(0)), (this.options.values = null))
                                : "max" === i &&
                                  ((this.options.value = this._values(this.options.values.length - 1)),
                                  (this.options.values = null))),
                        t.isArray(this.options.values) && (n = this.options.values.length),
                        t.Widget.prototype._setOption.apply(this, arguments),
                        e)
                    ) {
                        case "orientation":
                            this._detectOrientation(),
                                this.element
                                    .removeClass("ui-slider-horizontal ui-slider-vertical")
                                    .addClass("ui-slider-" + this.orientation),
                                this._refreshValue();
                            break;
                        case "value":
                            (this._animateOff = !0),
                                this._refreshValue(),
                                this._change(null, 0),
                                (this._animateOff = !1);
                            break;
                        case "values":
                            for (this._animateOff = !0, this._refreshValue(), s = 0; n > s; s += 1)
                                this._change(null, s);
                            this._animateOff = !1;
                            break;
                        case "min":
                        case "max":
                            (this._animateOff = !0), this._refreshValue(), (this._animateOff = !1);
                            break;
                        case "range":
                            (this._animateOff = !0), this._refresh(), (this._animateOff = !1);
                    }
                },
                _value: function () {
                    var t = this.options.value;
                    return (t = this._trimAlignValue(t));
                },
                _values: function (t) {
                    var e, i, s;
                    if (arguments.length) return (e = this.options.values[t]), (e = this._trimAlignValue(e));
                    if (this.options.values && this.options.values.length) {
                        for (i = this.options.values.slice(), s = 0; i.length > s; s += 1)
                            i[s] = this._trimAlignValue(i[s]);
                        return i;
                    }
                    return [];
                },
                _trimAlignValue: function (t) {
                    if (this._valueMin() >= t) return this._valueMin();
                    if (t >= this._valueMax()) return this._valueMax();
                    var e = this.options.step > 0 ? this.options.step : 1,
                        i = (t - this._valueMin()) % e,
                        s = t - i;
                    return 2 * Math.abs(i) >= e && (s += i > 0 ? e : -e), parseFloat(s.toFixed(5));
                },
                _valueMin: function () {
                    return this.options.min;
                },
                _valueMax: function () {
                    return this.options.max;
                },
                _refreshValue: function () {
                    var e,
                        i,
                        s,
                        n,
                        o,
                        a = this.options.range,
                        r = this.options,
                        h = this,
                        l = this._animateOff ? !1 : r.animate,
                        c = {};
                    this.options.values && this.options.values.length
                        ? this.handles.each(function (s) {
                              (i = 100 * ((h.values(s) - h._valueMin()) / (h._valueMax() - h._valueMin()))),
                                  (c["horizontal" === h.orientation ? "left" : "bottom"] = i + "%"),
                                  t(this).stop(1, 1)[l ? "animate" : "css"](c, r.animate),
                                  h.options.range === !0 &&
                                      ("horizontal" === h.orientation
                                          ? (0 === s &&
                                                h.range.stop(1, 1)[l ? "animate" : "css"]({ left: i + "%" }, r.animate),
                                            1 === s &&
                                                h.range[l ? "animate" : "css"](
                                                    { width: i - e + "%" },
                                                    { queue: !1, duration: r.animate }
                                                ))
                                          : (0 === s &&
                                                h.range
                                                    .stop(1, 1)
                                                    [l ? "animate" : "css"]({ bottom: i + "%" }, r.animate),
                                            1 === s &&
                                                h.range[l ? "animate" : "css"](
                                                    { height: i - e + "%" },
                                                    { queue: !1, duration: r.animate }
                                                ))),
                                  (e = i);
                          })
                        : ((s = this.value()),
                          (n = this._valueMin()),
                          (o = this._valueMax()),
                          (i = o !== n ? 100 * ((s - n) / (o - n)) : 0),
                          (c["horizontal" === this.orientation ? "left" : "bottom"] = i + "%"),
                          this.handle.stop(1, 1)[l ? "animate" : "css"](c, r.animate),
                          "min" === a &&
                              "horizontal" === this.orientation &&
                              this.range.stop(1, 1)[l ? "animate" : "css"]({ width: i + "%" }, r.animate),
                          "max" === a &&
                              "horizontal" === this.orientation &&
                              this.range[l ? "animate" : "css"](
                                  { width: 100 - i + "%" },
                                  { queue: !1, duration: r.animate }
                              ),
                          "min" === a &&
                              "vertical" === this.orientation &&
                              this.range.stop(1, 1)[l ? "animate" : "css"]({ height: i + "%" }, r.animate),
                          "max" === a &&
                              "vertical" === this.orientation &&
                              this.range[l ? "animate" : "css"](
                                  { height: 100 - i + "%" },
                                  { queue: !1, duration: r.animate }
                              ));
                },
                _handleEvents: {
                    keydown: function (i) {
                        var s,
                            n,
                            o,
                            a,
                            r = t(i.target).data("ui-slider-handle-index");
                        switch (i.keyCode) {
                            case t.ui.keyCode.HOME:
                            case t.ui.keyCode.END:
                            case t.ui.keyCode.PAGE_UP:
                            case t.ui.keyCode.PAGE_DOWN:
                            case t.ui.keyCode.UP:
                            case t.ui.keyCode.RIGHT:
                            case t.ui.keyCode.DOWN:
                            case t.ui.keyCode.LEFT:
                                if (
                                    (i.preventDefault(),
                                    !this._keySliding &&
                                        ((this._keySliding = !0),
                                        t(i.target).addClass("ui-state-active"),
                                        (s = this._start(i, r)),
                                        s === !1))
                                )
                                    return;
                        }
                        switch (
                            ((a = this.options.step),
                            (n = o = this.options.values && this.options.values.length ? this.values(r) : this.value()),
                            i.keyCode)
                        ) {
                            case t.ui.keyCode.HOME:
                                o = this._valueMin();
                                break;
                            case t.ui.keyCode.END:
                                o = this._valueMax();
                                break;
                            case t.ui.keyCode.PAGE_UP:
                                o = this._trimAlignValue(n + (this._valueMax() - this._valueMin()) / e);
                                break;
                            case t.ui.keyCode.PAGE_DOWN:
                                o = this._trimAlignValue(n - (this._valueMax() - this._valueMin()) / e);
                                break;
                            case t.ui.keyCode.UP:
                            case t.ui.keyCode.RIGHT:
                                if (n === this._valueMax()) return;
                                o = this._trimAlignValue(n + a);
                                break;
                            case t.ui.keyCode.DOWN:
                            case t.ui.keyCode.LEFT:
                                if (n === this._valueMin()) return;
                                o = this._trimAlignValue(n - a);
                        }
                        this._slide(i, r, o);
                    },
                    click: function (t) {
                        t.preventDefault();
                    },
                    keyup: function (e) {
                        var i = t(e.target).data("ui-slider-handle-index");
                        this._keySliding &&
                            ((this._keySliding = !1),
                            this._stop(e, i),
                            this._change(e, i),
                            t(e.target).removeClass("ui-state-active"));
                    },
                },
            });
        })(jQuery),
        (function (t) {
            function e(t) {
                return function () {
                    var e = this.element.val();
                    t.apply(this, arguments), this._refresh(), e !== this.element.val() && this._trigger("change");
                };
            }
            t.widget("ui.spinner", {
                version: "1.10.2",
                defaultElement: "<input>",
                widgetEventPrefix: "spin",
                options: {
                    culture: null,
                    icons: { down: "ui-icon-triangle-1-s", up: "ui-icon-triangle-1-n" },
                    incremental: !0,
                    max: null,
                    min: null,
                    numberFormat: null,
                    page: 10,
                    step: 1,
                    change: null,
                    spin: null,
                    start: null,
                    stop: null,
                },
                _create: function () {
                    this._setOption("max", this.options.max),
                        this._setOption("min", this.options.min),
                        this._setOption("step", this.options.step),
                        this._value(this.element.val(), !0),
                        this._draw(),
                        this._on(this._events),
                        this._refresh(),
                        this._on(this.window, {
                            beforeunload: function () {
                                this.element.removeAttr("autocomplete");
                            },
                        });
                },
                _getCreateOptions: function () {
                    var e = {},
                        i = this.element;
                    return (
                        t.each(["min", "max", "step"], function (t, s) {
                            var n = i.attr(s);
                            void 0 !== n && n.length && (e[s] = n);
                        }),
                        e
                    );
                },
                _events: {
                    keydown: function (t) {
                        this._start(t) && this._keydown(t) && t.preventDefault();
                    },
                    keyup: "_stop",
                    focus: function () {
                        this.previous = this.element.val();
                    },
                    blur: function (t) {
                        return this.cancelBlur
                            ? (delete this.cancelBlur, void 0)
                            : (this._stop(),
                              this._refresh(),
                              this.previous !== this.element.val() && this._trigger("change", t),
                              void 0);
                    },
                    mousewheel: function (t, e) {
                        if (e) {
                            if (!this.spinning && !this._start(t)) return !1;
                            this._spin((e > 0 ? 1 : -1) * this.options.step, t),
                                clearTimeout(this.mousewheelTimer),
                                (this.mousewheelTimer = this._delay(function () {
                                    this.spinning && this._stop(t);
                                }, 100)),
                                t.preventDefault();
                        }
                    },
                    "mousedown .ui-spinner-button": function (e) {
                        function i() {
                            var t = this.element[0] === this.document[0].activeElement;
                            t ||
                                (this.element.focus(),
                                (this.previous = s),
                                this._delay(function () {
                                    this.previous = s;
                                }));
                        }
                        var s;
                        (s = this.element[0] === this.document[0].activeElement ? this.previous : this.element.val()),
                            e.preventDefault(),
                            i.call(this),
                            (this.cancelBlur = !0),
                            this._delay(function () {
                                delete this.cancelBlur, i.call(this);
                            }),
                            this._start(e) !== !1 &&
                                this._repeat(null, t(e.currentTarget).hasClass("ui-spinner-up") ? 1 : -1, e);
                    },
                    "mouseup .ui-spinner-button": "_stop",
                    "mouseenter .ui-spinner-button": function (e) {
                        return t(e.currentTarget).hasClass("ui-state-active")
                            ? this._start(e) === !1
                                ? !1
                                : (this._repeat(null, t(e.currentTarget).hasClass("ui-spinner-up") ? 1 : -1, e), void 0)
                            : void 0;
                    },
                    "mouseleave .ui-spinner-button": "_stop",
                },
                _draw: function () {
                    var t = (this.uiSpinner = this.element
                        .addClass("ui-spinner-input")
                        .attr("autocomplete", "off")
                        .wrap(this._uiSpinnerHtml())
                        .parent()
                        .append(this._buttonHtml()));
                    this.element.attr("role", "spinbutton"),
                        (this.buttons = t
                            .find(".ui-spinner-button")
                            .attr("tabIndex", -1)
                            .button()
                            .removeClass("ui-corner-all")),
                        this.buttons.height() > Math.ceil(0.5 * t.height()) && t.height() > 0 && t.height(t.height()),
                        this.options.disabled && this.disable();
                },
                _keydown: function (e) {
                    var i = this.options,
                        s = t.ui.keyCode;
                    switch (e.keyCode) {
                        case s.UP:
                            return this._repeat(null, 1, e), !0;
                        case s.DOWN:
                            return this._repeat(null, -1, e), !0;
                        case s.PAGE_UP:
                            return this._repeat(null, i.page, e), !0;
                        case s.PAGE_DOWN:
                            return this._repeat(null, -i.page, e), !0;
                    }
                    return !1;
                },
                _uiSpinnerHtml: function () {
                    return "<span class='ui-spinner ui-widget ui-widget-content ui-corner-all'></span>";
                },
                _buttonHtml: function () {
                    return (
                        "<a class='ui-spinner-button ui-spinner-up ui-corner-tr'><span class='ui-icon " +
                        this.options.icons.up +
                        "'>&#9650;</span>" +
                        "</a>" +
                        "<a class='ui-spinner-button ui-spinner-down ui-corner-br'>" +
                        "<span class='ui-icon " +
                        this.options.icons.down +
                        "'>&#9660;</span>" +
                        "</a>"
                    );
                },
                _start: function (t) {
                    return this.spinning || this._trigger("start", t) !== !1
                        ? (this.counter || (this.counter = 1), (this.spinning = !0), !0)
                        : !1;
                },
                _repeat: function (t, e, i) {
                    (t = t || 500),
                        clearTimeout(this.timer),
                        (this.timer = this._delay(function () {
                            this._repeat(40, e, i);
                        }, t)),
                        this._spin(e * this.options.step, i);
                },
                _spin: function (t, e) {
                    var i = this.value() || 0;
                    this.counter || (this.counter = 1),
                        (i = this._adjustValue(i + t * this._increment(this.counter))),
                        (this.spinning && this._trigger("spin", e, { value: i }) === !1) ||
                            (this._value(i), this.counter++);
                },
                _increment: function (e) {
                    var i = this.options.incremental;
                    return i
                        ? t.isFunction(i)
                            ? i(e)
                            : Math.floor((e * e * e) / 5e4 - (e * e) / 500 + (17 * e) / 200 + 1)
                        : 1;
                },
                _precision: function () {
                    var t = this._precisionOf(this.options.step);
                    return null !== this.options.min && (t = Math.max(t, this._precisionOf(this.options.min))), t;
                },
                _precisionOf: function (t) {
                    var e = "" + t,
                        i = e.indexOf(".");
                    return -1 === i ? 0 : e.length - i - 1;
                },
                _adjustValue: function (t) {
                    var e,
                        i,
                        s = this.options;
                    return (
                        (e = null !== s.min ? s.min : 0),
                        (i = t - e),
                        (i = Math.round(i / s.step) * s.step),
                        (t = e + i),
                        (t = parseFloat(t.toFixed(this._precision()))),
                        null !== s.max && t > s.max ? s.max : null !== s.min && s.min > t ? s.min : t
                    );
                },
                _stop: function (t) {
                    this.spinning &&
                        (clearTimeout(this.timer),
                        clearTimeout(this.mousewheelTimer),
                        (this.counter = 0),
                        (this.spinning = !1),
                        this._trigger("stop", t));
                },
                _setOption: function (t, e) {
                    if ("culture" === t || "numberFormat" === t) {
                        var i = this._parse(this.element.val());
                        return (this.options[t] = e), this.element.val(this._format(i)), void 0;
                    }
                    ("max" === t || "min" === t || "step" === t) && "string" == typeof e && (e = this._parse(e)),
                        "icons" === t &&
                            (this.buttons.first().find(".ui-icon").removeClass(this.options.icons.up).addClass(e.up),
                            this.buttons.last().find(".ui-icon").removeClass(this.options.icons.down).addClass(e.down)),
                        this._super(t, e),
                        "disabled" === t &&
                            (e
                                ? (this.element.prop("disabled", !0), this.buttons.button("disable"))
                                : (this.element.prop("disabled", !1), this.buttons.button("enable")));
                },
                _setOptions: e(function (t) {
                    this._super(t), this._value(this.element.val());
                }),
                _parse: function (t) {
                    return (
                        "string" == typeof t &&
                            "" !== t &&
                            (t =
                                window.Globalize && this.options.numberFormat
                                    ? Globalize.parseFloat(t, 10, this.options.culture)
                                    : +t),
                        "" === t || isNaN(t) ? null : t
                    );
                },
                _format: function (t) {
                    return "" === t
                        ? ""
                        : window.Globalize && this.options.numberFormat
                          ? Globalize.format(t, this.options.numberFormat, this.options.culture)
                          : t;
                },
                _refresh: function () {
                    this.element.attr({
                        "aria-valuemin": this.options.min,
                        "aria-valuemax": this.options.max,
                        "aria-valuenow": this._parse(this.element.val()),
                    });
                },
                _value: function (t, e) {
                    var i;
                    "" !== t &&
                        ((i = this._parse(t)), null !== i && (e || (i = this._adjustValue(i)), (t = this._format(i)))),
                        this.element.val(t),
                        this._refresh();
                },
                _destroy: function () {
                    this.element
                        .removeClass("ui-spinner-input")
                        .prop("disabled", !1)
                        .removeAttr("autocomplete")
                        .removeAttr("role")
                        .removeAttr("aria-valuemin")
                        .removeAttr("aria-valuemax")
                        .removeAttr("aria-valuenow"),
                        this.uiSpinner.replaceWith(this.element);
                },
                stepUp: e(function (t) {
                    this._stepUp(t);
                }),
                _stepUp: function (t) {
                    this._start() && (this._spin((t || 1) * this.options.step), this._stop());
                },
                stepDown: e(function (t) {
                    this._stepDown(t);
                }),
                _stepDown: function (t) {
                    this._start() && (this._spin((t || 1) * -this.options.step), this._stop());
                },
                pageUp: e(function (t) {
                    this._stepUp((t || 1) * this.options.page);
                }),
                pageDown: e(function (t) {
                    this._stepDown((t || 1) * this.options.page);
                }),
                value: function (t) {
                    return arguments.length ? (e(this._value).call(this, t), void 0) : this._parse(this.element.val());
                },
                widget: function () {
                    return this.uiSpinner;
                },
            });
        })(jQuery),
        (function (t, e) {
            function i() {
                return ++n;
            }
            function s(t) {
                return (
                    t.hash.length > 1 &&
                    decodeURIComponent(t.href.replace(o, "")) === decodeURIComponent(location.href.replace(o, ""))
                );
            }
            var n = 0,
                o = /#.*$/;
            t.widget("ui.tabs", {
                version: "1.10.2",
                delay: 300,
                options: {
                    active: null,
                    collapsible: !1,
                    event: "click",
                    heightStyle: "content",
                    hide: null,
                    show: null,
                    activate: null,
                    beforeActivate: null,
                    beforeLoad: null,
                    load: null,
                },
                _create: function () {
                    var e = this,
                        i = this.options;
                    (this.running = !1),
                        this.element
                            .addClass("ui-tabs ui-widget ui-widget-content ui-corner-all")
                            .toggleClass("ui-tabs-collapsible", i.collapsible)
                            .delegate(".ui-tabs-nav > li", "mousedown" + this.eventNamespace, function (e) {
                                t(this).is(".ui-state-disabled") && e.preventDefault();
                            })
                            .delegate(".ui-tabs-anchor", "focus" + this.eventNamespace, function () {
                                t(this).closest("li").is(".ui-state-disabled") && this.blur();
                            }),
                        this._processTabs(),
                        (i.active = this._initialActive()),
                        t.isArray(i.disabled) &&
                            (i.disabled = t
                                .unique(
                                    i.disabled.concat(
                                        t.map(this.tabs.filter(".ui-state-disabled"), function (t) {
                                            return e.tabs.index(t);
                                        })
                                    )
                                )
                                .sort()),
                        (this.active =
                            this.options.active !== !1 && this.anchors.length ? this._findActive(i.active) : t()),
                        this._refresh(),
                        this.active.length && this.load(i.active);
                },
                _initialActive: function () {
                    var i = this.options.active,
                        s = this.options.collapsible,
                        n = location.hash.substring(1);
                    return (
                        null === i &&
                            (n &&
                                this.tabs.each(function (s, o) {
                                    return t(o).attr("aria-controls") === n ? ((i = s), !1) : e;
                                }),
                            null === i && (i = this.tabs.index(this.tabs.filter(".ui-tabs-active"))),
                            (null === i || -1 === i) && (i = this.tabs.length ? 0 : !1)),
                        i !== !1 && ((i = this.tabs.index(this.tabs.eq(i))), -1 === i && (i = s ? !1 : 0)),
                        !s && i === !1 && this.anchors.length && (i = 0),
                        i
                    );
                },
                _getCreateEventData: function () {
                    return { tab: this.active, panel: this.active.length ? this._getPanelForTab(this.active) : t() };
                },
                _tabKeydown: function (i) {
                    var s = t(this.document[0].activeElement).closest("li"),
                        n = this.tabs.index(s),
                        o = !0;
                    if (!this._handlePageNav(i)) {
                        switch (i.keyCode) {
                            case t.ui.keyCode.RIGHT:
                            case t.ui.keyCode.DOWN:
                                n++;
                                break;
                            case t.ui.keyCode.UP:
                            case t.ui.keyCode.LEFT:
                                (o = !1), n--;
                                break;
                            case t.ui.keyCode.END:
                                n = this.anchors.length - 1;
                                break;
                            case t.ui.keyCode.HOME:
                                n = 0;
                                break;
                            case t.ui.keyCode.SPACE:
                                return i.preventDefault(), clearTimeout(this.activating), this._activate(n), e;
                            case t.ui.keyCode.ENTER:
                                return (
                                    i.preventDefault(),
                                    clearTimeout(this.activating),
                                    this._activate(n === this.options.active ? !1 : n),
                                    e
                                );
                            default:
                                return;
                        }
                        i.preventDefault(),
                            clearTimeout(this.activating),
                            (n = this._focusNextTab(n, o)),
                            i.ctrlKey ||
                                (s.attr("aria-selected", "false"),
                                this.tabs.eq(n).attr("aria-selected", "true"),
                                (this.activating = this._delay(function () {
                                    this.option("active", n);
                                }, this.delay)));
                    }
                },
                _panelKeydown: function (e) {
                    this._handlePageNav(e) ||
                        (e.ctrlKey && e.keyCode === t.ui.keyCode.UP && (e.preventDefault(), this.active.focus()));
                },
                _handlePageNav: function (i) {
                    return i.altKey && i.keyCode === t.ui.keyCode.PAGE_UP
                        ? (this._activate(this._focusNextTab(this.options.active - 1, !1)), !0)
                        : i.altKey && i.keyCode === t.ui.keyCode.PAGE_DOWN
                          ? (this._activate(this._focusNextTab(this.options.active + 1, !0)), !0)
                          : e;
                },
                _findNextTab: function (e, i) {
                    function s() {
                        return e > n && (e = 0), 0 > e && (e = n), e;
                    }
                    for (var n = this.tabs.length - 1; -1 !== t.inArray(s(), this.options.disabled); )
                        e = i ? e + 1 : e - 1;
                    return e;
                },
                _focusNextTab: function (t, e) {
                    return (t = this._findNextTab(t, e)), this.tabs.eq(t).focus(), t;
                },
                _setOption: function (t, i) {
                    return "active" === t
                        ? (this._activate(i), e)
                        : "disabled" === t
                          ? (this._setupDisabled(i), e)
                          : (this._super(t, i),
                            "collapsible" === t &&
                                (this.element.toggleClass("ui-tabs-collapsible", i),
                                i || this.options.active !== !1 || this._activate(0)),
                            "event" === t && this._setupEvents(i),
                            "heightStyle" === t && this._setupHeightStyle(i),
                            e);
                },
                _tabId: function (t) {
                    return t.attr("aria-controls") || "ui-tabs-" + i();
                },
                _sanitizeSelector: function (t) {
                    return t ? t.replace(/[!"$%&'()*+,.\/:;<=>?@\[\]\^`{|}~]/g, "\\$&") : "";
                },
                refresh: function () {
                    var e = this.options,
                        i = this.tablist.children(":has(a[href])");
                    (e.disabled = t.map(i.filter(".ui-state-disabled"), function (t) {
                        return i.index(t);
                    })),
                        this._processTabs(),
                        e.active !== !1 && this.anchors.length
                            ? this.active.length && !t.contains(this.tablist[0], this.active[0])
                                ? this.tabs.length === e.disabled.length
                                    ? ((e.active = !1), (this.active = t()))
                                    : this._activate(this._findNextTab(Math.max(0, e.active - 1), !1))
                                : (e.active = this.tabs.index(this.active))
                            : ((e.active = !1), (this.active = t())),
                        this._refresh();
                },
                _refresh: function () {
                    this._setupDisabled(this.options.disabled),
                        this._setupEvents(this.options.event),
                        this._setupHeightStyle(this.options.heightStyle),
                        this.tabs.not(this.active).attr({ "aria-selected": "false", tabIndex: -1 }),
                        this.panels
                            .not(this._getPanelForTab(this.active))
                            .hide()
                            .attr({ "aria-expanded": "false", "aria-hidden": "true" }),
                        this.active.length
                            ? (this.active
                                  .addClass("ui-tabs-active ui-state-active")
                                  .attr({ "aria-selected": "true", tabIndex: 0 }),
                              this._getPanelForTab(this.active)
                                  .show()
                                  .attr({ "aria-expanded": "true", "aria-hidden": "false" }))
                            : this.tabs.eq(0).attr("tabIndex", 0);
                },
                _processTabs: function () {
                    var e = this;
                    (this.tablist = this._getList()
                        .addClass("ui-tabs-nav ui-helper-reset ui-helper-clearfix ui-widget-header ui-corner-all")
                        .attr("role", "tablist")),
                        (this.tabs = this.tablist
                            .find("> li:has(a[href])")
                            .addClass("ui-state-default ui-corner-top")
                            .attr({ role: "tab", tabIndex: -1 })),
                        (this.anchors = this.tabs
                            .map(function () {
                                return t("a", this)[0];
                            })
                            .addClass("ui-tabs-anchor")
                            .attr({ role: "presentation", tabIndex: -1 })),
                        (this.panels = t()),
                        this.anchors.each(function (i, n) {
                            var o,
                                a,
                                r,
                                h = t(n).uniqueId().attr("id"),
                                l = t(n).closest("li"),
                                c = l.attr("aria-controls");
                            s(n)
                                ? ((o = n.hash), (a = e.element.find(e._sanitizeSelector(o))))
                                : ((r = e._tabId(l)),
                                  (o = "#" + r),
                                  (a = e.element.find(o)),
                                  a.length || ((a = e._createPanel(r)), a.insertAfter(e.panels[i - 1] || e.tablist)),
                                  a.attr("aria-live", "polite")),
                                a.length && (e.panels = e.panels.add(a)),
                                c && l.data("ui-tabs-aria-controls", c),
                                l.attr({ "aria-controls": o.substring(1), "aria-labelledby": h }),
                                a.attr("aria-labelledby", h);
                        }),
                        this.panels
                            .addClass("ui-tabs-panel ui-widget-content ui-corner-bottom")
                            .attr("role", "tabpanel");
                },
                _getList: function () {
                    return this.element.find("ol,ul").eq(0);
                },
                _createPanel: function (e) {
                    return t("<div>")
                        .attr("id", e)
                        .addClass("ui-tabs-panel ui-widget-content ui-corner-bottom")
                        .data("ui-tabs-destroy", !0);
                },
                _setupDisabled: function (e) {
                    t.isArray(e) && (e.length ? e.length === this.anchors.length && (e = !0) : (e = !1));
                    for (var i, s = 0; (i = this.tabs[s]); s++)
                        e === !0 || -1 !== t.inArray(s, e)
                            ? t(i).addClass("ui-state-disabled").attr("aria-disabled", "true")
                            : t(i).removeClass("ui-state-disabled").removeAttr("aria-disabled");
                    this.options.disabled = e;
                },
                _setupEvents: function (e) {
                    var i = {
                        click: function (t) {
                            t.preventDefault();
                        },
                    };
                    e &&
                        t.each(e.split(" "), function (t, e) {
                            i[e] = "_eventHandler";
                        }),
                        this._off(this.anchors.add(this.tabs).add(this.panels)),
                        this._on(this.anchors, i),
                        this._on(this.tabs, { keydown: "_tabKeydown" }),
                        this._on(this.panels, { keydown: "_panelKeydown" }),
                        this._focusable(this.tabs),
                        this._hoverable(this.tabs);
                },
                _setupHeightStyle: function (e) {
                    var i,
                        s = this.element.parent();
                    "fill" === e
                        ? ((i = s.height()),
                          (i -= this.element.outerHeight() - this.element.height()),
                          this.element.siblings(":visible").each(function () {
                              var e = t(this),
                                  s = e.css("position");
                              "absolute" !== s && "fixed" !== s && (i -= e.outerHeight(!0));
                          }),
                          this.element
                              .children()
                              .not(this.panels)
                              .each(function () {
                                  i -= t(this).outerHeight(!0);
                              }),
                          this.panels
                              .each(function () {
                                  t(this).height(Math.max(0, i - t(this).innerHeight() + t(this).height()));
                              })
                              .css("overflow", "auto"))
                        : "auto" === e &&
                          ((i = 0),
                          this.panels
                              .each(function () {
                                  i = Math.max(i, t(this).height("").height());
                              })
                              .height(i));
                },
                _eventHandler: function (e) {
                    var i = this.options,
                        s = this.active,
                        n = t(e.currentTarget),
                        o = n.closest("li"),
                        a = o[0] === s[0],
                        r = a && i.collapsible,
                        h = r ? t() : this._getPanelForTab(o),
                        l = s.length ? this._getPanelForTab(s) : t(),
                        c = { oldTab: s, oldPanel: l, newTab: r ? t() : o, newPanel: h };
                    e.preventDefault(),
                        o.hasClass("ui-state-disabled") ||
                            o.hasClass("ui-tabs-loading") ||
                            this.running ||
                            (a && !i.collapsible) ||
                            this._trigger("beforeActivate", e, c) === !1 ||
                            ((i.active = r ? !1 : this.tabs.index(o)),
                            (this.active = a ? t() : o),
                            this.xhr && this.xhr.abort(),
                            l.length || h.length || t.error("jQuery UI Tabs: Mismatching fragment identifier."),
                            h.length && this.load(this.tabs.index(o), e),
                            this._toggle(e, c));
                },
                _toggle: function (e, i) {
                    function s() {
                        (o.running = !1), o._trigger("activate", e, i);
                    }
                    function n() {
                        i.newTab.closest("li").addClass("ui-tabs-active ui-state-active"),
                            a.length && o.options.show ? o._show(a, o.options.show, s) : (a.show(), s());
                    }
                    var o = this,
                        a = i.newPanel,
                        r = i.oldPanel;
                    (this.running = !0),
                        r.length && this.options.hide
                            ? this._hide(r, this.options.hide, function () {
                                  i.oldTab.closest("li").removeClass("ui-tabs-active ui-state-active"), n();
                              })
                            : (i.oldTab.closest("li").removeClass("ui-tabs-active ui-state-active"), r.hide(), n()),
                        r.attr({ "aria-expanded": "false", "aria-hidden": "true" }),
                        i.oldTab.attr("aria-selected", "false"),
                        a.length && r.length
                            ? i.oldTab.attr("tabIndex", -1)
                            : a.length &&
                              this.tabs
                                  .filter(function () {
                                      return 0 === t(this).attr("tabIndex");
                                  })
                                  .attr("tabIndex", -1),
                        a.attr({ "aria-expanded": "true", "aria-hidden": "false" }),
                        i.newTab.attr({ "aria-selected": "true", tabIndex: 0 });
                },
                _activate: function (e) {
                    var i,
                        s = this._findActive(e);
                    s[0] !== this.active[0] &&
                        (s.length || (s = this.active),
                        (i = s.find(".ui-tabs-anchor")[0]),
                        this._eventHandler({ target: i, currentTarget: i, preventDefault: t.noop }));
                },
                _findActive: function (e) {
                    return e === !1 ? t() : this.tabs.eq(e);
                },
                _getIndex: function (t) {
                    return (
                        "string" == typeof t && (t = this.anchors.index(this.anchors.filter("[href$='" + t + "']"))), t
                    );
                },
                _destroy: function () {
                    this.xhr && this.xhr.abort(),
                        this.element.removeClass(
                            "ui-tabs ui-widget ui-widget-content ui-corner-all ui-tabs-collapsible"
                        ),
                        this.tablist
                            .removeClass(
                                "ui-tabs-nav ui-helper-reset ui-helper-clearfix ui-widget-header ui-corner-all"
                            )
                            .removeAttr("role"),
                        this.anchors
                            .removeClass("ui-tabs-anchor")
                            .removeAttr("role")
                            .removeAttr("tabIndex")
                            .removeUniqueId(),
                        this.tabs.add(this.panels).each(function () {
                            t.data(this, "ui-tabs-destroy")
                                ? t(this).remove()
                                : t(this)
                                      .removeClass(
                                          "ui-state-default ui-state-active ui-state-disabled ui-corner-top ui-corner-bottom ui-widget-content ui-tabs-active ui-tabs-panel"
                                      )
                                      .removeAttr("tabIndex")
                                      .removeAttr("aria-live")
                                      .removeAttr("aria-busy")
                                      .removeAttr("aria-selected")
                                      .removeAttr("aria-labelledby")
                                      .removeAttr("aria-hidden")
                                      .removeAttr("aria-expanded")
                                      .removeAttr("role");
                        }),
                        this.tabs.each(function () {
                            var e = t(this),
                                i = e.data("ui-tabs-aria-controls");
                            i
                                ? e.attr("aria-controls", i).removeData("ui-tabs-aria-controls")
                                : e.removeAttr("aria-controls");
                        }),
                        this.panels.show(),
                        "content" !== this.options.heightStyle && this.panels.css("height", "");
                },
                enable: function (i) {
                    var s = this.options.disabled;
                    s !== !1 &&
                        (i === e
                            ? (s = !1)
                            : ((i = this._getIndex(i)),
                              (s = t.isArray(s)
                                  ? t.map(s, function (t) {
                                        return t !== i ? t : null;
                                    })
                                  : t.map(this.tabs, function (t, e) {
                                        return e !== i ? e : null;
                                    }))),
                        this._setupDisabled(s));
                },
                disable: function (i) {
                    var s = this.options.disabled;
                    if (s !== !0) {
                        if (i === e) s = !0;
                        else {
                            if (((i = this._getIndex(i)), -1 !== t.inArray(i, s))) return;
                            s = t.isArray(s) ? t.merge([i], s).sort() : [i];
                        }
                        this._setupDisabled(s);
                    }
                },
                load: function (e, i) {
                    e = this._getIndex(e);
                    var n = this,
                        o = this.tabs.eq(e),
                        a = o.find(".ui-tabs-anchor"),
                        r = this._getPanelForTab(o),
                        h = { tab: o, panel: r };
                    s(a[0]) ||
                        ((this.xhr = t.ajax(this._ajaxSettings(a, i, h))),
                        this.xhr &&
                            "canceled" !== this.xhr.statusText &&
                            (o.addClass("ui-tabs-loading"),
                            r.attr("aria-busy", "true"),
                            this.xhr
                                .success(function (t) {
                                    setTimeout(function () {
                                        r.html(t), n._trigger("load", i, h);
                                    }, 1);
                                })
                                .complete(function (t, e) {
                                    setTimeout(function () {
                                        "abort" === e && n.panels.stop(!1, !0),
                                            o.removeClass("ui-tabs-loading"),
                                            r.removeAttr("aria-busy"),
                                            t === n.xhr && delete n.xhr;
                                    }, 1);
                                })));
                },
                _ajaxSettings: function (e, i, s) {
                    var n = this;
                    return {
                        url: e.attr("href"),
                        beforeSend: function (e, o) {
                            return n._trigger("beforeLoad", i, t.extend({ jqXHR: e, ajaxSettings: o }, s));
                        },
                    };
                },
                _getPanelForTab: function (e) {
                    var i = t(e).attr("aria-controls");
                    return this.element.find(this._sanitizeSelector("#" + i));
                },
            });
        })(jQuery),
        (function (t) {
            function e(e, i) {
                var s = (e.attr("aria-describedby") || "").split(/\s+/);
                s.push(i), e.data("ui-tooltip-id", i).attr("aria-describedby", t.trim(s.join(" ")));
            }
            function i(e) {
                var i = e.data("ui-tooltip-id"),
                    s = (e.attr("aria-describedby") || "").split(/\s+/),
                    n = t.inArray(i, s);
                -1 !== n && s.splice(n, 1),
                    e.removeData("ui-tooltip-id"),
                    (s = t.trim(s.join(" "))),
                    s ? e.attr("aria-describedby", s) : e.removeAttr("aria-describedby");
            }
            var s = 0;
            t.widget("ui.tooltip", {
                version: "1.10.2",
                options: {
                    content: function () {
                        var e = t(this).attr("title") || "";
                        return t("<a>").text(e).html();
                    },
                    hide: !0,
                    items: "[title]:not([disabled])",
                    position: { my: "left top+15", at: "left bottom", collision: "flipfit flip" },
                    show: !0,
                    tooltipClass: null,
                    track: !1,
                    close: null,
                    open: null,
                },
                _create: function () {
                    this._on({ mouseover: "open", focusin: "open" }),
                        (this.tooltips = {}),
                        (this.parents = {}),
                        this.options.disabled && this._disable();
                },
                _setOption: function (e, i) {
                    var s = this;
                    return "disabled" === e
                        ? (this[i ? "_disable" : "_enable"](), (this.options[e] = i), void 0)
                        : (this._super(e, i),
                          "content" === e &&
                              t.each(this.tooltips, function (t, e) {
                                  s._updateContent(e);
                              }),
                          void 0);
                },
                _disable: function () {
                    var e = this;
                    t.each(this.tooltips, function (i, s) {
                        var n = t.Event("blur");
                        (n.target = n.currentTarget = s[0]), e.close(n, !0);
                    }),
                        this.element
                            .find(this.options.items)
                            .addBack()
                            .each(function () {
                                var e = t(this);
                                e.is("[title]") && e.data("ui-tooltip-title", e.attr("title")).attr("title", "");
                            });
                },
                _enable: function () {
                    this.element
                        .find(this.options.items)
                        .addBack()
                        .each(function () {
                            var e = t(this);
                            e.data("ui-tooltip-title") && e.attr("title", e.data("ui-tooltip-title"));
                        });
                },
                open: function (e) {
                    var i = this,
                        s = t(e ? e.target : this.element).closest(this.options.items);
                    s.length &&
                        !s.data("ui-tooltip-id") &&
                        (s.attr("title") && s.data("ui-tooltip-title", s.attr("title")),
                        s.data("ui-tooltip-open", !0),
                        e &&
                            "mouseover" === e.type &&
                            s.parents().each(function () {
                                var e,
                                    s = t(this);
                                s.data("ui-tooltip-open") &&
                                    ((e = t.Event("blur")), (e.target = e.currentTarget = this), i.close(e, !0)),
                                    s.attr("title") &&
                                        (s.uniqueId(),
                                        (i.parents[this.id] = { element: this, title: s.attr("title") }),
                                        s.attr("title", ""));
                            }),
                        this._updateContent(s, e));
                },
                _updateContent: function (t, e) {
                    var i,
                        s = this.options.content,
                        n = this,
                        o = e ? e.type : null;
                    return "string" == typeof s
                        ? this._open(e, t, s)
                        : ((i = s.call(t[0], function (i) {
                              t.data("ui-tooltip-open") &&
                                  n._delay(function () {
                                      e && (e.type = o), this._open(e, t, i);
                                  });
                          })),
                          i && this._open(e, t, i),
                          void 0);
                },
                _open: function (i, s, n) {
                    function o(t) {
                        (l.of = t), a.is(":hidden") || a.position(l);
                    }
                    var a,
                        r,
                        h,
                        l = t.extend({}, this.options.position);
                    if (n) {
                        if (((a = this._find(s)), a.length)) return a.find(".ui-tooltip-content").html(n), void 0;
                        s.is("[title]") && (i && "mouseover" === i.type ? s.attr("title", "") : s.removeAttr("title")),
                            (a = this._tooltip(s)),
                            e(s, a.attr("id")),
                            a.find(".ui-tooltip-content").html(n),
                            this.options.track && i && /^mouse/.test(i.type)
                                ? (this._on(this.document, { mousemove: o }), o(i))
                                : a.position(t.extend({ of: s }, this.options.position)),
                            a.hide(),
                            this._show(a, this.options.show),
                            this.options.show &&
                                this.options.show.delay &&
                                (h = this.delayedShow =
                                    setInterval(function () {
                                        a.is(":visible") && (o(l.of), clearInterval(h));
                                    }, t.fx.interval)),
                            this._trigger("open", i, { tooltip: a }),
                            (r = {
                                keyup: function (e) {
                                    if (e.keyCode === t.ui.keyCode.ESCAPE) {
                                        var i = t.Event(e);
                                        (i.currentTarget = s[0]), this.close(i, !0);
                                    }
                                },
                                remove: function () {
                                    this._removeTooltip(a);
                                },
                            }),
                            (i && "mouseover" !== i.type) || (r.mouseleave = "close"),
                            (i && "focusin" !== i.type) || (r.focusout = "close"),
                            this._on(!0, s, r);
                    }
                },
                close: function (e) {
                    var s = this,
                        n = t(e ? e.currentTarget : this.element),
                        o = this._find(n);
                    this.closing ||
                        (clearInterval(this.delayedShow),
                        n.data("ui-tooltip-title") && n.attr("title", n.data("ui-tooltip-title")),
                        i(n),
                        o.stop(!0),
                        this._hide(o, this.options.hide, function () {
                            s._removeTooltip(t(this));
                        }),
                        n.removeData("ui-tooltip-open"),
                        this._off(n, "mouseleave focusout keyup"),
                        n[0] !== this.element[0] && this._off(n, "remove"),
                        this._off(this.document, "mousemove"),
                        e &&
                            "mouseleave" === e.type &&
                            t.each(this.parents, function (e, i) {
                                t(i.element).attr("title", i.title), delete s.parents[e];
                            }),
                        (this.closing = !0),
                        this._trigger("close", e, { tooltip: o }),
                        (this.closing = !1));
                },
                _tooltip: function (e) {
                    var i = "ui-tooltip-" + s++,
                        n = t("<div>")
                            .attr({ id: i, role: "tooltip" })
                            .addClass(
                                "ui-tooltip ui-widget ui-corner-all ui-widget-content " +
                                    (this.options.tooltipClass || "")
                            );
                    return (
                        t("<div>").addClass("ui-tooltip-content").appendTo(n),
                        n.appendTo(this.document[0].body),
                        (this.tooltips[i] = e),
                        n
                    );
                },
                _find: function (e) {
                    var i = e.data("ui-tooltip-id");
                    return i ? t("#" + i) : t();
                },
                _removeTooltip: function (t) {
                    t.remove(), delete this.tooltips[t.attr("id")];
                },
                _destroy: function () {
                    var e = this;
                    t.each(this.tooltips, function (i, s) {
                        var n = t.Event("blur");
                        (n.target = n.currentTarget = s[0]),
                            e.close(n, !0),
                            t("#" + i).remove(),
                            s.data("ui-tooltip-title") &&
                                (s.attr("title", s.data("ui-tooltip-title")), s.removeData("ui-tooltip-title"));
                    });
                },
            });
        })(jQuery);

    /*! jQuery Migrate v1.1.1 | (c) 2005, 2013 jQuery Foundation, Inc. and other contributors | jquery.org/license */
    jQuery.migrateMute === void 0 && (jQuery.migrateMute = !0),
        (function (e, t, n) {
            function r(n) {
                o[n] ||
                    ((o[n] = !0),
                    e.migrateWarnings.push(n),
                    t.console &&
                        console.warn &&
                        !e.migrateMute &&
                        (console.warn("JQMIGRATE: " + n), e.migrateTrace && console.trace && console.trace()));
            }
            function a(t, a, o, i) {
                if (Object.defineProperty)
                    try {
                        return (
                            Object.defineProperty(t, a, {
                                configurable: !0,
                                enumerable: !0,
                                get: function () {
                                    return r(i), o;
                                },
                                set: function (e) {
                                    r(i), (o = e);
                                },
                            }),
                            n
                        );
                    } catch (s) {}
                (e._definePropertyBroken = !0), (t[a] = o);
            }
            var o = {};
            (e.migrateWarnings = []),
                !e.migrateMute && t.console && console.log && console.log("JQMIGRATE: Logging is active"),
                e.migrateTrace === n && (e.migrateTrace = !0),
                (e.migrateReset = function () {
                    (o = {}), (e.migrateWarnings.length = 0);
                }),
                "BackCompat" === document.compatMode && r("jQuery is not compatible with Quirks Mode");
            var i = e("<input/>", { size: 1 }).attr("size") && e.attrFn,
                s = e.attr,
                u =
                    (e.attrHooks.value && e.attrHooks.value.get) ||
                    function () {
                        return null;
                    },
                c =
                    (e.attrHooks.value && e.attrHooks.value.set) ||
                    function () {
                        return n;
                    },
                l = /^(?:input|button)$/i,
                d = /^[238]$/,
                p =
                    /^(?:autofocus|autoplay|async|checked|controls|defer|disabled|hidden|loop|multiple|open|readonly|required|scoped|selected)$/i,
                f = /^(?:checked|selected)$/i;
            a(e, "attrFn", i || {}, "jQuery.attrFn is deprecated"),
                (e.attr = function (t, a, o, u) {
                    var c = a.toLowerCase(),
                        g = t && t.nodeType;
                    return u &&
                        (4 > s.length && r("jQuery.fn.attr( props, pass ) is deprecated"),
                        t && !d.test(g) && (i ? a in i : e.isFunction(e.fn[a])))
                        ? e(t)[a](o)
                        : ("type" === a &&
                              o !== n &&
                              l.test(t.nodeName) &&
                              t.parentNode &&
                              r("Can't change the 'type' of an input or button in IE 6/7/8"),
                          !e.attrHooks[c] &&
                              p.test(c) &&
                              ((e.attrHooks[c] = {
                                  get: function (t, r) {
                                      var a,
                                          o = e.prop(t, r);
                                      return o === !0 ||
                                          ("boolean" != typeof o && (a = t.getAttributeNode(r)) && a.nodeValue !== !1)
                                          ? r.toLowerCase()
                                          : n;
                                  },
                                  set: function (t, n, r) {
                                      var a;
                                      return (
                                          n === !1
                                              ? e.removeAttr(t, r)
                                              : ((a = e.propFix[r] || r),
                                                a in t && (t[a] = !0),
                                                t.setAttribute(r, r.toLowerCase())),
                                          r
                                      );
                                  },
                              }),
                              f.test(c) && r("jQuery.fn.attr('" + c + "') may use property instead of attribute")),
                          s.call(e, t, a, o));
                }),
                (e.attrHooks.value = {
                    get: function (e, t) {
                        var n = (e.nodeName || "").toLowerCase();
                        return "button" === n
                            ? u.apply(this, arguments)
                            : ("input" !== n &&
                                  "option" !== n &&
                                  r("jQuery.fn.attr('value') no longer gets properties"),
                              t in e ? e.value : null);
                    },
                    set: function (e, t) {
                        var a = (e.nodeName || "").toLowerCase();
                        return "button" === a
                            ? c.apply(this, arguments)
                            : ("input" !== a &&
                                  "option" !== a &&
                                  r("jQuery.fn.attr('value', val) no longer sets properties"),
                              (e.value = t),
                              n);
                    },
                });
            var g,
                h,
                v = e.fn.init,
                m = e.parseJSON,
                y = /^(?:[^<]*(<[\w\W]+>)[^>]*|#([\w\-]*))$/;
            (e.fn.init = function (t, n, a) {
                var o;
                return t &&
                    "string" == typeof t &&
                    !e.isPlainObject(n) &&
                    (o = y.exec(t)) &&
                    o[1] &&
                    ("<" !== t.charAt(0) && r("$(html) HTML strings must start with '<' character"),
                    n && n.context && (n = n.context),
                    e.parseHTML)
                    ? v.call(this, e.parseHTML(e.trim(t), n, !0), n, a)
                    : v.apply(this, arguments);
            }),
                (e.fn.init.prototype = e.fn),
                (e.parseJSON = function (e) {
                    return e || null === e
                        ? m.apply(this, arguments)
                        : (r("jQuery.parseJSON requires a valid JSON string"), null);
                }),
                (e.uaMatch = function (e) {
                    e = e.toLowerCase();
                    var t =
                        /(chrome)[ \/]([\w.]+)/.exec(e) ||
                        /(webkit)[ \/]([\w.]+)/.exec(e) ||
                        /(opera)(?:.*version|)[ \/]([\w.]+)/.exec(e) ||
                        /(msie) ([\w.]+)/.exec(e) ||
                        (0 > e.indexOf("compatible") && /(mozilla)(?:.*? rv:([\w.]+)|)/.exec(e)) ||
                        [];
                    return { browser: t[1] || "", version: t[2] || "0" };
                }),
                e.browser ||
                    ((g = e.uaMatch(navigator.userAgent)),
                    (h = {}),
                    g.browser && ((h[g.browser] = !0), (h.version = g.version)),
                    h.chrome ? (h.webkit = !0) : h.webkit && (h.safari = !0),
                    (e.browser = h)),
                a(e, "browser", e.browser, "jQuery.browser is deprecated"),
                (e.sub = function () {
                    function t(e, n) {
                        return new t.fn.init(e, n);
                    }
                    e.extend(!0, t, this),
                        (t.superclass = this),
                        (t.fn = t.prototype = this()),
                        (t.fn.constructor = t),
                        (t.sub = this.sub),
                        (t.fn.init = function (r, a) {
                            return (
                                a && a instanceof e && !(a instanceof t) && (a = t(a)), e.fn.init.call(this, r, a, n)
                            );
                        }),
                        (t.fn.init.prototype = t.fn);
                    var n = t(document);
                    return r("jQuery.sub() is deprecated"), t;
                }),
                e.ajaxSetup({ converters: { "text json": e.parseJSON } });
            var b = e.fn.data;
            e.fn.data = function (t) {
                var a,
                    o,
                    i = this[0];
                return !i ||
                    "events" !== t ||
                    1 !== arguments.length ||
                    ((a = e.data(i, t)), (o = e._data(i, t)), (a !== n && a !== o) || o === n)
                    ? b.apply(this, arguments)
                    : (r("Use of jQuery.fn.data('events') is deprecated"), o);
            };
            var j = /\/(java|ecma)script/i,
                w = e.fn.andSelf || e.fn.addBack;
            (e.fn.andSelf = function () {
                return r("jQuery.fn.andSelf() replaced by jQuery.fn.addBack()"), w.apply(this, arguments);
            }),
                e.clean ||
                    (e.clean = function (t, a, o, i) {
                        (a = a || document),
                            (a = (!a.nodeType && a[0]) || a),
                            (a = a.ownerDocument || a),
                            r("jQuery.clean() is deprecated");
                        var s,
                            u,
                            c,
                            l,
                            d = [];
                        if ((e.merge(d, e.buildFragment(t, a).childNodes), o))
                            for (
                                c = function (e) {
                                    return !e.type || j.test(e.type)
                                        ? i
                                            ? i.push(e.parentNode ? e.parentNode.removeChild(e) : e)
                                            : o.appendChild(e)
                                        : n;
                                },
                                    s = 0;
                                null != (u = d[s]);
                                s++
                            )
                                (e.nodeName(u, "script") && c(u)) ||
                                    (o.appendChild(u),
                                    u.getElementsByTagName !== n &&
                                        ((l = e.grep(e.merge([], u.getElementsByTagName("script")), c)),
                                        d.splice.apply(d, [s + 1, 0].concat(l)),
                                        (s += l.length)));
                        return d;
                    });
            var Q = e.event.add,
                x = e.event.remove,
                k = e.event.trigger,
                N = e.fn.toggle,
                C = e.fn.live,
                S = e.fn.die,
                T = "ajaxStart|ajaxStop|ajaxSend|ajaxComplete|ajaxError|ajaxSuccess",
                M = RegExp("\\b(?:" + T + ")\\b"),
                H = /(?:^|\s)hover(\.\S+|)\b/,
                A = function (t) {
                    return "string" != typeof t || e.event.special.hover
                        ? t
                        : (H.test(t) && r("'hover' pseudo-event is deprecated, use 'mouseenter mouseleave'"),
                          t && t.replace(H, "mouseenter$1 mouseleave$1"));
                };
            e.event.props &&
                "attrChange" !== e.event.props[0] &&
                e.event.props.unshift("attrChange", "attrName", "relatedNode", "srcElement"),
                e.event.dispatch &&
                    a(e.event, "handle", e.event.dispatch, "jQuery.event.handle is undocumented and deprecated"),
                (e.event.add = function (e, t, n, a, o) {
                    e !== document && M.test(t) && r("AJAX events should be attached to document: " + t),
                        Q.call(this, e, A(t || ""), n, a, o);
                }),
                (e.event.remove = function (e, t, n, r, a) {
                    x.call(this, e, A(t) || "", n, r, a);
                }),
                (e.fn.error = function () {
                    var e = Array.prototype.slice.call(arguments, 0);
                    return (
                        r("jQuery.fn.error() is deprecated"),
                        e.splice(0, 0, "error"),
                        arguments.length ? this.bind.apply(this, e) : (this.triggerHandler.apply(this, e), this)
                    );
                }),
                (e.fn.toggle = function (t, n) {
                    if (!e.isFunction(t) || !e.isFunction(n)) return N.apply(this, arguments);
                    r("jQuery.fn.toggle(handler, handler...) is deprecated");
                    var a = arguments,
                        o = t.guid || e.guid++,
                        i = 0,
                        s = function (n) {
                            var r = (e._data(this, "lastToggle" + t.guid) || 0) % i;
                            return (
                                e._data(this, "lastToggle" + t.guid, r + 1),
                                n.preventDefault(),
                                a[r].apply(this, arguments) || !1
                            );
                        };
                    for (s.guid = o; a.length > i; ) a[i++].guid = o;
                    return this.click(s);
                }),
                (e.fn.live = function (t, n, a) {
                    return (
                        r("jQuery.fn.live() is deprecated"),
                        C ? C.apply(this, arguments) : (e(this.context).on(t, this.selector, n, a), this)
                    );
                }),
                (e.fn.die = function (t, n) {
                    return (
                        r("jQuery.fn.die() is deprecated"),
                        S ? S.apply(this, arguments) : (e(this.context).off(t, this.selector || "**", n), this)
                    );
                }),
                (e.event.trigger = function (e, t, n, a) {
                    return (
                        n || M.test(e) || r("Global events are undocumented and deprecated"),
                        k.call(this, e, t, n || document, a)
                    );
                }),
                e.each(T.split("|"), function (t, n) {
                    e.event.special[n] = {
                        setup: function () {
                            var t = this;
                            return (
                                t !== document &&
                                    (e.event.add(document, n + "." + e.guid, function () {
                                        e.event.trigger(n, null, t, !0);
                                    }),
                                    e._data(this, n, e.guid++)),
                                !1
                            );
                        },
                        teardown: function () {
                            return this !== document && e.event.remove(document, n + "." + e._data(this, n)), !1;
                        },
                    };
                });
        })(jQuery, window);
    //@ sourceMappingURL=dist/jquery-migrate.min.map
    var qq = qq || {};
    qq.extend = function (first, second) {
        for (var prop in second) {
            first[prop] = second[prop];
        }
    };
    qq.indexOf = function (arr, elt, from) {
        if (arr.indexOf) return arr.indexOf(elt, from);
        from = from || 0;
        var len = arr.length;
        if (from < 0) from += len;
        for (; from < len; from++) {
            if (from in arr && arr[from] === elt) {
                return from;
            }
        }
        return -1;
    };
    qq.getUniqueId = (function () {
        var id = 0;
        return function () {
            return id++;
        };
    })();
    qq.attach = function (element, type, fn) {
        if (element.addEventListener) {
            element.addEventListener(type, fn, false);
        } else if (element.attachEvent) {
            element.attachEvent("on" + type, fn);
        }
    };
    qq.detach = function (element, type, fn) {
        if (element.removeEventListener) {
            element.removeEventListener(type, fn, false);
        } else if (element.attachEvent) {
            element.detachEvent("on" + type, fn);
        }
    };
    qq.preventDefault = function (e) {
        if (e.preventDefault) {
            e.preventDefault();
        } else {
            e.returnValue = false;
        }
    };
    qq.insertBefore = function (a, b) {
        b.parentNode.insertBefore(a, b);
    };
    qq.remove = function (element) {
        element.parentNode.removeChild(element);
    };
    qq.contains = function (parent, descendant) {
        if (parent == descendant) return true;
        if (parent.contains) {
            return parent.contains(descendant);
        } else {
            return !!(descendant.compareDocumentPosition(parent) & 8);
        }
    };
    qq.toElement = (function () {
        var div = document.createElement("div");
        return function (html) {
            div.innerHTML = html;
            var element = div.firstChild;
            div.removeChild(element);
            return element;
        };
    })();
    qq.css = function (element, styles) {
        if (styles.opacity != null) {
            if (typeof element.style.opacity != "string" && typeof element.filters != "undefined") {
                styles.filter = "alpha(opacity=" + Math.round(100 * styles.opacity) + ")";
            }
        }
        qq.extend(element.style, styles);
    };
    qq.hasClass = function (element, name) {
        var re = new RegExp("(^| )" + name + "( |$)");
        return re.test(element.className);
    };
    qq.addClass = function (element, name) {
        if (!qq.hasClass(element, name)) {
            element.className += " " + name;
        }
    };
    qq.removeClass = function (element, name) {
        var re = new RegExp("(^| )" + name + "( |$)");
        element.className = element.className.replace(re, " ").replace(/^\s+|\s+$/g, "");
    };
    qq.setText = function (element, text) {
        element.innerText = text;
        element.textContent = text;
    };
    qq.children = function (element) {
        var children = [],
            child = element.firstChild;
        while (child) {
            if (child.nodeType == 1) {
                children.push(child);
            }
            child = child.nextSibling;
        }
        return children;
    };
    qq.getByClass = function (element, className) {
        if (element.querySelectorAll) {
            return element.querySelectorAll("." + className);
        }
        var result = [];
        var candidates = element.getElementsByTagName("*");
        var len = candidates.length;
        for (var i = 0; i < len; i++) {
            if (qq.hasClass(candidates[i], className)) {
                result.push(candidates[i]);
            }
        }
        return result;
    };
    qq.obj2url = function (obj, temp, prefixDone) {
        var uristrings = [],
            prefix = "&",
            add = function (nextObj, i) {
                var nextTemp = temp ? (/\[\]$/.test(temp) ? temp : temp + "[" + i + "]") : i;
                if (nextTemp != "undefined" && i != "undefined") {
                    uristrings.push(
                        typeof nextObj === "object"
                            ? qq.obj2url(nextObj, nextTemp, true)
                            : Object.prototype.toString.call(nextObj) === "[object Function]"
                              ? encodeURIComponent(nextTemp) + "=" + encodeURIComponent(nextObj())
                              : encodeURIComponent(nextTemp) + "=" + encodeURIComponent(nextObj)
                    );
                }
            };
        if (!prefixDone && temp) {
            prefix = /\?/.test(temp) ? (/\?$/.test(temp) ? "" : "&") : "?";
            uristrings.push(temp);
            uristrings.push(qq.obj2url(obj));
        } else if (Object.prototype.toString.call(obj) === "[object Array]" && typeof obj != "undefined") {
            for (var i = 0, len = obj.length; i < len; ++i) {
                add(obj[i], i);
            }
        } else if (typeof obj != "undefined" && obj !== null && typeof obj === "object") {
            for (var i in obj) {
                add(obj[i], i);
            }
        } else {
            uristrings.push(encodeURIComponent(temp) + "=" + encodeURIComponent(obj));
        }
        return uristrings.join(prefix).replace(/^&/, "").replace(/%20/g, "+");
    };
    var qq = qq || {};
    qq.FileUploaderBasic = function (o) {
        this._options = {
            debug: false,
            action: "/server/upload",
            params: {},
            button: null,
            multiple: true,
            maxConnections: 3,
            allowedExtensions: [],
            sizeLimit: 0,
            minSizeLimit: 0,
            onSubmit: function (id, fileName) {},
            onProgress: function (id, fileName, loaded, total) {},
            onComplete: function (id, fileName, responseJSON) {},
            onCancel: function (id, fileName) {},
            messages: {
                typeError: "{file} has invalid extension. Only {extensions} are allowed.",
                sizeError: "{file} is too large, maximum file size is {sizeLimit}.",
                minSizeError: "{file} is too small, minimum file size is {minSizeLimit}.",
                emptyError: "{file} is empty, please select files again without it.",
                onLeave: "The files are being uploaded, if you leave now the upload will be cancelled.",
            },
            showMessage: function (message) {
                alert(message);
            },
        };
        qq.extend(this._options, o);
        this._filesInProgress = 0;
        this._handler = this._createUploadHandler();
        if (this._options.button) {
            this._button = this._createUploadButton(this._options.button);
        }
        this._preventLeaveInProgress();
    };
    qq.FileUploaderBasic.prototype = {
        setParams: function (params) {
            this._options.params = params;
        },
        getInProgress: function () {
            return this._filesInProgress;
        },
        _createUploadButton: function (element) {
            var self = this;
            return new qq.UploadButton({
                element: element,
                multiple: this._options.multiple && qq.UploadHandlerXhr.isSupported(),
                onChange: function (input) {
                    self._onInputChange(input);
                },
            });
        },
        _createUploadHandler: function () {
            var self = this,
                handlerClass;
            if (qq.UploadHandlerXhr.isSupported()) {
                handlerClass = "UploadHandlerXhr";
            } else {
                handlerClass = "UploadHandlerForm";
            }
            var handler = new qq[handlerClass]({
                debug: this._options.debug,
                action: this._options.action,
                maxConnections: this._options.maxConnections,
                onProgress: function (id, fileName, loaded, total) {
                    self._onProgress(id, fileName, loaded, total);
                    self._options.onProgress(id, fileName, loaded, total);
                },
                onComplete: function (id, fileName, result) {
                    self._onComplete(id, fileName, result);
                    self._options.onComplete(id, fileName, result);
                },
                onCancel: function (id, fileName) {
                    self._onCancel(id, fileName);
                    self._options.onCancel(id, fileName);
                },
            });
            return handler;
        },
        _preventLeaveInProgress: function () {
            var self = this;
            qq.attach(window, "beforeunload", function (e) {
                if (!self._filesInProgress) {
                    return;
                }
                var e = e || window.event;
                e.returnValue = self._options.messages.onLeave;
                return self._options.messages.onLeave;
            });
        },
        _onSubmit: function (id, fileName) {
            this._filesInProgress++;
        },
        _onProgress: function (id, fileName, loaded, total) {},
        _onComplete: function (id, fileName, result) {
            this._filesInProgress--;
            if (result.error) {
                this._options.showMessage(result.error);
            }
        },
        _onCancel: function (id, fileName) {
            this._filesInProgress--;
        },
        _onInputChange: function (input) {
            if (this._handler instanceof qq.UploadHandlerXhr) {
                this._uploadFileList(input.files);
            } else {
                if (this._validateFile(input)) {
                    this._uploadFile(input);
                }
            }
            this._button.reset();
        },
        _uploadFileList: function (files) {
            for (var i = 0; i < files.length; i++) {
                if (!this._validateFile(files[i])) {
                    return;
                }
            }
            for (var i = 0; i < files.length; i++) {
                this._uploadFile(files[i]);
            }
        },
        _uploadFile: function (fileContainer) {
            var id = this._handler.add(fileContainer);
            var fileName = this._handler.getName(id);
            if (this._options.onSubmit(id, fileName) !== false) {
                this._onSubmit(id, fileName);
                this._handler.upload(id, this._options.params);
            }
        },
        _validateFile: function (file) {
            var name, size;
            if (file.value) {
                name = file.value.replace(/.*(\/|\\)/, "");
            } else {
                name = file.fileName != null ? file.fileName : file.name;
                size = file.fileSize != null ? file.fileSize : file.size;
            }
            if (!this._isAllowedExtension(name)) {
                this._error("typeError", name);
                return false;
            } else if (size === 0) {
                this._error("emptyError", name);
                return false;
            } else if (size && this._options.sizeLimit && size > this._options.sizeLimit) {
                this._error("sizeError", name);
                return false;
            } else if (size && size < this._options.minSizeLimit) {
                this._error("minSizeError", name);
                return false;
            }
            return true;
        },
        _error: function (code, fileName) {
            var message = this._options.messages[code];
            function r(name, replacement) {
                message = message.replace(name, replacement);
            }
            r("{file}", this._formatFileName(fileName));
            r("{extensions}", this._options.allowedExtensions.join(", "));
            r("{sizeLimit}", this._formatSize(this._options.sizeLimit));
            r("{minSizeLimit}", this._formatSize(this._options.minSizeLimit));
            this._options.showMessage(message);
        },
        _formatFileName: function (name) {
            if (name.length > 33) {
                name = name.slice(0, 19) + "..." + name.slice(-13);
            }
            return name;
        },
        _isAllowedExtension: function (fileName) {
            var ext = -1 !== fileName.indexOf(".") ? fileName.replace(/.*[.]/, "").toLowerCase() : "";
            var allowed = this._options.allowedExtensions;
            if (!allowed.length) {
                return true;
            }
            for (var i = 0; i < allowed.length; i++) {
                if (allowed[i].toLowerCase() == ext) {
                    return true;
                }
            }
            return false;
        },
        _formatSize: function (bytes) {
            var i = -1;
            do {
                bytes = bytes / 1024;
                i++;
            } while (bytes > 99);
            return Math.max(bytes, 0.1).toFixed(1) + ["kB", "MB", "GB", "TB", "PB", "EB"][i];
        },
    };
    qq.FileUploader = function (o) {
        qq.FileUploaderBasic.apply(this, arguments);
        qq.extend(this._options, {
            element: null,
            listElement: null,
            template:
                '<div class="qq-uploader">' +
                '<div class="qq-upload-drop-area"><span>Drop files here to upload</span></div>' +
                '<div class="qq-upload-button">Upload a file</div>' +
                '<ul class="qq-upload-list"></ul>' +
                "</div>",
            fileTemplate:
                "<li>" +
                '<span class="qq-upload-file"></span>' +
                '<span class="qq-upload-spinner"></span>' +
                '<span class="qq-upload-size"></span>' +
                '<a class="qq-upload-cancel" href="#">Cancel</a>' +
                '<span class="qq-upload-failed-text">Failed</span>' +
                "</li>",
            classes: {
                button: "qq-upload-button",
                drop: "qq-upload-drop-area",
                dropActive: "qq-upload-drop-area-active",
                list: "qq-upload-list",
                file: "qq-upload-file",
                spinner: "qq-upload-spinner",
                size: "qq-upload-size",
                cancel: "qq-upload-cancel",
                success: "qq-upload-success",
                fail: "qq-upload-fail",
            },
        });
        qq.extend(this._options, o);
        this._element = this._options.element;
        this._element.innerHTML = this._options.template;
        this._listElement = this._options.listElement || this._find(this._element, "list");
        this._classes = this._options.classes;
        this._button = this._createUploadButton(this._find(this._element, "button"));
        this._bindCancelEvent();
        this._setupDragDrop();
    };
    qq.extend(qq.FileUploader.prototype, qq.FileUploaderBasic.prototype);
    qq.extend(qq.FileUploader.prototype, {
        _find: function (parent, type) {
            var element = qq.getByClass(parent, this._options.classes[type])[0];
            if (!element) {
                throw new Error("element not found " + type);
            }
            return element;
        },
        _setupDragDrop: function () {
            var self = this,
                dropArea = this._find(this._element, "drop");
            var dz = new qq.UploadDropZone({
                element: dropArea,
                onEnter: function (e) {
                    qq.addClass(dropArea, self._classes.dropActive);
                    e.stopPropagation();
                },
                onLeave: function (e) {
                    e.stopPropagation();
                },
                onLeaveNotDescendants: function (e) {
                    qq.removeClass(dropArea, self._classes.dropActive);
                },
                onDrop: function (e) {
                    dropArea.style.display = "none";
                    qq.removeClass(dropArea, self._classes.dropActive);
                    self._uploadFileList(e.dataTransfer.files);
                },
            });
            dropArea.style.display = "none";
            qq.attach(document, "dragenter", function (e) {
                if (!dz._isValidFileDrag(e)) return;
                dropArea.style.display = "block";
            });
            qq.attach(document, "dragleave", function (e) {
                if (!dz._isValidFileDrag(e)) return;
                var relatedTarget = document.elementFromPoint(e.clientX, e.clientY);
                if (!relatedTarget || relatedTarget.nodeName == "HTML") {
                    dropArea.style.display = "none";
                }
            });
        },
        _onSubmit: function (id, fileName) {
            qq.FileUploaderBasic.prototype._onSubmit.apply(this, arguments);
            this._addToList(id, fileName);
        },
        _onProgress: function (id, fileName, loaded, total) {
            qq.FileUploaderBasic.prototype._onProgress.apply(this, arguments);
            var item = this._getItemByFileId(id);
            var size = this._find(item, "size");
            size.style.display = "inline";
            var text;
            if (loaded != total) {
                text = Math.round((loaded / total) * 100) + "% from " + this._formatSize(total);
            } else {
                text = this._formatSize(total);
            }
            qq.setText(size, text);
        },
        _onComplete: function (id, fileName, result) {
            qq.FileUploaderBasic.prototype._onComplete.apply(this, arguments);
            var item = this._getItemByFileId(id);
            qq.remove(this._find(item, "cancel"));
            qq.remove(this._find(item, "spinner"));
            if (result.success) {
                qq.addClass(item, this._classes.success);
            } else {
                qq.addClass(item, this._classes.fail);
            }
        },
        _addToList: function (id, fileName) {
            var item = qq.toElement(this._options.fileTemplate);
            item.qqFileId = id;
            var fileElement = this._find(item, "file");
            qq.setText(fileElement, this._formatFileName(fileName));
            this._find(item, "size").style.display = "none";
            this._listElement.appendChild(item);
        },
        _getItemByFileId: function (id) {
            var item = this._listElement.firstChild;
            while (item) {
                if (item.qqFileId == id) return item;
                item = item.nextSibling;
            }
        },
        _bindCancelEvent: function () {
            var self = this,
                list = this._listElement;
            qq.attach(list, "click", function (e) {
                e = e || window.event;
                var target = e.target || e.srcElement;
                if (qq.hasClass(target, self._classes.cancel)) {
                    qq.preventDefault(e);
                    var item = target.parentNode;
                    self._handler.cancel(item.qqFileId);
                    qq.remove(item);
                }
            });
        },
    });
    qq.UploadDropZone = function (o) {
        this._options = {
            element: null,
            onEnter: function (e) {},
            onLeave: function (e) {},
            onLeaveNotDescendants: function (e) {},
            onDrop: function (e) {},
        };
        qq.extend(this._options, o);
        this._element = this._options.element;
        this._disableDropOutside();
        this._attachEvents();
    };
    qq.UploadDropZone.prototype = {
        _disableDropOutside: function (e) {
            if (!qq.UploadDropZone.dropOutsideDisabled) {
                qq.attach(document, "dragover", function (e) {
                    if (e.dataTransfer) {
                        e.dataTransfer.dropEffect = "none";
                        e.preventDefault();
                    }
                });
                qq.UploadDropZone.dropOutsideDisabled = true;
            }
        },
        _attachEvents: function () {
            var self = this;
            qq.attach(self._element, "dragover", function (e) {
                if (!self._isValidFileDrag(e)) return;
                var effect = e.dataTransfer.effectAllowed;
                if (effect == "move" || effect == "linkMove") {
                    e.dataTransfer.dropEffect = "move";
                } else {
                    e.dataTransfer.dropEffect = "copy";
                }
                e.stopPropagation();
                e.preventDefault();
            });
            qq.attach(self._element, "dragenter", function (e) {
                if (!self._isValidFileDrag(e)) return;
                self._options.onEnter(e);
            });
            qq.attach(self._element, "dragleave", function (e) {
                if (!self._isValidFileDrag(e)) return;
                self._options.onLeave(e);
                var relatedTarget = document.elementFromPoint(e.clientX, e.clientY);
                if (qq.contains(this, relatedTarget)) return;
                self._options.onLeaveNotDescendants(e);
            });
            qq.attach(self._element, "drop", function (e) {
                if (!self._isValidFileDrag(e)) return;
                e.preventDefault();
                self._options.onDrop(e);
            });
        },
        _isValidFileDrag: function (e) {
            var dt = e.dataTransfer,
                isWebkit = navigator.userAgent.indexOf("AppleWebKit") > -1;
            return (
                dt &&
                dt.effectAllowed != "none" &&
                (dt.files || (!isWebkit && dt.types.contains && dt.types.contains("Files")))
            );
        },
    };
    qq.UploadButton = function (o) {
        this._options = {
            element: null,
            multiple: false,
            name: "file",
            onChange: function (input) {},
            hoverClass: "qq-upload-button-hover",
            focusClass: "qq-upload-button-focus",
        };
        qq.extend(this._options, o);
        this._element = this._options.element;
        qq.css(this._element, { position: "relative", overflow: "hidden", direction: "ltr" });
        this._input = this._createInput();
    };
    qq.UploadButton.prototype = {
        getInput: function () {
            return this._input;
        },
        reset: function () {
            if (this._input.parentNode) {
                qq.remove(this._input);
            }
            qq.removeClass(this._element, this._options.focusClass);
            this._input = this._createInput();
        },
        _createInput: function () {
            var input = document.createElement("input");
            if (this._options.multiple) {
                input.setAttribute("multiple", "multiple");
            }
            input.setAttribute("type", "file");
            input.setAttribute("name", this._options.name);
            qq.css(input, {
                position: "absolute",
                right: 0,
                top: 0,
                fontFamily: "Arial",
                fontSize: "118px",
                margin: 0,
                padding: 0,
                cursor: "pointer",
                opacity: 0,
            });
            this._element.appendChild(input);
            var self = this;
            qq.attach(input, "change", function () {
                self._options.onChange(input);
            });
            qq.attach(input, "mouseover", function () {
                qq.addClass(self._element, self._options.hoverClass);
            });
            qq.attach(input, "mouseout", function () {
                qq.removeClass(self._element, self._options.hoverClass);
            });
            qq.attach(input, "focus", function () {
                qq.addClass(self._element, self._options.focusClass);
            });
            qq.attach(input, "blur", function () {
                qq.removeClass(self._element, self._options.focusClass);
            });
            if (window.attachEvent) {
                input.setAttribute("tabIndex", "-1");
            }
            return input;
        },
    };
    qq.UploadHandlerAbstract = function (o) {
        this._options = {
            debug: false,
            action: "/upload.php",
            maxConnections: 999,
            onProgress: function (id, fileName, loaded, total) {},
            onComplete: function (id, fileName, response) {},
            onCancel: function (id, fileName) {},
        };
        qq.extend(this._options, o);
        this._queue = [];
        this._params = [];
    };
    qq.UploadHandlerAbstract.prototype = {
        log: function (str) {
            if (this._options.debug && window.console) console.log("[uploader] " + str);
        },
        add: function (file) {},
        upload: function (id, params) {
            var len = this._queue.push(id);
            var copy = {};
            qq.extend(copy, params);
            this._params[id] = copy;
            if (len <= this._options.maxConnections) {
                this._upload(id, this._params[id]);
            }
        },
        cancel: function (id) {
            this._cancel(id);
            this._dequeue(id);
        },
        cancelAll: function () {
            for (var i = 0; i < this._queue.length; i++) {
                this._cancel(this._queue[i]);
            }
            this._queue = [];
        },
        getName: function (id) {},
        getSize: function (id) {},
        getQueue: function () {
            return this._queue;
        },
        _upload: function (id) {},
        _cancel: function (id) {},
        _dequeue: function (id) {
            var i = qq.indexOf(this._queue, id);
            this._queue.splice(i, 1);
            var max = this._options.maxConnections;
            if (this._queue.length >= max && i < max) {
                var nextId = this._queue[max - 1];
                this._upload(nextId, this._params[nextId]);
            }
        },
    };
    qq.UploadHandlerForm = function (o) {
        qq.UploadHandlerAbstract.apply(this, arguments);
        this._inputs = {};
    };
    qq.extend(qq.UploadHandlerForm.prototype, qq.UploadHandlerAbstract.prototype);
    qq.extend(qq.UploadHandlerForm.prototype, {
        add: function (fileInput) {
            fileInput.setAttribute("name", "qqfile");
            var id = "qq-upload-handler-iframe" + qq.getUniqueId();
            this._inputs[id] = fileInput;
            if (fileInput.parentNode) {
                qq.remove(fileInput);
            }
            return id;
        },
        getName: function (id) {
            return this._inputs[id].value.replace(/.*(\/|\\)/, "");
        },
        _cancel: function (id) {
            this._options.onCancel(id, this.getName(id));
            delete this._inputs[id];
            var iframe = document.getElementById(id);
            if (iframe) {
                iframe.setAttribute("src", "javascript:false;");
                qq.remove(iframe);
            }
        },
        _upload: function (id, params) {
            var input = this._inputs[id];
            if (!input) {
                throw new Error("file with passed id was not added, or already uploaded or cancelled");
            }
            var fileName = this.getName(id);
            var iframe = this._createIframe(id);
            var form = this._createForm(iframe, params);
            form.appendChild(input);
            var self = this;
            this._attachLoadEvent(iframe, function () {
                self.log("iframe loaded");
                var response = self._getIframeContentJSON(iframe);
                self._options.onComplete(id, fileName, response);
                self._dequeue(id);
                delete self._inputs[id];
                setTimeout(function () {
                    qq.remove(iframe);
                }, 1);
            });
            form.submit();
            qq.remove(form);
            return id;
        },
        _attachLoadEvent: function (iframe, callback) {
            qq.attach(iframe, "load", function () {
                if (!iframe.parentNode) {
                    return;
                }
                if (
                    iframe.contentDocument &&
                    iframe.contentDocument.body &&
                    iframe.contentDocument.body.innerHTML == "false"
                ) {
                    return;
                }
                callback();
            });
        },
        _getIframeContentJSON: function (iframe) {
            var doc = iframe.contentDocument ? iframe.contentDocument : iframe.contentWindow.document,
                response;
            this.log("converting iframe's innerHTML to JSON");
            this.log("innerHTML = " + doc.body.innerHTML);
            try {
                response = eval("(" + doc.body.innerHTML + ")");
            } catch (err) {
                response = {};
            }
            return response;
        },
        _createIframe: function (id) {
            var iframe = qq.toElement('<iframe src="javascript:false;" name="' + id + '" />');
            iframe.setAttribute("id", id);
            iframe.style.display = "none";
            document.body.appendChild(iframe);
            return iframe;
        },
        _createForm: function (iframe, params) {
            var form = qq.toElement('<form method="post" enctype="multipart/form-data"></form>');
            var queryString = qq.obj2url(params, this._options.action);
            form.setAttribute("action", queryString);
            form.setAttribute("target", iframe.name);
            form.style.display = "none";
            document.body.appendChild(form);
            return form;
        },
    });
    qq.UploadHandlerXhr = function (o) {
        qq.UploadHandlerAbstract.apply(this, arguments);
        this._files = [];
        this._xhrs = [];
        this._loaded = [];
    };
    qq.UploadHandlerXhr.isSupported = function () {
        var input = document.createElement("input");
        input.type = "file";
        return "multiple" in input && typeof File != "undefined" && typeof new XMLHttpRequest().upload != "undefined";
    };
    qq.extend(qq.UploadHandlerXhr.prototype, qq.UploadHandlerAbstract.prototype);
    qq.extend(qq.UploadHandlerXhr.prototype, {
        add: function (file) {
            if (!(file instanceof File)) {
                throw new Error("Passed obj in not a File (in qq.UploadHandlerXhr)");
            }
            return this._files.push(file) - 1;
        },
        getName: function (id) {
            var file = this._files[id];
            return file.fileName != null ? file.fileName : file.name;
        },
        getSize: function (id) {
            var file = this._files[id];
            return file.fileSize != null ? file.fileSize : file.size;
        },
        getLoaded: function (id) {
            return this._loaded[id] || 0;
        },
        _upload: function (id, params) {
            var file = this._files[id],
                name = this.getName(id),
                size = this.getSize(id);
            this._loaded[id] = 0;
            var xhr = (this._xhrs[id] = new XMLHttpRequest());
            var self = this;
            xhr.upload.onprogress = function (e) {
                if (e.lengthComputable) {
                    self._loaded[id] = e.loaded;
                    self._options.onProgress(id, name, e.loaded, e.total);
                }
            };
            xhr.onreadystatechange = function () {
                if (xhr.readyState == 4) {
                    self._onComplete(id, xhr);
                }
            };
            params = params || {};
            params["qqfile"] = name;
            var queryString = qq.obj2url(params, this._options.action);
            xhr.open("POST", queryString, true);
            xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
            xhr.setRequestHeader("X-File-Name", encodeURIComponent(name));
            xhr.setRequestHeader("Content-Type", "application/octet-stream");
            xhr.send(file);
        },
        _onComplete: function (id, xhr) {
            if (!this._files[id]) return;
            var name = this.getName(id);
            var size = this.getSize(id);
            this._options.onProgress(id, name, size, size);
            if (xhr.status == 200) {
                this.log("xhr - server response received");
                this.log("responseText = " + xhr.responseText);
                var response;
                try {
                    response = eval("(" + xhr.responseText + ")");
                } catch (err) {
                    response = {};
                }
                this._options.onComplete(id, name, response);
            } else {
                this._options.onComplete(id, name, {});
            }
            this._files[id] = null;
            this._xhrs[id] = null;
            this._dequeue(id);
        },
        _cancel: function (id) {
            this._options.onCancel(id, this.getName(id));
            this._files[id] = null;
            if (this._xhrs[id]) {
                this._xhrs[id].abort();
                this._xhrs[id] = null;
            }
        },
    });
    qq.extend(qq.FileUploader.prototype, {
        _createUploadHandler: function () {
            var self = this,
                handlerClass;
            if (qq.UploadHandlerXhr.isSupported()) {
                handlerClass = "UploadHandlerXhr";
            } else {
                handlerClass = "UploadHandlerForm";
            }
            var handler = new qq[handlerClass]({
                debug: this._options.debug,
                action: this._options.action,
                maxConnections: this._options.maxConnections,
                onProgress: function (id, fileName, loaded, total) {
                    self._onProgress(id, fileName, loaded, total);
                    self._options.onProgress(id, fileName, loaded, total);
                },
                onComplete: function (id, fileName, result) {
                    self._onComplete(id, fileName, result);
                    self._options.onComplete(id, fileName, result);
                },
                onCancel: function (id, fileName) {
                    self._onCancel(id, fileName);
                    self._options.onCancel(id, fileName);
                },
                onUpload: function () {
                    self._onUpload();
                },
            });
            return handler;
        },
        _onUpload: function () {
            this._handler.uploadAll(this._options.params);
        },
        _uploadFile: function (fileContainer) {
            var id = this._handler.add(fileContainer);
            var fileName = this._handler.getName(id);
            if (this._options.onSubmit(id, fileName) !== false) {
                this._onSubmit(id, fileName);
            }
        },
        _addToList: function (id, fileName) {
            var item = qq.toElement(this._options.fileTemplate);
            item.qqFileId = id;
            var fileElement = this._find(item, "file");
            qq.setText(fileElement, fileName);
            this._find(item, "size").style.display = "none";
            var nameElement = this._find(item, "nameInput");
            fileName = fileName.toLowerCase();
            fileName = fileName.replace(/([ !"#$%&\'()+,\/;<=>?@[\]^`{|}~:]+)/g, "_");
            fileName = fileName.replace(/^_+/, "");
            nameElement.value = fileName;
            nameElement.id = "mediamanager__upload_item" + id;
            this._listElement.appendChild(item);
        },
    });
    qq.FileUploaderExtended = function (o) {
        qq.FileUploaderBasic.apply(this, arguments);
        qq.extend(this._options, {
            element: null,
            listElement: null,
            template:
                '<div class="qq-uploader">' +
                '<div class="qq-upload-drop-area"><span>' +
                LANG.media_drop +
                "</span></div>" +
                '<div class="qq-upload-button">' +
                LANG.media_select +
                "</div>" +
                '<ul class="qq-upload-list"></ul>' +
                '<div class="qq-action-container">' +
                '  <input class="qq-upload-action button" type="submit" value="' +
                LANG.media_upload_btn +
                '" id="mediamanager__upload_button">' +
                '  <label class="qq-overwrite-check"><input type="checkbox" value="1" name="ow" class="dw__ow"> <span>' +
                LANG.media_overwrt +
                "</span></label>" +
                "</div>" +
                "</div>",
            fileTemplate:
                "<li>" +
                '<span class="qq-upload-file hidden"></span>' +
                '  <input class="qq-upload-name-input edit" type="text" value="" />' +
                '  <span class="qq-upload-spinner hidden"></span>' +
                '  <span class="qq-upload-size"></span>' +
                '  <a class="qq-upload-cancel" href="#">' +
                LANG.media_cancel +
                "</a>" +
                '  <span class="qq-upload-failed-text error">Failed</span>' +
                "</li>",
            classes: {
                button: "qq-upload-button",
                drop: "qq-upload-drop-area",
                dropActive: "qq-upload-drop-area-active",
                list: "qq-upload-list",
                nameInput: "qq-upload-name-input",
                overwriteInput: "qq-overwrite-check",
                uploadButton: "qq-upload-action",
                file: "qq-upload-file",
                spinner: "qq-upload-spinner",
                size: "qq-upload-size",
                cancel: "qq-upload-cancel",
                success: "qq-upload-success",
                fail: "qq-upload-fail",
                failedText: "qq-upload-failed-text",
            },
        });
        qq.extend(this._options, o);
        this._element = this._options.element;
        this._element.innerHTML = this._options.template;
        this._listElement = this._options.listElement || this._find(this._element, "list");
        this._classes = this._options.classes;
        this._button = this._createUploadButton(this._find(this._element, "button"));
        this._bindCancelEvent();
        this._bindUploadEvent();
        this._setupDragDrop();
    };
    qq.extend(qq.FileUploaderExtended.prototype, qq.FileUploader.prototype);
    qq.extend(qq.FileUploaderExtended.prototype, {
        _bindUploadEvent: function () {
            var self = this,
                list = this._listElement;
            qq.attach(document.getElementById("mediamanager__upload_button"), "click", function (e) {
                e = e || window.event;
                var target = e.target || e.srcElement;
                qq.preventDefault(e);
                self._handler._options.onUpload();
                jQuery(".qq-upload-name-input").each(function (i) {
                    jQuery(this).attr("disabled", "disabled");
                });
            });
        },
        _onComplete: function (id, fileName, result) {
            this._filesInProgress--;
            var item = this._getItemByFileId(id);
            qq.remove(this._find(item, "cancel"));
            qq.remove(this._find(item, "spinner"));
            var nameInput = this._find(item, "nameInput");
            var fileElement = this._find(item, "file");
            qq.setText(fileElement, nameInput.value);
            qq.removeClass(fileElement, "hidden");
            qq.remove(nameInput);
            jQuery(".qq-upload-button, #mediamanager__upload_button").remove();
            jQuery(".dw__ow").parent().hide();
            jQuery(".qq-upload-drop-area").remove();
            if (result.success) {
                qq.addClass(item, this._classes.success);
                $link =
                    '<a href="' +
                    result.link +
                    '" id="h_:' +
                    result.id +
                    '" class="select">' +
                    nameInput.value +
                    "</a>";
                jQuery(fileElement).html($link);
            } else {
                qq.addClass(item, this._classes.fail);
                var fail = this._find(item, "failedText");
                if (result.error) qq.setText(fail, result.error);
            }
            if (document.getElementById("media__content") && !document.getElementById("mediamanager__done_form")) {
                var action = document.location.href;
                var i = action.indexOf("?");
                if (i) action = action.substr(0, i);
                var button = '<form method="post" action="' + action + '" id="mediamanager__done_form"><div>';
                button += '<input type="hidden" value="' + result.ns + '" name="ns">';
                button += '<input type="hidden" value="1" name="recent">';
                button += '<input class="button" type="submit" value="' + LANG.media_done_btn + '"></div></form>';
                jQuery("#mediamanager__uploader").append(button);
            }
        },
    });
    qq.extend(qq.UploadHandlerForm.prototype, {
        uploadAll: function (params) {
            this._uploadAll(params);
        },
        getName: function (id) {
            var file = this._inputs[id];
            var name = document.getElementById("mediamanager__upload_item" + id);
            if (name != null) {
                return name.value;
            } else {
                if (file != null) {
                    return file.value.replace(/.*(\/|\\)/, "");
                } else {
                    return null;
                }
            }
        },
        _uploadAll: function (params) {
            jQuery(".qq-upload-spinner").each(function (i) {
                jQuery(this).removeClass("hidden");
            });
            for (key in this._inputs) {
                this.upload(key, params);
            }
        },
        _upload: function (id, params) {
            var input = this._inputs[id];
            if (!input) {
                throw new Error("file with passed id was not added, or already uploaded or cancelled");
            }
            var fileName = this.getName(id);
            var iframe = this._createIframe(id);
            var form = this._createForm(iframe, params);
            form.appendChild(input);
            var nameInput = qq.toElement('<input name="mediaid" value="' + fileName + '" type="text">');
            form.appendChild(nameInput);
            var checked = jQuery(".dw__ow").attr("checked");
            var owCheckbox = jQuery(".dw__ow").clone();
            owCheckbox.attr("checked", checked);
            jQuery(form).append(owCheckbox);
            var self = this;
            this._attachLoadEvent(iframe, function () {
                self.log("iframe loaded");
                var response = self._getIframeContentJSON(iframe);
                self._options.onComplete(id, fileName, response);
                self._dequeue(id);
                delete self._inputs[id];
                setTimeout(function () {
                    qq.remove(iframe);
                }, 1);
            });
            form.submit();
            qq.remove(form);
            return id;
        },
    });
    qq.extend(qq.UploadHandlerXhr.prototype, {
        uploadAll: function (params) {
            this._uploadAll(params);
        },
        getName: function (id) {
            var file = this._files[id];
            var name = document.getElementById("mediamanager__upload_item" + id);
            if (name != null) {
                return name.value;
            } else {
                if (file != null) {
                    return file.fileName != null ? file.fileName : file.name;
                } else {
                    return null;
                }
            }
        },
        getSize: function (id) {
            var file = this._files[id];
            if (file == null) return null;
            return file.fileSize != null ? file.fileSize : file.size;
        },
        _upload: function (id, params) {
            var file = this._files[id],
                name = this.getName(id),
                size = this.getSize(id);
            if (name == null || size == null) return;
            this._loaded[id] = 0;
            var xhr = (this._xhrs[id] = new XMLHttpRequest());
            var self = this;
            xhr.upload.onprogress = function (e) {
                if (e.lengthComputable) {
                    self._loaded[id] = e.loaded;
                    self._options.onProgress(id, name, e.loaded, e.total);
                }
            };
            xhr.onreadystatechange = function () {
                if (xhr.readyState == 4) {
                    self._onComplete(id, xhr);
                }
            };
            params = params || {};
            params["qqfile"] = name;
            params["ow"] = jQuery(".dw__ow").attr("checked");
            var queryString = qq.obj2url(params, this._options.action);
            xhr.open("POST", queryString, true);
            xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
            xhr.setRequestHeader("X-File-Name", encodeURIComponent(name));
            xhr.setRequestHeader("Content-Type", "application/octet-stream");
            xhr.send(file);
        },
        _uploadAll: function (params) {
            jQuery(".qq-upload-spinner").each(function (i) {
                jQuery(this).removeClass("hidden");
            });
            for (key in this._files) {
                this.upload(key, params);
            }
        },
    });
    function substr_replace(str, replace, start, length) {
        var a2, b1;
        a2 = (start < 0 ? str.length : 0) + start;
        if (typeof length === "undefined") {
            length = str.length - a2;
        } else if (length < 0 && start < 0 && length <= start) {
            length = 0;
        }
        b1 = (length < 0 ? str.length : a2) + length;
        return str.substring(0, a2) + replace + str.substring(b1);
    }
    function bind(fnc) {
        var Aps = Array.prototype.slice,
            static_args = Aps.call(arguments, 1);
        return function () {
            return fnc.apply(this, static_args.concat(Aps.call(arguments, 0)));
        };
    }
    function logError(e, file) {
        if (window.console && console.error) {
            console.error(
                'The error "%s: %s" occurred in file "%s". ' +
                    "If this is in a plugin try updating or disabling the plugin, " +
                    'if this is in a template try updating the template or switching to the "dokuwiki" template.',
                e.name,
                e.message,
                file
            );
        }
    }
    var timer = {
        _cur_id: 0,
        _handlers: {},
        execDispatch: function (id) {
            timer._handlers[id]();
        },
        add: function (func, timeout) {
            var id = ++timer._cur_id;
            timer._handlers[id] = func;
            return window.setTimeout("timer.execDispatch(" + id + ")", timeout);
        },
    };
    function Delay(func, timeout) {
        this.func = func;
        if (timeout) {
            this.timeout = timeout;
        }
    }
    Delay.prototype = {
        func: null,
        timeout: 500,
        delTimer: function () {
            if (this.timer !== null) {
                window.clearTimeout(this.timer);
                this.timer = null;
            }
        },
        start: function () {
            DEPRECATED("don't use the Delay object, use window.timeout with a callback instead");
            this.delTimer();
            var _this = this;
            this.timer = timer.add(function () {
                _this.exec.call(_this);
            }, this.timeout);
            this._data = { _this: arguments[0], _params: Array.prototype.slice.call(arguments, 2) };
        },
        exec: function () {
            this.delTimer();
            this.func.call(this._data._this, this._data._params);
        },
    };
    var DokuCookie = {
        data: {},
        name: "DOKU_PREFS",
        setValue: function (key, val) {
            var text = [],
                _this = this;
            this.init();
            this.data[key] = val;
            jQuery.each(_this.data, function (key, val) {
                if (_this.data.hasOwnProperty(key)) {
                    text.push(encodeURIComponent(key) + "#" + encodeURIComponent(val));
                }
            });
            jQuery.cookie(this.name, text.join("#"), {
                expires: 365,
                path: DOKU_COOKIE_PARAM.path,
                secure: DOKU_COOKIE_PARAM.secure,
            });
        },
        getValue: function (key) {
            this.init();
            return this.data[key];
        },
        init: function () {
            var text, parts, i;
            if (!jQuery.isEmptyObject(this.data)) {
                return;
            }
            text = jQuery.cookie(this.name);
            if (text) {
                parts = text.split("#");
                for (i = 0; i < parts.length; i += 2) {
                    this.data[decodeURIComponent(parts[i])] = decodeURIComponent(parts[i + 1]);
                }
            }
        },
    };
    if ("function" === typeof jQuery && "function" === typeof jQuery.noConflict) {
        jQuery.noConflict();
    }
    var clientPC = navigator.userAgent.toLowerCase();
    var is_macos = navigator.appVersion.indexOf("Mac") != -1;
    var is_gecko =
        clientPC.indexOf("gecko") != -1 &&
        clientPC.indexOf("spoofer") == -1 &&
        clientPC.indexOf("khtml") == -1 &&
        clientPC.indexOf("netscape/7.0") == -1;
    var is_safari = clientPC.indexOf("applewebkit") != -1 && clientPC.indexOf("spoofer") == -1;
    var is_khtml = navigator.vendor == "KDE" || (document.childNodes && !document.all && !navigator.taintEnabled);
    if (clientPC.indexOf("opera") != -1) {
        var is_opera = true;
        var is_opera_preseven = window.opera && !document.childNodes;
        var is_opera_seven = window.opera && document.childNodes;
    }
    function showLoadBar() {
        document.write('<img src="' + DOKU_BASE + 'lib/images/loading.gif" ' + 'width="150" height="12" alt="..." />');
    }
    function hideLoadBar(id) {
        jQuery("#" + id).hide();
    }
    function closePopups() {
        jQuery("div.JSpopup").hide();
    }
    jQuery(function () {
        jQuery(document).click(closePopups);
    });
    function sack(file) {
        this.AjaxFailedAlert =
            "Your browser does not support the enhanced functionality of this website, and therefore you will have an experience that differs from the intended one.\n";
        this.requestFile = file;
        this.method = "POST";
        this.URLString = "";
        this.encodeURIString = true;
        this.execute = false;
        this.asynchronous = true;
        this.onLoading = function () {};
        this.onLoaded = function () {};
        this.onInteractive = function () {};
        this.onCompletion = function () {};
        this.afterCompletion = function () {};
        this.createAJAX = function () {
            try {
                this.xmlhttp = new ActiveXObject("Msxml2.XMLHTTP");
            } catch (e) {
                try {
                    this.xmlhttp = new ActiveXObject("Microsoft.XMLHTTP");
                } catch (err) {
                    this.xmlhttp = null;
                }
            }
            if (!this.xmlhttp && typeof XMLHttpRequest != "undefined") {
                this.xmlhttp = new XMLHttpRequest();
            }
            if (!this.xmlhttp) {
                this.failed = true;
            }
        };
        this.setVar = function (name, value) {
            if (this.URLString.length < 3) {
                this.URLString = name + "=" + value;
            } else {
                this.URLString += "&" + name + "=" + value;
            }
        };
        this.encVar = function (name, value) {
            var varString = encodeURIComponent(name) + "=" + encodeURIComponent(value);
            return varString;
        };
        this.encodeURLString = function (string) {
            varArray = string.split("&");
            for (i = 0; i < varArray.length; i++) {
                urlVars = varArray[i].split("=");
                if (urlVars[0].indexOf("amp;") != -1) {
                    urlVars[0] = urlVars[0].substring(4);
                }
                varArray[i] = this.encVar(urlVars[0], urlVars[1]);
            }
            return varArray.join("&");
        };
        this.runResponse = function () {
            eval(this.response);
        };
        this.runAJAX = function (urlstring) {
            DEPRECATED("Please use jQuery.post() or any other of jQuery's AJAX methods.");
            this.responseStatus = new Array(2);
            if (this.failed && this.AjaxFailedAlert) {
                alert(this.AjaxFailedAlert);
            } else {
                if (urlstring) {
                    if (this.URLString.length) {
                        this.URLString = this.URLString + "&" + urlstring;
                    } else {
                        this.URLString = urlstring;
                    }
                }
                if (this.encodeURIString) {
                    var timeval = new Date().getTime();
                    this.URLString = this.encodeURLString(this.URLString);
                    this.setVar("rndval", timeval);
                }
                if (this.element) {
                    this.elementObj = document.getElementById(this.element);
                }
                if (this.xmlhttp) {
                    var self = this;
                    if (this.method == "GET") {
                        var totalurlstring = this.requestFile + "?" + this.URLString;
                        this.xmlhttp.open(this.method, totalurlstring, this.asynchronous);
                    } else {
                        this.xmlhttp.open(this.method, this.requestFile, this.asynchronous);
                    }
                    if (this.method == "POST") {
                        try {
                            this.xmlhttp.setRequestHeader(
                                "Content-Type",
                                "application/x-www-form-urlencoded; charset=UTF-8"
                            );
                        } catch (e) {}
                    }
                    this.xmlhttp.onreadystatechange = function () {
                        switch (self.xmlhttp.readyState) {
                            case 1:
                                self.onLoading();
                                break;
                            case 2:
                                self.onLoaded();
                                break;
                            case 3:
                                self.onInteractive();
                                break;
                            case 4:
                                self.response = self.xmlhttp.responseText;
                                self.responseXML = self.xmlhttp.responseXML;
                                self.responseStatus[0] = self.xmlhttp.status;
                                self.responseStatus[1] = self.xmlhttp.statusText;
                                self.onCompletion();
                                if (self.execute) {
                                    self.runResponse();
                                }
                                if (self.elementObj) {
                                    var elemNodeName = self.elementObj.nodeName;
                                    elemNodeName.toLowerCase();
                                    if (
                                        elemNodeName == "input" ||
                                        elemNodeName == "select" ||
                                        elemNodeName == "option" ||
                                        elemNodeName == "textarea"
                                    ) {
                                        self.elementObj.value = self.response;
                                    } else {
                                        self.elementObj.innerHTML = self.response;
                                    }
                                }
                                self.afterCompletion();
                                self.URLString = "";
                                break;
                        }
                    };
                    this.xmlhttp.send(this.URLString);
                }
            }
        };
        this.createAJAX();
    }
    var dw_qsearch = {
        $inObj: null,
        $outObj: null,
        timer: null,
        curRequest: null,
        init: function (input, output) {
            var do_qsearch;
            dw_qsearch.$inObj = jQuery(input);
            dw_qsearch.$outObj = jQuery(output);
            if (dw_qsearch.$inObj.length === 0 || dw_qsearch.$outObj.length === 0) {
                return;
            }
            do_qsearch = function () {
                if (dw_qsearch.curRequest != null) {
                    dw_qsearch.curRequest.abort();
                }
                var value = dw_qsearch.$inObj.val();
                if (value === "") {
                    dw_qsearch.clear_results();
                    return;
                }
                dw_qsearch.curRequest = jQuery.post(
                    DOKU_BASE + "lib/exe/ajax.php",
                    { call: "qsearch", q: encodeURI(value) },
                    dw_qsearch.onCompletion,
                    "html"
                );
            };
            dw_qsearch.$inObj.keyup(function () {
                if (dw_qsearch.timer) {
                    window.clearTimeout(dw_qsearch.timer);
                    dw_qsearch.timer = null;
                }
                dw_qsearch.timer = window.setTimeout(do_qsearch, 500);
            });
            dw_qsearch.$outObj.click(dw_qsearch.clear_results);
        },
        clear_results: function () {
            dw_qsearch.$outObj.hide();
            dw_qsearch.$outObj.text("");
        },
        onCompletion: function (data) {
            var max, $links, too_big;
            dw_qsearch.curRequest = null;
            if (data === "") {
                dw_qsearch.clear_results();
                return;
            }
            dw_qsearch.$outObj.html(data).show().css("white-space", "nowrap");
            dw_qsearch.$outObj.find("li").css("overflow", "visible");
            $links = dw_qsearch.$outObj.find("a");
            max = dw_qsearch.$outObj[0].clientWidth;
            if (document.documentElement.dir === "rtl") {
                max -= parseInt(dw_qsearch.$outObj.css("padding-left"));
                too_big = function (l) {
                    return l.offsetLeft < 0;
                };
            } else {
                max -= parseInt(dw_qsearch.$outObj.css("padding-right"));
                too_big = function (l) {
                    return l.offsetWidth + l.offsetLeft > max;
                };
            }
            $links.each(function () {
                var start, length, replace, nsL, nsR, eli, runaway;
                if (!too_big(this)) {
                    return;
                }
                if (this.textContent) {
                    this.__defineGetter__("innerText", function () {
                        return this.textContent;
                    });
                    this.__defineSetter__("innerText", function (val) {
                        this.textContent = val;
                    });
                }
                nsL = this.innerText.indexOf("(");
                nsR = this.innerText.indexOf(")");
                eli = 0;
                runaway = 0;
                while (nsR - nsL > 3 && too_big(this) && runaway++ < 500) {
                    if (eli !== 0) {
                        if (eli - nsL > nsR - eli) {
                            start = eli - 2;
                            length = 2;
                        } else {
                            start = eli + 1;
                            length = 1;
                        }
                        replace = "";
                    } else {
                        start = Math.floor(nsL + (nsR - nsL) / 2);
                        length = 1;
                        replace = "…";
                    }
                    this.innerText = substr_replace(this.innerText, replace, start, length);
                    eli = this.innerText.indexOf("…");
                    nsL = this.innerText.indexOf("(");
                    nsR = this.innerText.indexOf(")");
                }
            });
            dw_qsearch.$outObj.find("li").css("overflow", "hidden").css("text-overflow", "ellipsis");
        },
    };
    jQuery(function () {
        dw_qsearch.init("#qsearch__in", "#qsearch__out");
    });
    jQuery.fn.dw_tree = function (overrides) {
        var dw_tree = {
            throbber_delay: 500,
            $obj: this,
            toggle_selector: "a.idx_dir",
            init: function () {
                this.$obj.delegate(this.toggle_selector, "click", this, this.toggle);
                jQuery("ul:first", this.$obj).attr("role", "tree");
                jQuery("ul", this.$obj).not(":first").attr("role", "group");
                jQuery("li", this.$obj).attr("role", "treeitem");
                jQuery("li.open > ul", this.$obj).attr("aria-expanded", "true");
                jQuery("li.closed > ul", this.$obj).attr("aria-expanded", "false");
                jQuery("li.closed", this.$obj).attr("aria-live", "assertive");
            },
            toggle: function (e) {
                var $listitem, $sublist, timeout, $clicky, show_sublist, dw_tree, opening;
                e.preventDefault();
                dw_tree = e.data;
                $clicky = jQuery(this);
                $listitem = $clicky.closest("li");
                $sublist = $listitem.find("ul").first();
                opening = $listitem.hasClass("closed");
                dw_tree.toggle_display($clicky, opening);
                if ($sublist.is(":visible")) {
                    $listitem.removeClass("open").addClass("closed");
                    $sublist.attr("aria-expanded", "false");
                } else {
                    $listitem.removeClass("closed").addClass("open");
                    $sublist.attr("aria-expanded", "true");
                }
                if (!opening) {
                    $sublist.dw_hide();
                    return;
                }
                show_sublist = function (data) {
                    $sublist.hide();
                    if (typeof data !== "undefined") {
                        $sublist.html(data);
                        $sublist.parent().attr("aria-busy", "false").removeAttr("aria-live");
                        jQuery("li.closed", $sublist).attr("aria-live", "assertive");
                    }
                    if ($listitem.hasClass("open")) {
                        $sublist.dw_show();
                    }
                };
                if ($sublist.length > 0) {
                    show_sublist();
                    return;
                }
                $sublist = jQuery('<ul class="idx" role="group"/>');
                $listitem.append($sublist);
                timeout = window.setTimeout(
                    bind(
                        show_sublist,
                        '<li aria-busy="true"><img src="' +
                            DOKU_BASE +
                            'lib/images/throbber.gif" alt="loading..." title="loading..." /></li>'
                    ),
                    dw_tree.throbber_delay
                );
                dw_tree.load_data(function (data) {
                    window.clearTimeout(timeout);
                    show_sublist(data);
                }, $clicky);
            },
            toggle_display: function ($clicky, opening) {},
            load_data: function (show_data, $clicky) {
                show_data();
            },
        };
        jQuery.extend(dw_tree, overrides);
        if (!overrides.deferInit) {
            dw_tree.init();
        }
        return dw_tree;
    };
    var dw_index = jQuery("#index__tree").dw_tree({
        deferInit: true,
        load_data: function (show_sublist, $clicky) {
            jQuery.post(
                DOKU_BASE + "lib/exe/ajax.php",
                $clicky[0].search.substr(1) + "&call=index",
                show_sublist,
                "html"
            );
        },
    });
    jQuery(function () {
        var $tree = jQuery("#index__tree");
        dw_index.$obj = $tree;
        dw_index.init();
    });
    var drag = {
        obj: null,
        handle: null,
        oX: 0,
        oY: 0,
        eX: 0,
        eY: 0,
        attach: function (obj, handle) {
            DEPRECATED("Use jQuery.draggable() instead.");
            if (handle) {
                handle.dragobject = obj;
            } else {
                handle = obj;
            }
            var _this = this;
            addEvent($(handle), "mousedown", function (e) {
                return _this.start(e);
            });
        },
        start: function (e) {
            this.handle = e.target;
            if (this.handle.dragobject) {
                this.obj = this.handle.dragobject;
            } else {
                this.obj = this.handle;
            }
            this.handle.className += " ondrag";
            this.obj.className += " ondrag";
            this.oX = parseInt(this.obj.style.left);
            this.oY = parseInt(this.obj.style.top);
            this.eX = e.pageX;
            this.eY = e.pageY;
            var _this = this;
            this.mousehandlers = [
                function (e) {
                    return _this.drag(e);
                },
                function (e) {
                    return _this.stop(e);
                },
            ];
            addEvent(document, "mousemove", this.mousehandlers[0]);
            addEvent(document, "mouseup", this.mousehandlers[1]);
            return false;
        },
        stop: function () {
            this.handle.className = this.handle.className.replace(/ ?ondrag/, "");
            this.obj.className = this.obj.className.replace(/ ?ondrag/, "");
            removeEvent(document, "mousemove", this.mousehandlers[0]);
            removeEvent(document, "mouseup", this.mousehandlers[1]);
            this.obj = null;
            this.handle = null;
        },
        drag: function (e) {
            if (this.obj) {
                this.obj.style.top = e.pageY + this.oY - this.eY + "px";
                this.obj.style.left = e.pageX + this.oX - this.eX + "px";
            }
        },
    };
    function selection_class() {
        this.start = 0;
        this.end = 0;
        this.obj = null;
        this.rangeCopy = null;
        this.scroll = 0;
        this.fix = 0;
        this.getLength = function () {
            return this.end - this.start;
        };
        this.getText = function () {
            return !this.obj ? "" : this.obj.value.substring(this.start, this.end);
        };
    }
    function getSelection(textArea) {
        var sel = new selection_class();
        sel.obj = textArea;
        sel.start = textArea.value.length;
        sel.end = textArea.value.length;
        textArea.focus();
        if (document.getSelection) {
            sel.start = textArea.selectionStart;
            sel.end = textArea.selectionEnd;
            sel.scroll = textArea.scrollTop;
        } else if (document.selection) {
            sel.rangeCopy = document.selection.createRange().duplicate();
            if (textArea.tagName === "INPUT") {
                var before_range = textArea.createTextRange();
                before_range.expand("textedit");
            } else {
                var before_range = document.body.createTextRange();
                before_range.moveToElementText(textArea);
            }
            before_range.setEndPoint("EndToStart", sel.rangeCopy);
            var before_finished = false,
                selection_finished = false;
            var before_text, selection_text;
            before_text = before_range.text;
            selection_text = sel.rangeCopy.text;
            sel.start = before_text.length;
            sel.end = sel.start + selection_text.length;
            do {
                if (!before_finished) {
                    if (before_range.compareEndPoints("StartToEnd", before_range) == 0) {
                        before_finished = true;
                    } else {
                        before_range.moveEnd("character", -1);
                        if (before_range.text == before_text) {
                            sel.start += 2;
                            sel.end += 2;
                        } else {
                            before_finished = true;
                        }
                    }
                }
                if (!selection_finished) {
                    if (sel.rangeCopy.compareEndPoints("StartToEnd", sel.rangeCopy) == 0) {
                        selection_finished = true;
                    } else {
                        sel.rangeCopy.moveEnd("character", -1);
                        if (sel.rangeCopy.text == selection_text) {
                            sel.end += 2;
                        } else {
                            selection_finished = true;
                        }
                    }
                }
            } while (!before_finished || !selection_finished);
            var countNL = function (str) {
                var m = str.split("\r\n");
                if (!m || !m.length) return 0;
                return m.length - 1;
            };
            sel.fix = countNL(sel.obj.value.substring(0, sel.start));
        }
        return sel;
    }
    function setSelection(selection) {
        if (document.getSelection) {
            selection.obj.setSelectionRange(selection.start, selection.end);
            if (selection.scroll) selection.obj.scrollTop = selection.scroll;
        } else if (document.selection) {
            selection.rangeCopy.collapse(true);
            selection.rangeCopy.moveStart("character", selection.start - selection.fix);
            selection.rangeCopy.moveEnd("character", selection.end - selection.start);
            selection.rangeCopy.select();
        }
    }
    function pasteText(selection, text, opts) {
        if (!opts) opts = {};
        selection.obj.value =
            selection.obj.value.substring(0, selection.start) +
            text +
            selection.obj.value.substring(selection.end, selection.obj.value.length);
        if (is_opera) {
            selection.end = selection.start + text.replace(/\r?\n/g, "\r\n").length;
        } else {
            selection.end = selection.start + text.length;
        }
        if (opts.startofs) selection.start += opts.startofs;
        if (opts.endofs) selection.end -= opts.endofs;
        if (opts.nosel) selection.start = selection.end;
        setSelection(selection);
    }
    function insertTags(textAreaID, tagOpen, tagClose, sampleText) {
        var txtarea = jQuery("#" + textAreaID)[0];
        var selection = getSelection(txtarea);
        var text = selection.getText();
        var opts;
        if (text.charAt(text.length - 1) == " ") {
            selection.end--;
            text = selection.getText();
        }
        if (!text) {
            text = sampleText;
            opts = { startofs: tagOpen.length, endofs: tagClose.length };
        } else {
            opts = { nosel: true };
        }
        text = tagOpen + text + tagClose;
        pasteText(selection, text, opts);
    }
    function insertAtCarret(textAreaID, text) {
        var txtarea = jQuery("#" + textAreaID)[0];
        var selection = getSelection(txtarea);
        pasteText(selection, text, { nosel: true });
    }
    var pickercounter = 0;
    function initToolbar(tbid, edid, tb, allowblock) {
        var $toolbar, $edit;
        if (typeof tbid == "string") {
            $toolbar = jQuery("#" + tbid);
        } else {
            $toolbar = jQuery(tbid);
        }
        $edit = jQuery("#" + edid);
        if ($toolbar.length == 0 || $edit.length == 0 || $edit.attr("readOnly")) {
            return;
        }
        if (typeof allowblock === "undefined") {
            allowblock = true;
        }
        $toolbar.html("");
        jQuery.each(tb, function (k, val) {
            if (!tb.hasOwnProperty(k) || (!allowblock && val.block === true)) {
                return;
            }
            var actionFunc, $btn;
            $btn = jQuery(createToolButton(val.icon, val.title, val.key, val.id, val["class"]));
            actionFunc = "tb_" + val.type;
            if (jQuery.isFunction(window[actionFunc])) {
                $btn.bind("click", bind(window[actionFunc], $btn, val, edid));
                $toolbar.append($btn);
                return;
            }
            actionFunc = "addBtnAction" + val.type.charAt(0).toUpperCase() + val.type.substring(1);
            if (jQuery.isFunction(window[actionFunc])) {
                var pickerid = window[actionFunc]($btn, val, edid);
                if (pickerid !== "") {
                    $toolbar.append($btn);
                    $btn.attr("aria-controls", pickerid);
                    if (actionFunc === "addBtnActionPicker") {
                        $btn.attr("aria-haspopup", "true");
                    }
                }
                return;
            }
            alert("unknown toolbar type: " + val.type + "  " + actionFunc);
        });
    }
    function tb_format(btn, props, edid) {
        var sample = props.sample || props.title;
        insertTags(edid, fixtxt(props.open), fixtxt(props.close), fixtxt(sample));
        pickerClose();
        return false;
    }
    function tb_formatln(btn, props, edid) {
        var sample = props.sample || props.title,
            opts,
            selection = getSelection(jQuery("#" + edid)[0]);
        sample = fixtxt(sample);
        props.open = fixtxt(props.open);
        props.close = fixtxt(props.close);
        if (selection.getLength()) {
            sample = selection.getText();
            opts = { nosel: true };
        } else {
            opts = { startofs: props.open.length, endofs: props.close.length };
        }
        sample = sample.split("\n").join(props.close + "\n" + props.open);
        sample = props.open + sample + props.close;
        pasteText(selection, sample, opts);
        pickerClose();
        return false;
    }
    function tb_insert(btn, props, edid) {
        insertAtCarret(edid, fixtxt(props.insert));
        pickerClose();
        return false;
    }
    function tb_mediapopup(btn, props, edid) {
        window.open(
            DOKU_BASE + props.url + encodeURIComponent(NS) + "&edid=" + encodeURIComponent(edid),
            props.name,
            props.options
        );
        return false;
    }
    function tb_autohead(btn, props, edid) {
        var lvl = currentHeadlineLevel(edid),
            tags;
        lvl += props.mod;
        if (lvl < 1) lvl = 1;
        if (lvl > 5) lvl = 5;
        tags = new Array(8 - lvl).join("=");
        insertTags(edid, tags + " ", " " + tags + "\n", props.text);
        pickerClose();
        return false;
    }
    function addBtnActionPicker($btn, props, edid) {
        var pickerid = "picker" + pickercounter++;
        var picker = createPicker(pickerid, props, edid);
        jQuery(picker).attr("aria-hidden", "true");
        $btn.click(function () {
            pickerToggle(pickerid, $btn);
            return "";
        });
        return pickerid;
    }
    function addBtnActionLinkwiz($btn, props, edid) {
        dw_linkwiz.init(jQuery("#" + edid));
        jQuery($btn).click(function () {
            dw_linkwiz.val = props;
            dw_linkwiz.toggle();
            return "";
        });
        return "link__wiz";
    }
    function pickerToggle(pickerid, $btn) {
        var $picker = jQuery("#" + pickerid),
            pos = $btn.offset();
        if ($picker.hasClass("a11y")) {
            $picker.removeClass("a11y").attr("aria-hidden", "false");
        } else {
            $picker.addClass("a11y").attr("aria-hidden", "true");
        }
        $picker.offset({ left: pos.left + 3, top: pos.top + $btn[0].offsetHeight + 3 });
    }
    function pickerClose() {
        jQuery(".picker").addClass("a11y");
    }
    function fixtxt(str) {
        return str.replace(/\\n/g, "\n");
    }
    jQuery(function () {
        initToolbar("tool__bar", "wiki__text", toolbar);
        jQuery("#tool__bar").attr("role", "toolbar");
    });
    function createToolButton(icon, label, key, id, classname) {
        var $btn = jQuery(document.createElement("button")),
            $ico = jQuery(document.createElement("img"));
        $btn.addClass("toolbutton");
        if (classname) {
            $btn.addClass(classname);
        }
        $btn.attr("title", label).attr("aria-controls", "wiki__text");
        if (key) {
            $btn.attr("title", label + " [" + key.toUpperCase() + "]").attr("accessKey", key);
        }
        if (id) {
            $btn.attr("id", id);
            $ico.attr("id", id + "_ico");
        }
        if (icon.substr(0, 1) !== "/") {
            icon = DOKU_BASE + "lib/images/toolbar/" + icon;
        }
        $ico.attr("src", icon);
        $ico.attr("alt", "");
        $ico.attr("width", 16);
        $ico.attr("height", 16);
        $btn.append($ico);
        return $btn[0];
    }
    function createPicker(id, props, edid) {
        var $picker = jQuery(document.createElement("div"));
        $picker.addClass("picker a11y");
        if (props["class"]) {
            $picker.addClass(props["class"]);
        }
        $picker.attr("id", id).css("position", "absolute");
        function $makebutton(title) {
            var $btn = jQuery(document.createElement("button"))
                .addClass("pickerbutton")
                .attr("title", title)
                .attr("aria-controls", edid)
                .bind("click", bind(pickerInsert, title, edid))
                .appendTo($picker);
            return $btn;
        }
        jQuery.each(props.list, function (key, item) {
            if (!props.list.hasOwnProperty(key)) {
                return;
            }
            if (isNaN(key)) {
                if (item.substr(0, 1) !== "/") {
                    item = DOKU_BASE + "lib/images/" + props.icobase + "/" + item;
                }
                jQuery(document.createElement("img")).attr("src", item).attr("alt", "").appendTo($makebutton(key));
            } else if (typeof item == "string") {
                $makebutton(item).text(item);
            } else {
                initToolbar($picker, edid, props.list);
                return false;
            }
        });
        jQuery("body").append($picker);
        return $picker[0];
    }
    function pickerInsert(text, edid) {
        insertAtCarret(edid, text);
        pickerClose();
    }
    function addBtnActionSignature($btn, props, edid) {
        if (typeof SIG != "undefined" && SIG != "") {
            $btn.bind("click", bind(insertAtCarret, edid, SIG));
            return edid;
        }
        return "";
    }
    function currentHeadlineLevel(textboxId) {
        var field = jQuery("#" + textboxId)[0],
            s = false,
            opts = [field.value.substr(0, getSelection(field).start)];
        if (field.form.prefix) {
            opts.push(field.form.prefix.value);
        }
        jQuery.each(opts, function (_, opt) {
            var str = "\n" + opt,
                lasthl = str.lastIndexOf("\n==");
            if (lasthl !== -1) {
                s = str.substr(lasthl + 1, 6);
                return false;
            }
        });
        if (s === false) {
            return 0;
        }
        return 7 - s.match(/^={2,6}/)[0].length;
    }
    window.textChanged = false;
    function deleteDraft() {
        if (is_opera || window.keepDraft) {
            return;
        }
        var $dwform = jQuery("#dw__editform");
        if ($dwform.length === 0) {
            return;
        }
        jQuery.post(DOKU_BASE + "lib/exe/ajax.php", { call: "draftdel", id: $dwform.find("input[name=id]").val() });
    }
    jQuery(function () {
        var $editform = jQuery("#dw__editform");
        if ($editform.length == 0) {
            return;
        }
        var $edit_text = jQuery("#wiki__text");
        if ($edit_text.length > 0) {
            if ($edit_text.attr("readOnly")) {
                return;
            }
            var sel = getSelection($edit_text[0]);
            sel.start = 0;
            sel.end = 0;
            setSelection(sel);
            $edit_text.focus();
        }
        var checkfunc = function () {
            textChanged = true;
            summaryCheck();
        };
        $editform.change(checkfunc);
        $editform.keydown(checkfunc);
        window.onbeforeunload = function () {
            if (window.textChanged) {
                return LANG.notsavedyet;
            }
        };
        window.onunload = deleteDraft;
        jQuery("#edbtn__save").click(function () {
            window.onbeforeunload = "";
            textChanged = false;
        });
        jQuery("#edbtn__preview").click(function () {
            window.onbeforeunload = "";
            textChanged = false;
            window.keepDraft = true;
        });
        var $summary = jQuery("#edit__summary");
        $summary.change(summaryCheck);
        $summary.keyup(summaryCheck);
        if (textChanged) summaryCheck();
    });
    function summaryCheck() {
        var $sum = jQuery("#edit__summary"),
            missing = $sum.val() === "";
        $sum.toggleClass("missing", missing).toggleClass("edit", !missing);
    }
    var dw_editor = {
        init: function () {
            var $editor = jQuery("#wiki__text");
            if ($editor.length === 0) {
                return;
            }
            dw_editor.initSizeCtl("#size__ctl", $editor);
            if ($editor.attr("readOnly")) {
                return;
            }
            if (jQuery.browser.opera) {
                $editor.keypress(dw_editor.keyHandler);
            } else {
                $editor.keydown(dw_editor.keyHandler);
            }
        },
        initSizeCtl: function (ctlarea, editor) {
            var $ctl = jQuery(ctlarea),
                $textarea = jQuery(editor);
            if ($ctl.length === 0 || $textarea.length === 0) {
                return;
            }
            $textarea.css("height", DokuCookie.getValue("sizeCtl") || "300px");
            var wrp = DokuCookie.getValue("wrapCtl");
            if (wrp) {
                dw_editor.setWrap($textarea[0], wrp);
            }
            jQuery.each(
                [
                    [
                        "larger",
                        function () {
                            dw_editor.sizeCtl(editor, 100);
                        },
                    ],
                    [
                        "smaller",
                        function () {
                            dw_editor.sizeCtl(editor, -100);
                        },
                    ],
                    [
                        "wrap",
                        function () {
                            dw_editor.toggleWrap(editor);
                        },
                    ],
                ],
                function (_, img) {
                    jQuery(document.createElement("IMG"))
                        .attr("src", DOKU_BASE + "lib/images/" + img[0] + ".gif")
                        .attr("alt", "")
                        .click(img[1])
                        .appendTo($ctl);
                }
            );
        },
        sizeCtl: function (editor, val) {
            var $textarea = jQuery(editor),
                height = parseInt($textarea.css("height")) + val;
            $textarea.css("height", height + "px");
            DokuCookie.setValue("sizeCtl", $textarea.css("height"));
        },
        toggleWrap: function (editor) {
            var $textarea = jQuery(editor),
                wrap = $textarea.attr("wrap");
            dw_editor.setWrap($textarea[0], wrap && wrap.toLowerCase() == "off" ? "soft" : "off");
            DokuCookie.setValue("wrapCtl", $textarea.attr("wrap"));
        },
        setWrap: function (textarea, wrapAttrValue) {
            textarea.setAttribute("wrap", wrapAttrValue);
            var parNod = textarea.parentNode;
            var nxtSib = textarea.nextSibling;
            parNod.removeChild(textarea);
            parNod.insertBefore(textarea, nxtSib);
        },
        keyHandler: function (e) {
            if (jQuery.inArray(e.keyCode, [8, 13, 32]) === -1) {
                return;
            }
            var selection = getSelection(this);
            if (selection.getLength() > 0) {
                return;
            }
            var search = "\n" + this.value.substr(0, selection.start);
            var linestart = Math.max(search.lastIndexOf("\n"), search.lastIndexOf("\r"));
            search = search.substr(linestart);
            if (e.keyCode == 13) {
                var match = search.match(/(\n  +([\*-] ?)?)/);
                if (match) {
                    var scroll = this.scrollHeight;
                    var match2 = search.match(/^\n  +[\*-]\s*$/);
                    if (match2 && this.value.substr(selection.start).match(/^($|\r?\n)/)) {
                        this.value = this.value.substr(0, linestart) + "\n" + this.value.substr(selection.start);
                        selection.start = linestart + 1;
                        selection.end = linestart + 1;
                        setSelection(selection);
                    } else {
                        insertAtCarret(this.id, match[1]);
                    }
                    this.scrollTop += this.scrollHeight - scroll;
                    e.preventDefault();
                    return false;
                }
            } else if (e.keyCode == 8) {
                var match = search.match(/(\n  +)([*-] ?)$/);
                if (match) {
                    var spaces = match[1].length - 1;
                    if (spaces > 3) {
                        this.value = this.value.substr(0, linestart) + this.value.substr(linestart + 2);
                        selection.start = selection.start - 2;
                        selection.end = selection.start;
                    } else {
                        this.value = this.value.substr(0, linestart) + this.value.substr(selection.start);
                        selection.start = linestart;
                        selection.end = linestart;
                    }
                    setSelection(selection);
                    e.preventDefault();
                    return false;
                }
            } else if (e.keyCode == 32) {
                var match = search.match(/(\n  +)([*-] )$/);
                if (match) {
                    this.value = this.value.substr(0, linestart) + "  " + this.value.substr(linestart);
                    selection.start = selection.start + 2;
                    selection.end = selection.start;
                    setSelection(selection);
                    e.preventDefault();
                    return false;
                }
            }
        },
    };
    jQuery(dw_editor.init);
    var dw_locktimer = {
        timeout: 0,
        draft: false,
        timerID: null,
        lasttime: null,
        msg: LANG.willexpire,
        pageid: "",
        init: function (timeout, msg, draft, edid) {
            var $edit;
            switch (arguments.length) {
                case 4:
                    DEPRECATED("Setting the locktimer expiry message is deprecated");
                    dw_locktimer.msg = msg;
                    break;
                case 3:
                    edid = draft;
                case 2:
                    draft = msg;
            }
            edid = edid || "wiki__text";
            $edit = jQuery("#" + edid);
            if ($edit.length === 0 || $edit.attr("readonly")) {
                return;
            }
            dw_locktimer.timeout = timeout * 1000;
            dw_locktimer.draft = draft;
            dw_locktimer.lasttime = new Date();
            dw_locktimer.pageid = jQuery("#dw__editform input[name=id]").val();
            if (!dw_locktimer.pageid) {
                return;
            }
            $edit.keypress(dw_locktimer.refresh);
            dw_locktimer.reset();
        },
        reset: function () {
            dw_locktimer.clear();
            dw_locktimer.timerID = window.setTimeout(dw_locktimer.warning, dw_locktimer.timeout);
        },
        warning: function () {
            dw_locktimer.clear();
            alert(fixtxt(dw_locktimer.msg));
        },
        clear: function () {
            if (dw_locktimer.timerID !== null) {
                window.clearTimeout(dw_locktimer.timerID);
                dw_locktimer.timerID = null;
            }
        },
        refresh: function () {
            var now = new Date(),
                params = "call=lock&id=" + dw_locktimer.pageid + "&";
            if (now.getTime() - dw_locktimer.lasttime.getTime() <= 30 * 1000) {
                return;
            }
            if (dw_locktimer.draft && jQuery("#dw__editform textarea[name=wikitext]").length > 0) {
                params += jQuery("#dw__editform")
                    .find(
                        "input[name=prefix], " +
                            "textarea[name=wikitext], " +
                            "input[name=suffix], " +
                            "input[name=date]"
                    )
                    .serialize();
            }
            jQuery.post(DOKU_BASE + "lib/exe/ajax.php", params, dw_locktimer.refreshed, "html");
            dw_locktimer.lasttime = now;
        },
        refreshed: function (data) {
            var error = data.charAt(0);
            data = data.substring(1);
            jQuery("#draft__status").html(data);
            if (error != "1") {
                return;
            }
            dw_locktimer.reset();
        },
    };
    var dw_linkwiz = {
        $wiz: null,
        $entry: null,
        result: null,
        timer: null,
        textArea: null,
        selected: null,
        selection: null,
        init: function ($editor) {
            var pos = $editor.position();
            if (dw_linkwiz.$wiz) return;
            dw_linkwiz.$wiz = jQuery(document.createElement("div"))
                .dialog({ autoOpen: false, draggable: true, title: LANG.linkwiz, resizable: false })
                .html(
                    "<div>" +
                        LANG.linkto +
                        ' <input type="text" class="edit" id="link__wiz_entry" autocomplete="off" /></div>' +
                        '<div id="link__wiz_result"></div>'
                )
                .parent()
                .attr("id", "link__wiz")
                .css({ position: "absolute", top: pos.top + 20 + "px", left: pos.left + 80 + "px" })
                .hide()
                .appendTo(".dokuwiki:first");
            dw_linkwiz.textArea = $editor[0];
            dw_linkwiz.result = jQuery("#link__wiz_result")[0];
            jQuery(dw_linkwiz.result).css("position", "relative");
            dw_linkwiz.$entry = jQuery("#link__wiz_entry");
            if (JSINFO.namespace) {
                dw_linkwiz.$entry.val(JSINFO.namespace + ":");
            }
            jQuery("#link__wiz .ui-dialog-titlebar-close").click(dw_linkwiz.hide);
            dw_linkwiz.$entry.keyup(dw_linkwiz.onEntry);
            jQuery(dw_linkwiz.result).delegate("a", "click", dw_linkwiz.onResultClick);
        },
        onEntry: function (e) {
            if (e.keyCode == 37 || e.keyCode == 39) {
                return true;
            }
            if (e.keyCode == 27) {
                dw_linkwiz.hide();
                e.preventDefault();
                e.stopPropagation();
                return false;
            }
            if (e.keyCode == 38) {
                dw_linkwiz.select(dw_linkwiz.selected - 1);
                e.preventDefault();
                e.stopPropagation();
                return false;
            }
            if (e.keyCode == 40) {
                dw_linkwiz.select(dw_linkwiz.selected + 1);
                e.preventDefault();
                e.stopPropagation();
                return false;
            }
            if (e.keyCode == 13) {
                if (dw_linkwiz.selected > -1) {
                    var $obj = dw_linkwiz.$getResult(dw_linkwiz.selected);
                    if ($obj.length > 0) {
                        dw_linkwiz.resultClick($obj.find("a")[0]);
                    }
                } else if (dw_linkwiz.$entry.val()) {
                    dw_linkwiz.insertLink(dw_linkwiz.$entry.val());
                }
                e.preventDefault();
                e.stopPropagation();
                return false;
            }
            dw_linkwiz.autocomplete();
        },
        getResult: function (num) {
            DEPRECATED("use dw_linkwiz.$getResult()[0] instead");
            return dw_linkwiz.$getResult()[0] || null;
        },
        $getResult: function (num) {
            return jQuery(dw_linkwiz.result).find("div").eq(num);
        },
        select: function (num) {
            if (num < 0) {
                dw_linkwiz.deselect();
                return;
            }
            var $obj = dw_linkwiz.$getResult(num);
            if ($obj.length === 0) {
                return;
            }
            dw_linkwiz.deselect();
            $obj.addClass("selected");
            var childPos = $obj.position().top;
            var yDiff = childPos + $obj.outerHeight() - jQuery(dw_linkwiz.result).innerHeight();
            if (childPos < 0) {
                jQuery(dw_linkwiz.result)[0].scrollTop += childPos;
            } else if (yDiff > 0) {
                jQuery(dw_linkwiz.result)[0].scrollTop += yDiff;
            }
            dw_linkwiz.selected = num;
        },
        deselect: function () {
            if (dw_linkwiz.selected > -1) {
                dw_linkwiz.$getResult(dw_linkwiz.selected).removeClass("selected");
            }
            dw_linkwiz.selected = -1;
        },
        onResultClick: function (e) {
            if (!jQuery(this).is("a")) {
                return;
            }
            e.stopPropagation();
            e.preventDefault();
            dw_linkwiz.resultClick(this);
            return false;
        },
        resultClick: function (a) {
            dw_linkwiz.$entry.val(a.title);
            if (a.title == "" || a.title.substr(a.title.length - 1) == ":") {
                dw_linkwiz.autocomplete_exec();
            } else {
                if (jQuery(a.nextSibling).is("span")) {
                    dw_linkwiz.insertLink(a.nextSibling.innerHTML);
                } else {
                    dw_linkwiz.insertLink("");
                }
            }
        },
        insertLink: function (title) {
            var link = dw_linkwiz.$entry.val(),
                sel,
                stxt;
            if (!link) {
                return;
            }
            sel = getSelection(dw_linkwiz.textArea);
            if (sel.start == 0 && sel.end == 0) {
                sel = dw_linkwiz.selection;
            }
            stxt = sel.getText();
            if (stxt.charAt(stxt.length - 1) == " ") {
                sel.end--;
                stxt = sel.getText();
            }
            if (!stxt && !DOKU_UHC) {
                stxt = title;
            }
            if (dw_linkwiz.textArea.form.id.value.indexOf(":") != -1 && link.indexOf(":") == -1) {
                link = ":" + link;
            }
            var so = link.length;
            var eo = 0;
            if (dw_linkwiz.val) {
                if (dw_linkwiz.val.open) {
                    so += dw_linkwiz.val.open.length;
                    link = dw_linkwiz.val.open + link;
                }
                if (stxt) {
                    link += "|" + stxt;
                    so += 1;
                }
                if (dw_linkwiz.val.close) {
                    link += dw_linkwiz.val.close;
                    eo = dw_linkwiz.val.close.length;
                }
            }
            pasteText(sel, link, { startofs: so, endofs: eo });
            dw_linkwiz.hide();
            dw_linkwiz.$entry.val(dw_linkwiz.$entry.val().replace(/[^:]*$/, ""));
        },
        autocomplete: function () {
            if (dw_linkwiz.timer !== null) {
                window.clearTimeout(dw_linkwiz.timer);
                dw_linkwiz.timer = null;
            }
            dw_linkwiz.timer = window.setTimeout(dw_linkwiz.autocomplete_exec, 350);
        },
        autocomplete_exec: function () {
            var $res = jQuery(dw_linkwiz.result);
            dw_linkwiz.deselect();
            $res.html('<img src="' + DOKU_BASE + 'lib/images/throbber.gif" alt="" width="16" height="16" />').load(
                DOKU_BASE + "lib/exe/ajax.php",
                { call: "linkwiz", q: dw_linkwiz.$entry.val() }
            );
        },
        show: function () {
            dw_linkwiz.selection = getSelection(dw_linkwiz.textArea);
            dw_linkwiz.$wiz.show();
            dw_linkwiz.$entry.focus();
            dw_linkwiz.autocomplete();
        },
        hide: function () {
            dw_linkwiz.$wiz.hide();
            dw_linkwiz.textArea.focus();
        },
        toggle: function () {
            if (dw_linkwiz.$wiz.css("display") == "none") {
                dw_linkwiz.show();
            } else {
                dw_linkwiz.hide();
            }
        },
    };
    var dw_mediamanager = {
        keepopen: false,
        hide: false,
        popup: false,
        display: false,
        ext: false,
        $popup: null,
        align: false,
        link: false,
        size: false,
        forbidden_opts: {},
        view_opts: { list: false, sort: false },
        layout_width: 0,
        minHeights: { thumbs: 200, rows: 100 },
        init: function () {
            var $content, $tree;
            $content = jQuery("#media__content");
            $tree = jQuery("#media__tree");
            if (!$tree.length) return;
            dw_mediamanager.prepare_content($content);
            dw_mediamanager.attachoptions();
            dw_mediamanager.initpopup();
            $content
                .delegate("#upload__file", "change", dw_mediamanager.suggest)
                .delegate("a.select", "click", dw_mediamanager.select)
                .delegate("#media__content a.btn_media_delete", "click", dw_mediamanager.confirmattach)
                .delegate("#mediamanager__done_form", "submit", dw_mediamanager.list);
            $tree.dw_tree({
                toggle_selector: "img",
                load_data: function (show_sublist, $clicky) {
                    var $link = $clicky.parent().find("div.li a.idx_dir");
                    jQuery.post(
                        DOKU_BASE + "lib/exe/ajax.php",
                        $link[0].search.substr(1) + "&call=medians",
                        show_sublist,
                        "html"
                    );
                },
                toggle_display: function ($clicky, opening) {
                    $clicky.attr("src", DOKU_BASE + "lib/images/" + (opening ? "minus" : "plus") + ".gif");
                },
            });
            $tree.delegate("a", "click", dw_mediamanager.list);
            dw_mediamanager.set_fileview_list();
            dw_mediamanager.init_options();
            dw_mediamanager.image_diff();
            dw_mediamanager.init_ajax_uploader();
            jQuery("#mediamanager__page div.filelist")
                .delegate("ul.tabs a", "click", dw_mediamanager.list)
                .delegate("div.panelContent a", "click", dw_mediamanager.details)
                .delegate("#dw__mediasearch", "submit", dw_mediamanager.list)
                .delegate("#upload__file", "change", dw_mediamanager.suggest)
                .delegate(".qq-upload-file a", "click", dw_mediamanager.details);
            jQuery("#mediamanager__page div.file")
                .delegate("ul.tabs a", "click", dw_mediamanager.details)
                .delegate("#mediamanager__btn_update", "submit", dw_mediamanager.list)
                .delegate("#page__revisions", "submit", dw_mediamanager.details)
                .delegate("#page__revisions a", "click", dw_mediamanager.details)
                .delegate("#mediamanager__save_meta", "submit", dw_mediamanager.details)
                .delegate("#mediamanager__btn_delete", "submit", dw_mediamanager.details)
                .delegate("#mediamanager__btn_restore", "submit", dw_mediamanager.details)
                .delegate(".btn_newer, .btn_older", "submit", dw_mediamanager.details);
            dw_mediamanager.update_resizable();
            dw_mediamanager.layout_width = jQuery("#mediamanager__page").width();
            jQuery(window).resize(dw_mediamanager.window_resize);
        },
        init_options: function () {
            var $options = jQuery("div.filelist div.panelHeader form.options"),
                $listType,
                $sortBy,
                $both;
            if ($options.length === 0) {
                return;
            }
            $listType = $options.find("li.listType");
            $sortBy = $options.find("li.sortBy");
            $both = $listType.add($sortBy);
            $options.find("input[type=submit]").parent().hide();
            $both.find("label").each(function () {
                var $this = jQuery(this);
                $this.children("input").appendTo($this.parent());
            });
            $both.buttonset();
            $listType.children("input").change(function (event) {
                dw_mediamanager.set_fileview_list();
            });
            $sortBy.children("input").change(function (event) {
                dw_mediamanager.set_fileview_sort();
                dw_mediamanager.list.call(jQuery("#dw__mediasearch")[0] || this, event);
            });
        },
        initpopup: function () {
            var opts, $insp, $insbtn;
            dw_mediamanager.$popup = jQuery(document.createElement("div"))
                .attr("id", "media__popup_content")
                .dialog({
                    autoOpen: false,
                    width: 280,
                    modal: true,
                    draggable: true,
                    title: LANG.mediatitle,
                    resizable: false,
                });
            opts = [
                { id: "link", label: LANG.mediatarget, btns: ["lnk", "direct", "nolnk", "displaylnk"] },
                { id: "align", label: LANG.mediaalign, btns: ["noalign", "left", "center", "right"] },
                { id: "size", label: LANG.mediasize, btns: ["small", "medium", "large", "original"] },
            ];
            jQuery.each(opts, function (_, opt) {
                var $p, $l;
                $p = jQuery(document.createElement("p")).attr("id", "media__" + opt.id);
                if (dw_mediamanager.display === "2") {
                    $p.hide();
                }
                $l = jQuery(document.createElement("label")).text(opt.label);
                $p.append($l);
                jQuery.each(opt.btns, function (i, text) {
                    var $btn, $img;
                    $btn = jQuery(document.createElement("button"))
                        .addClass("button")
                        .attr("id", "media__" + opt.id + "btn" + (i + 1))
                        .attr("title", LANG["media" + text])
                        .click(bind(dw_mediamanager.setOpt, opt.id));
                    $img = jQuery(document.createElement("img")).attr(
                        "src",
                        DOKU_BASE + "lib/images/media_" + opt.id + "_" + text + ".png"
                    );
                    $btn.append($img);
                    $p.append($btn);
                });
                dw_mediamanager.$popup.append($p);
            });
            $insp = jQuery(document.createElement("p"));
            dw_mediamanager.$popup.append($insp);
            $insbtn = jQuery(document.createElement("input"))
                .attr("id", "media__sendbtn")
                .attr("type", "button")
                .addClass("button")
                .val(LANG.mediainsert);
            $insp.append($insbtn);
        },
        insert: function (id) {
            var opts, alignleft, alignright, edid, s;
            dw_mediamanager.$popup.dialog("close");
            opts = "";
            alignleft = "";
            alignright = "";
            if ({ img: 1, swf: 1 }[dw_mediamanager.ext] === 1) {
                if (dw_mediamanager.link === "4") {
                    opts = "?linkonly";
                } else {
                    if (dw_mediamanager.link === "3" && dw_mediamanager.ext === "img") {
                        opts = "?nolink";
                    } else if (dw_mediamanager.link === "2" && dw_mediamanager.ext === "img") {
                        opts = "?direct";
                    }
                    s = parseInt(dw_mediamanager.size, 10);
                    if (s && s >= 1 && s < 4) {
                        opts += opts.length ? "&" : "?";
                        opts += dw_mediamanager.size + "00";
                        if (dw_mediamanager.ext === "swf") {
                            switch (s) {
                                case 1:
                                    opts += "x62";
                                    break;
                                case 2:
                                    opts += "x123";
                                    break;
                                case 3:
                                    opts += "x185";
                                    break;
                            }
                        }
                    }
                    if (dw_mediamanager.align !== "1") {
                        alignleft = dw_mediamanager.align === "2" ? "" : " ";
                        alignright = dw_mediamanager.align === "4" ? "" : " ";
                    }
                }
            }
            edid = String.prototype.match.call(document.location, /&edid=([^&]+)/);
            opener.insertTags(edid ? edid[1] : "wiki__text", "{{" + alignleft + id + opts + alignright + "|", "}}", "");
            if (!dw_mediamanager.keepopen) {
                window.close();
            }
            opener.focus();
            return false;
        },
        suggest: function () {
            var $file, $name, text;
            $file = jQuery(this);
            $name = jQuery("#upload__name");
            if ($name.val() != "") return;
            if (!$file.length || !$name.length) {
                return;
            }
            text = $file.val();
            text = text.substr(text.lastIndexOf("/") + 1);
            text = text.substr(text.lastIndexOf("\\") + 1);
            $name.val(text);
        },
        list: function (event) {
            var $link, $content, params;
            if (event) {
                event.preventDefault();
            }
            jQuery("div.success, div.info, div.error, div.notify").remove();
            $link = jQuery(this);
            $content = jQuery("#media__content");
            if ($content.length === 0) {
                $content = jQuery("div.filelist");
                if ($link.hasClass("idx_dir")) {
                    jQuery("div.file").empty();
                    jQuery("div.namespaces .selected").removeClass("selected");
                    $link.addClass("selected");
                }
            }
            params = "call=medialist&";
            if ($link[0].search) {
                params += $link[0].search.substr(1);
            } else if ($link.is("form")) {
                params += dw_mediamanager.form_params($link);
            } else if ($link.closest("form").length > 0) {
                params += dw_mediamanager.form_params($link.closest("form"));
            }
            dw_mediamanager.update_content($content, params);
        },
        form_params: function ($form) {
            if (!$form.length) return;
            var action = "";
            var i = $form[0].action.indexOf("?");
            if (i >= 0) action = $form[0].action.substr(i + 1);
            return action + "&" + $form.serialize();
        },
        set_fileview_list: function (new_type) {
            dw_mediamanager.set_fileview_opt(
                [
                    "list",
                    "listType",
                    function (new_type) {
                        jQuery("div.filelist div.panelContent ul")
                            .toggleClass("rows", new_type === "rows")
                            .toggleClass("thumbs", new_type === "thumbs");
                    },
                ],
                new_type
            );
            dw_mediamanager.resize();
        },
        set_fileview_sort: function (new_sort) {
            dw_mediamanager.set_fileview_opt(["sort", "sortBy", function (new_sort) {}], new_sort);
        },
        set_fileview_opt: function (opt, new_val) {
            if (typeof new_val === "undefined") {
                new_val = jQuery("form.options li." + opt[1] + " input")
                    .filter(":checked")
                    .val();
                if (typeof new_val === "undefined") {
                    new_val = "thumbs";
                }
            }
            if (new_val !== dw_mediamanager.view_opts[opt[0]]) {
                opt[2](new_val);
                DokuCookie.setValue(opt[0], new_val);
                dw_mediamanager.view_opts[opt[0]] = new_val;
            }
        },
        details: function (event) {
            var $link, $content, params, update_list;
            $link = jQuery(this);
            event.preventDefault();
            jQuery("div.success, div.info, div.error, div.notify").remove();
            if ($link[0].id == "mediamanager__btn_delete" && !confirm(LANG.del_confirm)) {
                return false;
            }
            if ($link[0].id == "mediamanager__btn_restore" && !confirm(LANG.restore_confirm)) {
                return false;
            }
            $content = jQuery("div.file");
            params = "call=mediadetails&";
            if ($link[0].search) {
                params += $link[0].search.substr(1);
            } else if ($link.is("form")) {
                params += dw_mediamanager.form_params($link);
            } else if ($link.closest("form").length > 0) {
                params += dw_mediamanager.form_params($link.closest("form"));
            }
            update_list = $link[0].id == "mediamanager__btn_delete" || $link[0].id == "mediamanager__btn_restore";
            dw_mediamanager.update_content($content, params, update_list);
        },
        update_content: function ($content, params, update_list) {
            var $container;
            jQuery.post(
                DOKU_BASE + "lib/exe/ajax.php",
                params,
                function (data) {
                    dw_mediamanager.$resizables().resizable("destroy");
                    if (update_list) {
                        dw_mediamanager.list.call(jQuery('#mediamanager__page form.options input[type="submit"]')[0]);
                    }
                    $content.html(data);
                    dw_mediamanager.prepare_content($content);
                    dw_mediamanager.updatehide();
                    dw_mediamanager.update_resizable();
                    dw_behaviour.revisionBoxHandler();
                    dw_mediamanager.set_fileview_list(dw_mediamanager.view_opts.list);
                    dw_mediamanager.image_diff();
                    dw_mediamanager.init_ajax_uploader();
                    dw_mediamanager.init_options();
                },
                "html"
            );
            $container = $content.find("div.panelContent");
            if ($container.length === 0) {
                $container = $content;
            }
            $container.html('<img src="' + DOKU_BASE + 'lib/images/loading.gif" alt="..." class="load" />');
        },
        window_resize: function () {
            dw_mediamanager.resize();
            dw_mediamanager.opacity_slider();
            dw_mediamanager.portions_slider();
        },
        $resizables: function () {
            return jQuery("#mediamanager__page").find("div.namespaces, div.filelist");
        },
        update_resizable: function () {
            $resizables = dw_mediamanager.$resizables();
            $resizables.resizable({
                handles: "e",
                resize: function (event, ui) {
                    var widthFull = jQuery("#mediamanager__page").width();
                    var widthResizables = 0;
                    $resizables.each(function () {
                        widthResizables += jQuery(this).width();
                    });
                    var $filePanel = jQuery("#mediamanager__page div.panel.file");
                    var widthOtherResizable = widthResizables - jQuery(this).width();
                    var minWidthNonResizable = parseFloat($filePanel.css("min-width"));
                    var maxWidth = widthFull - (widthOtherResizable + minWidthNonResizable) - 1;
                    $resizables.resizable("option", "maxWidth", maxWidth);
                    var relWidthNonResizable = 99.9 - (100 * widthResizables) / widthFull;
                    $filePanel.width(relWidthNonResizable + "%");
                    if (!jQuery.browser.webkit) {
                        $resizables.each(function () {
                            w = jQuery(this).width();
                            w = (99.99 * w) / widthFull;
                            w += "%";
                            jQuery(this).width(w);
                        });
                    }
                    dw_mediamanager.resize();
                    dw_mediamanager.opacity_slider();
                    dw_mediamanager.portions_slider();
                },
            });
            dw_mediamanager.resize();
        },
        resize: function () {
            var $contents = jQuery("#mediamanager__page div.panelContent"),
                height =
                    jQuery(window).height() -
                    jQuery(document.body).height() +
                    Math.max.apply(
                        null,
                        jQuery.map($contents, function (v) {
                            return jQuery(v).height();
                        })
                    );
            if (height < dw_mediamanager.minHeights[dw_mediamanager.view_opts.list]) {
                $contents.add(dw_mediamanager.$resizables()).height("auto");
            } else {
                $contents.height(height);
                dw_mediamanager.$resizables().each(function () {
                    var $this = jQuery(this);
                    $this.height(height + $this.find("div.panelContent").offset().top - $this.offset().top);
                });
            }
        },
        image_diff: function () {
            if (jQuery("#mediamanager__difftype").length) return;
            $form = jQuery("#mediamanager__form_diffview");
            if (!$form.length) return;
            $label = jQuery(document.createElement("label"));
            $label.append("<span>" + LANG.media_diff + "</span> ");
            $select = jQuery(document.createElement("select"))
                .attr("id", "mediamanager__difftype")
                .attr("name", "difftype")
                .change(dw_mediamanager.change_diff_type);
            $select.append(new Option(LANG.media_diff_both, "both"));
            $select.append(new Option(LANG.media_diff_opacity, "opacity"));
            $select.append(new Option(LANG.media_diff_portions, "portions"));
            $label.append($select);
            $form.append($label);
            var select = document.getElementById("mediamanager__difftype");
            select.options[0].text = LANG.media_diff_both;
            select.options[1].text = LANG.media_diff_opacity;
            select.options[2].text = LANG.media_diff_portions;
        },
        change_diff_type: function () {
            $select = jQuery("#mediamanager__difftype");
            $content = jQuery("#mediamanager__diff");
            params = dw_mediamanager.form_params($select.closest("form")) + "&call=mediadiff";
            jQuery.post(
                DOKU_BASE + "lib/exe/ajax.php",
                params,
                function (data) {
                    $content.html(data);
                    dw_mediamanager.portions_slider();
                    dw_mediamanager.opacity_slider();
                },
                "html"
            );
        },
        opacity_slider: function () {
            var $slider = jQuery("#mediamanager__diff div.slider");
            if (!$slider.length) return;
            var $image = jQuery("#mediamanager__diff div.imageDiff.opacity div.image1 img");
            if (!$image.length) return;
            $slider.width($image.width() - 20);
            $slider.slider();
            $slider.slider("option", "min", 0);
            $slider.slider("option", "max", 0.999);
            $slider.slider("option", "step", 0.001);
            $slider.slider("option", "value", 0.5);
            $slider.bind("slide", function (event, ui) {
                jQuery("#mediamanager__diff div.imageDiff.opacity div.image2 img").css({
                    opacity: $slider.slider("option", "value"),
                });
            });
        },
        portions_slider: function () {
            var $image1 = jQuery("#mediamanager__diff div.imageDiff.portions div.image1 img");
            var $image2 = jQuery("#mediamanager__diff div.imageDiff.portions div.image2 img");
            if (!$image1.length || !$image2.length) return;
            var $div = jQuery("#mediamanager__diff");
            if (!$div.length) return;
            $div.width("100%");
            $image2.parent().width("97%");
            $image1.width("100%");
            $image2.width("100%");
            if ($image1.width() < $div.width()) {
                $div.width($image1.width());
            }
            $image2.parent().width("50%");
            $image2.width($image1.width());
            $image1.width($image1.width());
            var $slider = jQuery("#mediamanager__diff div.slider");
            if (!$slider.length) return;
            $slider.width($image1.width() - 20);
            $slider.slider();
            $slider.slider("option", "min", 0);
            $slider.slider("option", "max", 97);
            $slider.slider("option", "step", 1);
            $slider.slider("option", "value", 50);
            $slider.bind("slide", function (event, ui) {
                jQuery("#mediamanager__diff div.imageDiff.portions div.image2").css({
                    width: $slider.slider("option", "value") + "%",
                });
            });
        },
        params_toarray: function (str) {
            var vars = [],
                hash;
            var hashes = str.split("&");
            for (var i = 0; i < hashes.length; i++) {
                hash = hashes[i].split("=");
                vars[decodeURIComponent(hash[0])] = decodeURIComponent(hash[1]);
            }
            return vars;
        },
        init_ajax_uploader: function () {
            if (!jQuery("#mediamanager__uploader").length) return;
            if (jQuery(".qq-upload-list").length) return;
            var params = dw_mediamanager.form_params(jQuery("#dw__upload")) + "&call=mediaupload";
            params = dw_mediamanager.params_toarray(params);
            var uploader = new qq.FileUploaderExtended({
                element: document.getElementById("mediamanager__uploader"),
                action: DOKU_BASE + "lib/exe/ajax.php",
                params: params,
            });
        },
        prepare_content: function ($content) {
            $content.find("div.example:visible").hide();
        },
        select: function (event) {
            var $link, id, dot, ext;
            event.preventDefault();
            $link = jQuery(this);
            id = $link.attr("id").substr(2);
            if (!opener) {
                jQuery(document.getElementById("ex_" + id.replace(/:/g, "_").replace(/^_/, ""))).dw_toggle();
                return;
            }
            dw_mediamanager.ext = false;
            dot = id.lastIndexOf(".");
            if (-1 === dot) {
                dw_mediamanager.insert(id);
                return;
            }
            ext = id.substr(dot);
            if ({ ".jpg": 1, ".jpeg": 1, ".png": 1, ".gif": 1, ".swf": 1 }[ext] !== 1) {
                dw_mediamanager.insert(id);
                return;
            }
            jQuery("#media__sendbtn").unbind().click(bind(dw_mediamanager.insert, id));
            dw_mediamanager.unforbid("ext");
            if (ext === ".swf") {
                dw_mediamanager.ext = "swf";
                dw_mediamanager.forbid("ext", { link: ["1", "2"], size: ["4"] });
            } else {
                dw_mediamanager.ext = "img";
            }
            dw_mediamanager.setOpt("link");
            dw_mediamanager.setOpt("align");
            dw_mediamanager.setOpt("size");
            jQuery("#media__linkbtn1, #media__linkbtn2, #media__sizebtn4").toggle(dw_mediamanager.ext === "img");
            dw_mediamanager.$popup.dialog("open");
            jQuery("#media__sendbtn").focus();
        },
        confirmattach: function (e) {
            if (!confirm(LANG.del_confirm + "\n" + jQuery(this).attr("title"))) {
                e.preventDefault();
            }
        },
        attachoptions: function () {
            var $obj, opts;
            $obj = jQuery("#media__opts");
            if ($obj.length === 0) {
                return;
            }
            opts = [];
            if (opener) {
                opts.push(["keepopen", "keepopen"]);
            }
            opts.push(["hide", "hidedetails"]);
            jQuery.each(opts, function (_, opt) {
                var $box, $lbl;
                $box = jQuery(document.createElement("input"))
                    .attr("type", "checkbox")
                    .attr("id", "media__" + opt[0])
                    .click(bind(dw_mediamanager.toggleOption, opt[0]));
                if (DokuCookie.getValue(opt[0])) {
                    $box.prop("checked", true);
                    dw_mediamanager[opt[0]] = true;
                }
                $lbl = jQuery(document.createElement("label"))
                    .attr("for", "media__" + opt[0])
                    .text(LANG[opt[1]]);
                $obj.append($box, $lbl, document.createElement("br"));
            });
            dw_mediamanager.updatehide();
        },
        toggleOption: function (variable) {
            if (jQuery(this).prop("checked")) {
                DokuCookie.setValue(variable, 1);
                dw_mediamanager[variable] = true;
            } else {
                DokuCookie.setValue(variable, "");
                dw_mediamanager[variable] = false;
            }
            if (variable === "hide") {
                dw_mediamanager.updatehide();
            }
        },
        updatehide: function () {
            jQuery("#media__content div.detail").dw_toggle(!dw_mediamanager.hide);
        },
        setOpt: function (opt, e) {
            var val, i;
            if (typeof e !== "undefined") {
                val = this.id.substring(this.id.length - 1);
            } else {
                val = dw_mediamanager.getOpt(opt);
            }
            if (val === false) {
                DokuCookie.setValue(opt, "");
                dw_mediamanager[opt] = false;
                return;
            }
            if (opt === "link") {
                if (val !== "4" && dw_mediamanager.link === "4") {
                    dw_mediamanager.unforbid("linkonly");
                    dw_mediamanager.setOpt("align");
                    dw_mediamanager.setOpt("size");
                } else if (val === "4") {
                    dw_mediamanager.forbid("linkonly", { align: false, size: false });
                }
                jQuery("#media__size, #media__align").dw_toggle(val !== "4");
            }
            DokuCookie.setValue(opt, val);
            dw_mediamanager[opt] = val;
            for (i = 1; i <= 4; i++) {
                jQuery("#media__" + opt + "btn" + i).removeClass("selected");
            }
            jQuery("#media__" + opt + "btn" + val).addClass("selected");
        },
        unforbid: function (group) {
            delete dw_mediamanager.forbidden_opts[group];
        },
        forbid: function (group, forbids) {
            dw_mediamanager.forbidden_opts[group] = forbids;
        },
        allowedOpt: function (opt, val) {
            var ret = true;
            jQuery.each(dw_mediamanager.forbidden_opts, function (_, forbids) {
                ret = forbids[opt] !== false && jQuery.inArray(val, forbids[opt]) === -1;
                return ret;
            });
            return ret;
        },
        getOpt: function (opt) {
            var allowed = bind(dw_mediamanager.allowedOpt, opt);
            if (dw_mediamanager[opt] !== false && allowed(dw_mediamanager[opt])) {
                return dw_mediamanager[opt];
            }
            if (DokuCookie.getValue(opt) && allowed(DokuCookie.getValue(opt))) {
                return DokuCookie.getValue(opt);
            }
            if (opt === "size" && allowed("2")) {
                return "2";
            }
            return jQuery.grep(["1", "2", "3", "4"], allowed)[0] || false;
        },
    };
    jQuery(dw_mediamanager.init);
    jQuery.fn.dw_hide = function (fn) {
        this.attr("aria-expanded", "false");
        return this.slideUp("fast", fn);
    };
    jQuery.fn.dw_show = function (fn) {
        this.attr("aria-expanded", "true");
        return this.slideDown("fast", fn);
    };
    jQuery.fn.dw_toggle = function (bool, fn) {
        return this.each(function () {
            var $this = jQuery(this);
            if (typeof bool === "undefined") {
                bool = $this.is(":hidden");
            }
            $this[bool ? "dw_show" : "dw_hide"](fn);
        });
    };
    var dw_behaviour = {
        init: function () {
            dw_behaviour.focusMarker();
            dw_behaviour.scrollToMarker();
            dw_behaviour.removeHighlightOnClick();
            dw_behaviour.quickSelect();
            dw_behaviour.checkWindowsShares();
            dw_behaviour.subscription();
            dw_behaviour.revisionBoxHandler();
            jQuery(document).on("click", "#page__revisions input[type=checkbox]", dw_behaviour.revisionBoxHandler);
        },
        scrollToMarker: function () {
            var $obj = jQuery("#scroll__here");
            if ($obj.length) {
                $obj[0].scrollIntoView();
            }
        },
        focusMarker: function () {
            jQuery("#focus__this").focus();
        },
        removeHighlightOnClick: function () {
            jQuery("span.search_hit").click(function (e) {
                jQuery(e.target).removeClass("search_hit");
            });
        },
        quickSelect: function () {
            jQuery("select.quickselect")
                .change(function (e) {
                    e.target.form.submit();
                })
                .closest("form")
                .find("input[type=submit]")
                .not(".show")
                .hide();
        },
        checkWindowsShares: function () {
            if (!LANG.nosmblinks || typeof document.all !== "undefined") {
                return;
            }
            jQuery("a.windows").on("click", function () {
                alert(LANG.nosmblinks.replace(/\\n/, "\n"));
            });
        },
        subscription: function () {
            var $form, $list, $digest;
            $form = jQuery("#subscribe__form");
            if (0 === $form.length) return;
            $list = $form.find("input[name='sub_style'][value='list']");
            $digest = $form.find("input[name='sub_style'][value='digest']");
            $form
                .find("input[name='sub_target']")
                .click(function () {
                    var $this = jQuery(this),
                        show_list;
                    if (!$this.prop("checked")) {
                        return;
                    }
                    show_list = $this.val().match(/:$/);
                    $list.parent().dw_toggle(show_list);
                    if (!show_list && $list.prop("checked")) {
                        $digest.prop("checked", "checked");
                    }
                })
                .filter(":checked")
                .click();
        },
        revisionBoxHandler: function () {
            var $checked = jQuery("#page__revisions input[type=checkbox]:checked");
            var $all = jQuery("#page__revisions input[type=checkbox]");
            if ($checked.length < 2) {
                $all.attr("disabled", false);
                jQuery("#page__revisions input[type=submit]").attr("disabled", true);
            } else {
                $all.attr("disabled", true);
                jQuery("#page__revisions input[type=submit]").attr("disabled", false);
                for (var i = 0; i < $checked.length; i++) {
                    $checked[i].disabled = false;
                    if (i > 1) {
                        $checked[i].checked = false;
                    }
                }
            }
        },
    };
    jQuery(dw_behaviour.init);
    dw_page = {
        init: function () {
            dw_page.sectionHighlight();
            jQuery("a.fn_top").mouseover(dw_page.footnoteDisplay);
            dw_page.makeToggle("#dw__toc h3", "#dw__toc > div");
        },
        sectionHighlight: function () {
            jQuery("form.btn_secedit")
                .mouseover(function () {
                    var $tgt = jQuery(this).parent(),
                        nr = $tgt.attr("class").match(/(\s+|^)editbutton_(\d+)(\s+|$)/)[2],
                        $highlight = jQuery(),
                        $highlightWrap = jQuery('<div class="section_highlight"></div>');
                    while (
                        $tgt.length > 0 &&
                        !($tgt.hasClass("sectionedit" + nr) || $tgt.find(".sectionedit" + nr).length)
                    ) {
                        $tgt = $tgt.prev();
                        $highlight = $highlight.add($tgt);
                    }
                    $highlight.filter(":last").before($highlightWrap);
                    $highlight.detach().appendTo($highlightWrap);
                })
                .mouseout(function () {
                    var $highlightWrap = jQuery(".section_highlight");
                    $highlightWrap.before($highlightWrap.children().detach());
                    $highlightWrap.detach();
                });
        },
        insituPopup: function (target, popup_id) {
            var $fndiv = jQuery("#" + popup_id);
            if ($fndiv.length === 0) {
                $fndiv = jQuery(document.createElement("div"))
                    .attr("id", popup_id)
                    .addClass("insitu-footnote JSpopup")
                    .attr("aria-hidden", "true")
                    .mouseleave(function () {
                        jQuery(this).hide().attr("aria-hidden", "true");
                    })
                    .attr("role", "tooltip");
                jQuery(".dokuwiki:first").append($fndiv);
            }
            $fndiv.show().position({ my: "left top", at: "left center", of: target }).hide();
            return $fndiv;
        },
        footnoteDisplay: function () {
            var content = jQuery(jQuery(this).attr("href")).closest("div.fn").html();
            if (content === null) {
                return;
            }
            content = content.replace(/((^|\s*,\s*)<sup>.*?<\/sup>)+\s*/gi, "");
            content = content.replace(/\bid=(['"])([^"']+)\1/gi, 'id="insitu__$2');
            dw_page.insituPopup(this, "insitu__fn").html(content).show().attr("aria-hidden", "false");
        },
        makeToggle: function (handle, content, state) {
            var $handle, $content, $clicky, $child, setClicky;
            $handle = jQuery(handle);
            if (!$handle.length) return;
            $content = jQuery(content);
            if (!$content.length) return;
            $child = $content.children();
            setClicky = function (hiding) {
                if (hiding) {
                    $clicky.html("<span>+</span>");
                    $handle.addClass("closed");
                    $handle.removeClass("open");
                } else {
                    $clicky.html("<span>−</span>");
                    $handle.addClass("open");
                    $handle.removeClass("closed");
                }
            };
            $handle[0].setState = function (state) {
                var hidden;
                if (!state) state = 1;
                $content.css("min-height", $content.height()).show();
                $child.stop(true, true);
                if (state === -1) {
                    hidden = false;
                } else if (state === 1) {
                    hidden = true;
                } else {
                    hidden = $child.is(":hidden");
                }
                setClicky(!hidden);
                $child.dw_toggle(hidden, function () {
                    $content.toggle(hidden);
                    $content.css("min-height", "");
                });
            };
            $clicky = jQuery(document.createElement("strong"));
            $handle.css("cursor", "pointer").click($handle[0].setState).prepend($clicky);
            $handle[0].setState(state);
        },
    };
    jQuery(dw_page.init);
    var device_class = "";
    var device_classes = "desktop mobile tablet phone";
    function tpl_dokuwiki_mobile() {
        var screen_mode = jQuery("#screen__mode").css("z-index") + "";
        switch (screen_mode) {
            case "1":
                if (device_class.match(/tablet/)) return;
                device_class = "mobile tablet";
                break;
            case "2":
                if (device_class.match(/phone/)) return;
                device_class = "mobile phone";
                break;
            default:
                if (device_class == "desktop") return;
                device_class = "desktop";
        }
        jQuery("html").removeClass(device_classes).addClass(device_class);
        var $handle = jQuery("#dokuwiki__aside h3.toggle");
        var $toc = jQuery("#dw__toc h3");
        if (device_class == "desktop") {
            if ($handle.length) {
                $handle[0].setState(1);
                $handle.hide();
            }
            if ($toc.length) {
                $toc[0].setState(1);
            }
        }
        if (device_class.match(/mobile/)) {
            if ($handle.length) {
                $handle.show();
                $handle[0].setState(-1);
            }
            if ($toc.length) {
                $toc[0].setState(-1);
            }
        }
    }
    jQuery(function () {
        var resizeTimer;
        dw_page.makeToggle("#dokuwiki__aside h3.toggle", "#dokuwiki__aside div.content");
        tpl_dokuwiki_mobile();
        jQuery(window).bind("resize", function () {
            if (resizeTimer) clearTimeout(resizeTimer);
            resizeTimer = setTimeout(tpl_dokuwiki_mobile, 200);
        });
        var $sidebar = jQuery(".desktop #dokuwiki__aside");
        if ($sidebar.length) {
            var $content = jQuery("#dokuwiki__content div.page");
            $content.css("min-height", $sidebar.height());
        }
    });
    var dw_acl = {
        init: function () {
            var $tree;
            if (jQuery("#acl_manager").length === 0) {
                return;
            }
            jQuery("#acl__user select").change(dw_acl.userselhandler);
            jQuery("#acl__user input[type=submit]").click(dw_acl.loadinfo);
            $tree = jQuery("#acl__tree");
            $tree.dw_tree({
                toggle_selector: "img",
                load_data: function (show_sublist, $clicky) {
                    var $frm = jQuery("#acl__detail form");
                    jQuery.post(
                        DOKU_BASE + "lib/exe/ajax.php",
                        jQuery.extend(dw_acl.parseatt($clicky.parent().find("a")[0].search), {
                            call: "plugin_acl",
                            ajax: "tree",
                            current_ns: $frm.find("input[name=ns]").val(),
                            current_id: $frm.find("input[name=id]").val(),
                        }),
                        show_sublist,
                        "html"
                    );
                },
                toggle_display: function ($clicky, opening) {
                    $clicky.attr("src", DOKU_BASE + "lib/images/" + (opening ? "minus" : "plus") + ".gif");
                },
            });
            $tree.delegate("a", "click", dw_acl.treehandler);
        },
        userselhandler: function () {
            jQuery("#acl__user input").toggle(this.value === "__g__" || this.value === "__u__");
            dw_acl.loadinfo();
        },
        loadinfo: function () {
            jQuery("#acl__info")
                .attr("role", "alert")
                .html('<img src="' + DOKU_BASE + 'lib/images/throbber.gif" alt="..." />')
                .load(
                    DOKU_BASE + "lib/exe/ajax.php",
                    jQuery("#acl__detail form").serialize() + "&call=plugin_acl&ajax=info"
                );
            return false;
        },
        parseatt: function (str) {
            if (str[0] === "?") {
                str = str.substr(1);
            }
            var attributes = {};
            var all = str.split("&");
            for (var i = 0; i < all.length; i++) {
                var att = all[i].split("=");
                attributes[att[0]] = decodeURIComponent(att[1]);
            }
            return attributes;
        },
        treehandler: function () {
            var $link, $frm;
            $link = jQuery(this);
            jQuery("#acl__tree a.cur").removeClass("cur");
            $link.addClass("cur");
            $frm = jQuery("#acl__detail form");
            if ($link.hasClass("wikilink1")) {
                $frm.find("input[name=ns]").val("");
                $frm.find("input[name=id]").val(dw_acl.parseatt($link[0].search).id);
            } else if ($link.hasClass("idx_dir")) {
                $frm.find("input[name=ns]").val(dw_acl.parseatt($link[0].search).ns);
                $frm.find("input[name=id]").val("");
            }
            dw_acl.loadinfo();
            return false;
        },
    };
    jQuery(dw_acl.init);
    jQuery(function () {
        jQuery("#usrmgr__del").click(function () {
            return confirm(LANG.del_confirm);
        });
    });
    jQuery(function () {
        dw_locktimer.init(840, 1);
    });
}
