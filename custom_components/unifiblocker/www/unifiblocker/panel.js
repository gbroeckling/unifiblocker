/**
 * @license
 * Copyright 2019 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const tt = globalThis, ut = tt.ShadowRoot && (tt.ShadyCSS === void 0 || tt.ShadyCSS.nativeShadow) && "adoptedStyleSheets" in Document.prototype && "replace" in CSSStyleSheet.prototype, mt = Symbol(), Ct = /* @__PURE__ */ new WeakMap();
let zt = class {
  constructor(t, a, s) {
    if (this._$cssResult$ = !0, s !== mt) throw Error("CSSResult is not constructable. Use `unsafeCSS` or `css` instead.");
    this.cssText = t, this.t = a;
  }
  get styleSheet() {
    let t = this.o;
    const a = this.t;
    if (ut && t === void 0) {
      const s = a !== void 0 && a.length === 1;
      s && (t = Ct.get(a)), t === void 0 && ((this.o = t = new CSSStyleSheet()).replaceSync(this.cssText), s && Ct.set(a, t));
    }
    return t;
  }
  toString() {
    return this.cssText;
  }
};
const Zt = (e) => new zt(typeof e == "string" ? e : e + "", void 0, mt), vt = (e, ...t) => {
  const a = e.length === 1 ? e[0] : t.reduce((s, n, i) => s + ((r) => {
    if (r._$cssResult$ === !0) return r.cssText;
    if (typeof r == "number") return r;
    throw Error("Value passed to 'css' function must be a 'css' function result: " + r + ". Use 'unsafeCSS' to pass non-literal values, but take care to ensure page security.");
  })(n) + e[i + 1], e[0]);
  return new zt(a, e, mt);
}, Yt = (e, t) => {
  if (ut) e.adoptedStyleSheets = t.map((a) => a instanceof CSSStyleSheet ? a : a.styleSheet);
  else for (const a of t) {
    const s = document.createElement("style"), n = tt.litNonce;
    n !== void 0 && s.setAttribute("nonce", n), s.textContent = a.cssText, e.appendChild(s);
  }
}, At = ut ? (e) => e : (e) => e instanceof CSSStyleSheet ? ((t) => {
  let a = "";
  for (const s of t.cssRules) a += s.cssText;
  return Zt(a);
})(e) : e;
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const { is: te, defineProperty: ee, getOwnPropertyDescriptor: se, getOwnPropertyNames: ae, getOwnPropertySymbols: ne, getPrototypeOf: ie } = Object, ot = globalThis, St = ot.trustedTypes, oe = St ? St.emptyScript : "", re = ot.reactiveElementPolyfillSupport, W = (e, t) => e, et = { toAttribute(e, t) {
  switch (t) {
    case Boolean:
      e = e ? oe : null;
      break;
    case Object:
    case Array:
      e = e == null ? e : JSON.stringify(e);
  }
  return e;
}, fromAttribute(e, t) {
  let a = e;
  switch (t) {
    case Boolean:
      a = e !== null;
      break;
    case Number:
      a = e === null ? null : Number(e);
      break;
    case Object:
    case Array:
      try {
        a = JSON.parse(e);
      } catch {
        a = null;
      }
  }
  return a;
} }, bt = (e, t) => !te(e, t), Pt = { attribute: !0, type: String, converter: et, reflect: !1, useDefault: !1, hasChanged: bt };
Symbol.metadata ??= Symbol("metadata"), ot.litPropertyMetadata ??= /* @__PURE__ */ new WeakMap();
let H = class extends HTMLElement {
  static addInitializer(t) {
    this._$Ei(), (this.l ??= []).push(t);
  }
  static get observedAttributes() {
    return this.finalize(), this._$Eh && [...this._$Eh.keys()];
  }
  static createProperty(t, a = Pt) {
    if (a.state && (a.attribute = !1), this._$Ei(), this.prototype.hasOwnProperty(t) && ((a = Object.create(a)).wrapped = !0), this.elementProperties.set(t, a), !a.noAccessor) {
      const s = Symbol(), n = this.getPropertyDescriptor(t, s, a);
      n !== void 0 && ee(this.prototype, t, n);
    }
  }
  static getPropertyDescriptor(t, a, s) {
    const { get: n, set: i } = se(this.prototype, t) ?? { get() {
      return this[a];
    }, set(r) {
      this[a] = r;
    } };
    return { get: n, set(r) {
      const h = n?.call(this);
      i?.call(this, r), this.requestUpdate(t, h, s);
    }, configurable: !0, enumerable: !0 };
  }
  static getPropertyOptions(t) {
    return this.elementProperties.get(t) ?? Pt;
  }
  static _$Ei() {
    if (this.hasOwnProperty(W("elementProperties"))) return;
    const t = ie(this);
    t.finalize(), t.l !== void 0 && (this.l = [...t.l]), this.elementProperties = new Map(t.elementProperties);
  }
  static finalize() {
    if (this.hasOwnProperty(W("finalized"))) return;
    if (this.finalized = !0, this._$Ei(), this.hasOwnProperty(W("properties"))) {
      const a = this.properties, s = [...ae(a), ...ne(a)];
      for (const n of s) this.createProperty(n, a[n]);
    }
    const t = this[Symbol.metadata];
    if (t !== null) {
      const a = litPropertyMetadata.get(t);
      if (a !== void 0) for (const [s, n] of a) this.elementProperties.set(s, n);
    }
    this._$Eh = /* @__PURE__ */ new Map();
    for (const [a, s] of this.elementProperties) {
      const n = this._$Eu(a, s);
      n !== void 0 && this._$Eh.set(n, a);
    }
    this.elementStyles = this.finalizeStyles(this.styles);
  }
  static finalizeStyles(t) {
    const a = [];
    if (Array.isArray(t)) {
      const s = new Set(t.flat(1 / 0).reverse());
      for (const n of s) a.unshift(At(n));
    } else t !== void 0 && a.push(At(t));
    return a;
  }
  static _$Eu(t, a) {
    const s = a.attribute;
    return s === !1 ? void 0 : typeof s == "string" ? s : typeof t == "string" ? t.toLowerCase() : void 0;
  }
  constructor() {
    super(), this._$Ep = void 0, this.isUpdatePending = !1, this.hasUpdated = !1, this._$Em = null, this._$Ev();
  }
  _$Ev() {
    this._$ES = new Promise((t) => this.enableUpdating = t), this._$AL = /* @__PURE__ */ new Map(), this._$E_(), this.requestUpdate(), this.constructor.l?.forEach((t) => t(this));
  }
  addController(t) {
    (this._$EO ??= /* @__PURE__ */ new Set()).add(t), this.renderRoot !== void 0 && this.isConnected && t.hostConnected?.();
  }
  removeController(t) {
    this._$EO?.delete(t);
  }
  _$E_() {
    const t = /* @__PURE__ */ new Map(), a = this.constructor.elementProperties;
    for (const s of a.keys()) this.hasOwnProperty(s) && (t.set(s, this[s]), delete this[s]);
    t.size > 0 && (this._$Ep = t);
  }
  createRenderRoot() {
    const t = this.shadowRoot ?? this.attachShadow(this.constructor.shadowRootOptions);
    return Yt(t, this.constructor.elementStyles), t;
  }
  connectedCallback() {
    this.renderRoot ??= this.createRenderRoot(), this.enableUpdating(!0), this._$EO?.forEach((t) => t.hostConnected?.());
  }
  enableUpdating(t) {
  }
  disconnectedCallback() {
    this._$EO?.forEach((t) => t.hostDisconnected?.());
  }
  attributeChangedCallback(t, a, s) {
    this._$AK(t, s);
  }
  _$ET(t, a) {
    const s = this.constructor.elementProperties.get(t), n = this.constructor._$Eu(t, s);
    if (n !== void 0 && s.reflect === !0) {
      const i = (s.converter?.toAttribute !== void 0 ? s.converter : et).toAttribute(a, s.type);
      this._$Em = t, i == null ? this.removeAttribute(n) : this.setAttribute(n, i), this._$Em = null;
    }
  }
  _$AK(t, a) {
    const s = this.constructor, n = s._$Eh.get(t);
    if (n !== void 0 && this._$Em !== n) {
      const i = s.getPropertyOptions(n), r = typeof i.converter == "function" ? { fromAttribute: i.converter } : i.converter?.fromAttribute !== void 0 ? i.converter : et;
      this._$Em = n;
      const h = r.fromAttribute(a, i.type);
      this[n] = h ?? this._$Ej?.get(n) ?? h, this._$Em = null;
    }
  }
  requestUpdate(t, a, s, n = !1, i) {
    if (t !== void 0) {
      const r = this.constructor;
      if (n === !1 && (i = this[t]), s ??= r.getPropertyOptions(t), !((s.hasChanged ?? bt)(i, a) || s.useDefault && s.reflect && i === this._$Ej?.get(t) && !this.hasAttribute(r._$Eu(t, s)))) return;
      this.C(t, a, s);
    }
    this.isUpdatePending === !1 && (this._$ES = this._$EP());
  }
  C(t, a, { useDefault: s, reflect: n, wrapped: i }, r) {
    s && !(this._$Ej ??= /* @__PURE__ */ new Map()).has(t) && (this._$Ej.set(t, r ?? a ?? this[t]), i !== !0 || r !== void 0) || (this._$AL.has(t) || (this.hasUpdated || s || (a = void 0), this._$AL.set(t, a)), n === !0 && this._$Em !== t && (this._$Eq ??= /* @__PURE__ */ new Set()).add(t));
  }
  async _$EP() {
    this.isUpdatePending = !0;
    try {
      await this._$ES;
    } catch (a) {
      Promise.reject(a);
    }
    const t = this.scheduleUpdate();
    return t != null && await t, !this.isUpdatePending;
  }
  scheduleUpdate() {
    return this.performUpdate();
  }
  performUpdate() {
    if (!this.isUpdatePending) return;
    if (!this.hasUpdated) {
      if (this.renderRoot ??= this.createRenderRoot(), this._$Ep) {
        for (const [n, i] of this._$Ep) this[n] = i;
        this._$Ep = void 0;
      }
      const s = this.constructor.elementProperties;
      if (s.size > 0) for (const [n, i] of s) {
        const { wrapped: r } = i, h = this[n];
        r !== !0 || this._$AL.has(n) || h === void 0 || this.C(n, void 0, i, h);
      }
    }
    let t = !1;
    const a = this._$AL;
    try {
      t = this.shouldUpdate(a), t ? (this.willUpdate(a), this._$EO?.forEach((s) => s.hostUpdate?.()), this.update(a)) : this._$EM();
    } catch (s) {
      throw t = !1, this._$EM(), s;
    }
    t && this._$AE(a);
  }
  willUpdate(t) {
  }
  _$AE(t) {
    this._$EO?.forEach((a) => a.hostUpdated?.()), this.hasUpdated || (this.hasUpdated = !0, this.firstUpdated(t)), this.updated(t);
  }
  _$EM() {
    this._$AL = /* @__PURE__ */ new Map(), this.isUpdatePending = !1;
  }
  get updateComplete() {
    return this.getUpdateComplete();
  }
  getUpdateComplete() {
    return this._$ES;
  }
  shouldUpdate(t) {
    return !0;
  }
  update(t) {
    this._$Eq &&= this._$Eq.forEach((a) => this._$ET(a, this[a])), this._$EM();
  }
  updated(t) {
  }
  firstUpdated(t) {
  }
};
H.elementStyles = [], H.shadowRootOptions = { mode: "open" }, H[W("elementProperties")] = /* @__PURE__ */ new Map(), H[W("finalized")] = /* @__PURE__ */ new Map(), re?.({ ReactiveElement: H }), (ot.reactiveElementVersions ??= []).push("2.1.2");
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const $t = globalThis, Ot = (e) => e, st = $t.trustedTypes, Et = st ? st.createPolicy("lit-html", { createHTML: (e) => e }) : void 0, Ft = "$lit$", P = `lit$${Math.random().toFixed(9).slice(2)}$`, qt = "?" + P, le = `<${qt}>`, T = document, Q = () => T.createComment(""), K = (e) => e === null || typeof e != "object" && typeof e != "function", gt = Array.isArray, ce = (e) => gt(e) || typeof e?.[Symbol.iterator] == "function", ht = `[ 	
\f\r]`, V = /<(?:(!--|\/[^a-zA-Z])|(\/?[a-zA-Z][^>\s]*)|(\/?$))/g, Nt = /-->/g, Mt = />/g, E = RegExp(`>|${ht}(?:([^\\s"'>=/]+)(${ht}*=${ht}*(?:[^ 	
\f\r"'\`<>=]|("|')|))|$)`, "g"), Tt = /'/g, Ut = /"/g, Vt = /^(?:script|style|textarea|title)$/i, Wt = (e) => (t, ...a) => ({ _$litType$: e, strings: t, values: a }), o = Wt(1), de = Wt(2), B = Symbol.for("lit-noChange"), l = Symbol.for("lit-nothing"), Rt = /* @__PURE__ */ new WeakMap(), N = T.createTreeWalker(T, 129);
function Qt(e, t) {
  if (!gt(e) || !e.hasOwnProperty("raw")) throw Error("invalid template strings array");
  return Et !== void 0 ? Et.createHTML(t) : t;
}
const he = (e, t) => {
  const a = e.length - 1, s = [];
  let n, i = t === 2 ? "<svg>" : t === 3 ? "<math>" : "", r = V;
  for (let h = 0; h < a; h++) {
    const c = e[h];
    let p, u, d = -1, f = 0;
    for (; f < c.length && (r.lastIndex = f, u = r.exec(c), u !== null); ) f = r.lastIndex, r === V ? u[1] === "!--" ? r = Nt : u[1] !== void 0 ? r = Mt : u[2] !== void 0 ? (Vt.test(u[2]) && (n = RegExp("</" + u[2], "g")), r = E) : u[3] !== void 0 && (r = E) : r === E ? u[0] === ">" ? (r = n ?? V, d = -1) : u[1] === void 0 ? d = -2 : (d = r.lastIndex - u[2].length, p = u[1], r = u[3] === void 0 ? E : u[3] === '"' ? Ut : Tt) : r === Ut || r === Tt ? r = E : r === Nt || r === Mt ? r = V : (r = E, n = void 0);
    const b = r === E && e[h + 1].startsWith("/>") ? " " : "";
    i += r === V ? c + le : d >= 0 ? (s.push(p), c.slice(0, d) + Ft + c.slice(d) + P + b) : c + P + (d === -2 ? h : b);
  }
  return [Qt(e, i + (e[a] || "<?>") + (t === 2 ? "</svg>" : t === 3 ? "</math>" : "")), s];
};
class X {
  constructor({ strings: t, _$litType$: a }, s) {
    let n;
    this.parts = [];
    let i = 0, r = 0;
    const h = t.length - 1, c = this.parts, [p, u] = he(t, a);
    if (this.el = X.createElement(p, s), N.currentNode = this.el.content, a === 2 || a === 3) {
      const d = this.el.content.firstChild;
      d.replaceWith(...d.childNodes);
    }
    for (; (n = N.nextNode()) !== null && c.length < h; ) {
      if (n.nodeType === 1) {
        if (n.hasAttributes()) for (const d of n.getAttributeNames()) if (d.endsWith(Ft)) {
          const f = u[r++], b = n.getAttribute(d).split(P), j = /([.?@])?(.*)/.exec(f);
          c.push({ type: 1, index: i, name: j[2], strings: b, ctor: j[1] === "." ? ue : j[1] === "?" ? me : j[1] === "@" ? ve : rt }), n.removeAttribute(d);
        } else d.startsWith(P) && (c.push({ type: 6, index: i }), n.removeAttribute(d));
        if (Vt.test(n.tagName)) {
          const d = n.textContent.split(P), f = d.length - 1;
          if (f > 0) {
            n.textContent = st ? st.emptyScript : "";
            for (let b = 0; b < f; b++) n.append(d[b], Q()), N.nextNode(), c.push({ type: 2, index: ++i });
            n.append(d[f], Q());
          }
        }
      } else if (n.nodeType === 8) if (n.data === qt) c.push({ type: 2, index: i });
      else {
        let d = -1;
        for (; (d = n.data.indexOf(P, d + 1)) !== -1; ) c.push({ type: 7, index: i }), d += P.length - 1;
      }
      i++;
    }
  }
  static createElement(t, a) {
    const s = T.createElement("template");
    return s.innerHTML = t, s;
  }
}
function z(e, t, a = e, s) {
  if (t === B) return t;
  let n = s !== void 0 ? a._$Co?.[s] : a._$Cl;
  const i = K(t) ? void 0 : t._$litDirective$;
  return n?.constructor !== i && (n?._$AO?.(!1), i === void 0 ? n = void 0 : (n = new i(e), n._$AT(e, a, s)), s !== void 0 ? (a._$Co ??= [])[s] = n : a._$Cl = n), n !== void 0 && (t = z(e, n._$AS(e, t.values), n, s)), t;
}
class pe {
  constructor(t, a) {
    this._$AV = [], this._$AN = void 0, this._$AD = t, this._$AM = a;
  }
  get parentNode() {
    return this._$AM.parentNode;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  u(t) {
    const { el: { content: a }, parts: s } = this._$AD, n = (t?.creationScope ?? T).importNode(a, !0);
    N.currentNode = n;
    let i = N.nextNode(), r = 0, h = 0, c = s[0];
    for (; c !== void 0; ) {
      if (r === c.index) {
        let p;
        c.type === 2 ? p = new J(i, i.nextSibling, this, t) : c.type === 1 ? p = new c.ctor(i, c.name, c.strings, this, t) : c.type === 6 && (p = new be(i, this, t)), this._$AV.push(p), c = s[++h];
      }
      r !== c?.index && (i = N.nextNode(), r++);
    }
    return N.currentNode = T, n;
  }
  p(t) {
    let a = 0;
    for (const s of this._$AV) s !== void 0 && (s.strings !== void 0 ? (s._$AI(t, s, a), a += s.strings.length - 2) : s._$AI(t[a])), a++;
  }
}
class J {
  get _$AU() {
    return this._$AM?._$AU ?? this._$Cv;
  }
  constructor(t, a, s, n) {
    this.type = 2, this._$AH = l, this._$AN = void 0, this._$AA = t, this._$AB = a, this._$AM = s, this.options = n, this._$Cv = n?.isConnected ?? !0;
  }
  get parentNode() {
    let t = this._$AA.parentNode;
    const a = this._$AM;
    return a !== void 0 && t?.nodeType === 11 && (t = a.parentNode), t;
  }
  get startNode() {
    return this._$AA;
  }
  get endNode() {
    return this._$AB;
  }
  _$AI(t, a = this) {
    t = z(this, t, a), K(t) ? t === l || t == null || t === "" ? (this._$AH !== l && this._$AR(), this._$AH = l) : t !== this._$AH && t !== B && this._(t) : t._$litType$ !== void 0 ? this.$(t) : t.nodeType !== void 0 ? this.T(t) : ce(t) ? this.k(t) : this._(t);
  }
  O(t) {
    return this._$AA.parentNode.insertBefore(t, this._$AB);
  }
  T(t) {
    this._$AH !== t && (this._$AR(), this._$AH = this.O(t));
  }
  _(t) {
    this._$AH !== l && K(this._$AH) ? this._$AA.nextSibling.data = t : this.T(T.createTextNode(t)), this._$AH = t;
  }
  $(t) {
    const { values: a, _$litType$: s } = t, n = typeof s == "number" ? this._$AC(t) : (s.el === void 0 && (s.el = X.createElement(Qt(s.h, s.h[0]), this.options)), s);
    if (this._$AH?._$AD === n) this._$AH.p(a);
    else {
      const i = new pe(n, this), r = i.u(this.options);
      i.p(a), this.T(r), this._$AH = i;
    }
  }
  _$AC(t) {
    let a = Rt.get(t.strings);
    return a === void 0 && Rt.set(t.strings, a = new X(t)), a;
  }
  k(t) {
    gt(this._$AH) || (this._$AH = [], this._$AR());
    const a = this._$AH;
    let s, n = 0;
    for (const i of t) n === a.length ? a.push(s = new J(this.O(Q()), this.O(Q()), this, this.options)) : s = a[n], s._$AI(i), n++;
    n < a.length && (this._$AR(s && s._$AB.nextSibling, n), a.length = n);
  }
  _$AR(t = this._$AA.nextSibling, a) {
    for (this._$AP?.(!1, !0, a); t !== this._$AB; ) {
      const s = Ot(t).nextSibling;
      Ot(t).remove(), t = s;
    }
  }
  setConnected(t) {
    this._$AM === void 0 && (this._$Cv = t, this._$AP?.(t));
  }
}
class rt {
  get tagName() {
    return this.element.tagName;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  constructor(t, a, s, n, i) {
    this.type = 1, this._$AH = l, this._$AN = void 0, this.element = t, this.name = a, this._$AM = n, this.options = i, s.length > 2 || s[0] !== "" || s[1] !== "" ? (this._$AH = Array(s.length - 1).fill(new String()), this.strings = s) : this._$AH = l;
  }
  _$AI(t, a = this, s, n) {
    const i = this.strings;
    let r = !1;
    if (i === void 0) t = z(this, t, a, 0), r = !K(t) || t !== this._$AH && t !== B, r && (this._$AH = t);
    else {
      const h = t;
      let c, p;
      for (t = i[0], c = 0; c < i.length - 1; c++) p = z(this, h[s + c], a, c), p === B && (p = this._$AH[c]), r ||= !K(p) || p !== this._$AH[c], p === l ? t = l : t !== l && (t += (p ?? "") + i[c + 1]), this._$AH[c] = p;
    }
    r && !n && this.j(t);
  }
  j(t) {
    t === l ? this.element.removeAttribute(this.name) : this.element.setAttribute(this.name, t ?? "");
  }
}
class ue extends rt {
  constructor() {
    super(...arguments), this.type = 3;
  }
  j(t) {
    this.element[this.name] = t === l ? void 0 : t;
  }
}
class me extends rt {
  constructor() {
    super(...arguments), this.type = 4;
  }
  j(t) {
    this.element.toggleAttribute(this.name, !!t && t !== l);
  }
}
class ve extends rt {
  constructor(t, a, s, n, i) {
    super(t, a, s, n, i), this.type = 5;
  }
  _$AI(t, a = this) {
    if ((t = z(this, t, a, 0) ?? l) === B) return;
    const s = this._$AH, n = t === l && s !== l || t.capture !== s.capture || t.once !== s.once || t.passive !== s.passive, i = t !== l && (s === l || n);
    n && this.element.removeEventListener(this.name, this, s), i && this.element.addEventListener(this.name, this, t), this._$AH = t;
  }
  handleEvent(t) {
    typeof this._$AH == "function" ? this._$AH.call(this.options?.host ?? this.element, t) : this._$AH.handleEvent(t);
  }
}
class be {
  constructor(t, a, s) {
    this.element = t, this.type = 6, this._$AN = void 0, this._$AM = a, this.options = s;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  _$AI(t) {
    z(this, t);
  }
}
const $e = $t.litHtmlPolyfillSupport;
$e?.(X, J), ($t.litHtmlVersions ??= []).push("3.3.3");
const ge = (e, t, a) => {
  const s = a?.renderBefore ?? t;
  let n = s._$litPart$;
  if (n === void 0) {
    const i = a?.renderBefore ?? null;
    s._$litPart$ = n = new J(t.insertBefore(Q(), i), i, void 0, a ?? {});
  }
  return n._$AI(e), n;
};
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const ft = globalThis;
class $ extends H {
  constructor() {
    super(...arguments), this.renderOptions = { host: this }, this._$Do = void 0;
  }
  createRenderRoot() {
    const t = super.createRenderRoot();
    return this.renderOptions.renderBefore ??= t.firstChild, t;
  }
  update(t) {
    const a = this.render();
    this.hasUpdated || (this.renderOptions.isConnected = this.isConnected), super.update(t), this._$Do = ge(a, this.renderRoot, this.renderOptions);
  }
  connectedCallback() {
    super.connectedCallback(), this._$Do?.setConnected(!0);
  }
  disconnectedCallback() {
    super.disconnectedCallback(), this._$Do?.setConnected(!1);
  }
  render() {
    return B;
  }
}
$._$litElement$ = !0, $.finalized = !0, ft.litElementHydrateSupport?.({ LitElement: $ });
const fe = ft.litElementPolyfillSupport;
fe?.({ LitElement: $ });
(ft.litElementVersions ??= []).push("4.2.2");
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const x = (e) => (t, a) => {
  a !== void 0 ? a.addInitializer(() => {
    customElements.define(e, t);
  }) : customElements.define(e, t);
};
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const ye = { attribute: !0, type: String, converter: et, reflect: !1, hasChanged: bt }, we = (e = ye, t, a) => {
  const { kind: s, metadata: n } = a;
  let i = globalThis.litPropertyMetadata.get(n);
  if (i === void 0 && globalThis.litPropertyMetadata.set(n, i = /* @__PURE__ */ new Map()), s === "setter" && ((e = Object.create(e)).wrapped = !0), i.set(a.name, e), s === "accessor") {
    const { name: r } = a;
    return { set(h) {
      const c = t.get.call(this);
      t.set.call(this, h), this.requestUpdate(r, c, e, !0, h);
    }, init(h) {
      return h !== void 0 && this.C(r, void 0, e, h), h;
    } };
  }
  if (s === "setter") {
    const { name: r } = a;
    return function(h) {
      const c = this[r];
      t.call(this, h), this.requestUpdate(r, c, e, !0, h);
    };
  }
  throw Error("Unsupported decorator location: " + s);
};
function g(e) {
  return (t, a) => typeof a == "object" ? we(e, t, a) : ((s, n, i) => {
    const r = n.hasOwnProperty(i);
    return n.constructor.createProperty(i, s), r ? Object.getOwnPropertyDescriptor(n, i) : void 0;
  })(e, t, a);
}
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
function v(e) {
  return g({ ...e, state: !0, attribute: !1 });
}
class pt extends Error {
  constructor(t, a) {
    super(a), this.code = t;
  }
}
async function _(e, t, a = {}) {
  try {
    return await e.callWS({ type: `unifiblocker/${t}`, ...a });
  } catch (s) {
    throw new pt(s?.code ?? "error", s?.message ?? String(s));
  }
}
async function S(e, t) {
  try {
    return await e;
  } catch {
    return t;
  }
}
async function _e(e) {
  const [t, a, s, n, i, r, h, c] = await Promise.all([
    S(_(e, "overview"), {}),
    S(_(e, "clients"), { clients: [] }),
    S(_(e, "recommendations"), {}),
    S(_(e, "localnet_status"), {}),
    S(_(e, "miners"), { rigs: [], summary: {} }),
    S(_(e, "scan_results"), { results: {} }),
    S(_(e, "report_status"), null),
    S(_(e, "learned_rules"), null)
  ]);
  return {
    overview: t,
    clients: a.clients || [],
    recs: s,
    localnet: n,
    miners: i,
    scans: r.results || {},
    report: h,
    learned: c,
    loaded: !0,
    error: "",
    updated: Date.now()
  };
}
const k = vt`
  :host {
    --ub-ok: var(--success-color, #43a047);
    --ub-warn: var(--warning-color, #ffa000);
    --ub-bad: var(--error-color, #db4437);
    --ub-info: var(--info-color, #039be5);
    --ub-muted: var(--secondary-text-color);
    --ub-line: var(--divider-color, rgba(127, 127, 127, 0.25));
    --ub-card: var(--card-background-color, var(--ha-card-background, #fff));
    --ub-radius: var(--ha-card-border-radius, 12px);
    color: var(--primary-text-color);
    font-family: var(--paper-font-body1_-_font-family, Roboto, system-ui, sans-serif);
  }
  h1 { font-size: 22px; font-weight: 500; margin: 0 0 4px; }
  h2 { font-size: 16px; font-weight: 500; margin: 0 0 12px; }
  h3 { font-size: 14px; font-weight: 500; margin: 12px 0 6px; }
  p { margin: 0 0 8px; line-height: 1.45; }
  .sub { color: var(--ub-muted); font-size: 13px; margin-bottom: 16px; }
  .muted { color: var(--ub-muted); }
  .small { font-size: 12px; }
  .mono { font-family: var(--code-font-family, ui-monospace, Consolas, monospace); font-size: 12px; }
  .card {
    background: var(--ub-card);
    border-radius: var(--ub-radius);
    box-shadow: var(--ha-card-box-shadow, none);
    border: 1px solid var(--ha-card-border-color, var(--ub-line));
    padding: 16px;
    margin-bottom: 16px;
  }
  .grid { display: grid; gap: 16px; }
  .grid.two { grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); }
  .tiles { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 12px; margin-bottom: 16px; }
  .tile {
    background: var(--ub-card); border: 1px solid var(--ha-card-border-color, var(--ub-line));
    border-radius: var(--ub-radius); padding: 12px 14px; text-align: left; color: inherit; font: inherit;
  }
  button.tile { cursor: pointer; }
  button.tile:hover, button.tile:focus-visible { border-color: var(--primary-color); outline: none; }
  .tile .n { font-size: 26px; font-weight: 500; line-height: 1.2; }
  .tile .l { color: var(--ub-muted); font-size: 12px; }
  .tile.bad .n { color: var(--ub-bad); }
  .tile.warn .n { color: var(--ub-warn); }
  .tile.ok .n { color: var(--ub-ok); }
  .badge {
    display: inline-flex; align-items: center; gap: 4px; padding: 1px 8px; border-radius: 10px;
    font-size: 11px; font-weight: 500; line-height: 18px; white-space: nowrap;
    background: color-mix(in srgb, var(--ub-muted) 18%, transparent); color: var(--primary-text-color);
  }
  .badge.ok { background: color-mix(in srgb, var(--ub-ok) 20%, transparent); }
  .badge.warn { background: color-mix(in srgb, var(--ub-warn) 25%, transparent); }
  .badge.bad { background: color-mix(in srgb, var(--ub-bad) 22%, transparent); }
  .badge.info { background: color-mix(in srgb, var(--ub-info) 20%, transparent); }
  button.btn, a.btn {
    display: inline-flex; align-items: center; gap: 6px; border: 1px solid var(--ub-line); border-radius: 8px;
    background: transparent; color: var(--primary-text-color); padding: 6px 12px; font: inherit; font-size: 13px;
    cursor: pointer; text-decoration: none;
  }
  button.btn:hover, button.btn:focus-visible { border-color: var(--primary-color); outline: none; }
  button.btn.primary { background: var(--primary-color); border-color: var(--primary-color); color: var(--text-primary-color, #fff); }
  button.btn.danger { color: var(--ub-bad); border-color: color-mix(in srgb, var(--ub-bad) 50%, transparent); }
  button.btn:disabled { opacity: 0.5; cursor: default; }
  .row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .spacer { flex: 1; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--ub-line); vertical-align: top; }
  th { color: var(--ub-muted); font-weight: 500; font-size: 12px; white-space: nowrap; }
  th button { all: unset; cursor: pointer; }
  th button:focus-visible { outline: 2px solid var(--primary-color); }
  tbody tr.click { cursor: pointer; }
  tbody tr.click:hover, tbody tr.click:focus-visible { background: color-mix(in srgb, var(--primary-color) 7%, transparent); outline: none; }
  .scroll { overflow-x: auto; }
  .empty { color: var(--ub-muted); padding: 16px 0; text-align: center; }
  .chips { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 12px; }
  .chip {
    border: 1px solid var(--ub-line); border-radius: 16px; padding: 4px 12px; background: transparent;
    color: inherit; font: inherit; font-size: 13px; cursor: pointer;
  }
  .chip[aria-pressed="true"] { background: var(--primary-color); border-color: var(--primary-color); color: var(--text-primary-color, #fff); }
  input[type="search"], input[type="text"], select {
    font: inherit; font-size: 14px; padding: 7px 10px; border-radius: 8px; border: 1px solid var(--ub-line);
    background: var(--ub-card); color: var(--primary-text-color);
  }
  .kv { display: grid; grid-template-columns: 120px 1fr; gap: 4px 12px; font-size: 13px; }
  .kv > :nth-child(odd) { color: var(--ub-muted); }
  .rec { border-left: 4px solid var(--ub-line); padding: 8px 12px; margin-bottom: 10px; }
  .rec.critical { border-color: var(--ub-bad); }
  .rec.high { border-color: var(--ub-warn); }
  .rec.medium { border-color: var(--ub-info); }
  .rec .t { font-weight: 500; }
  .rec .d { color: var(--ub-muted); font-size: 13px; white-space: pre-line; margin: 4px 0; }
  button.linkish { all: unset; cursor: pointer; color: var(--primary-color); }
  button.linkish:focus-visible { outline: 2px solid var(--primary-color); }
  .sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
`;
function L(e) {
  if (!e) return "0 B";
  const t = ["B", "KB", "MB", "GB", "TB"];
  let a = 0, s = e;
  for (; s >= 1e3 && a < t.length - 1; )
    s /= 1e3, a++;
  return `${s >= 100 || a === 0 ? Math.round(s) : s.toFixed(1)} ${t[a]}`;
}
function y(e, t, a = `${t}s`) {
  return `${e} ${e === 1 ? t : a}`;
}
function Kt(e) {
  if (!e) return "—";
  const t = Math.floor(e / 86400), a = Math.floor(e % 86400 / 3600), s = Math.floor(e % 3600 / 60);
  return t ? `${t}d ${a}h` : a ? `${a}h ${s}m` : `${s}m`;
}
function Dt(e) {
  if (!e) return "—";
  const t = ["H/s", "kH/s", "MH/s", "GH/s", "TH/s", "PH/s"];
  let a = 0, s = e;
  for (; s >= 1e3 && a < t.length - 1; )
    s /= 1e3, a++;
  return `${s.toFixed(s >= 100 ? 0 : 1)} ${t[a]}`;
}
const I = (e) => e == null ? "—" : `$${e.toFixed(2)}`;
function m(e) {
  return e.name || e.hostname || e.mac;
}
function yt(e, t = 3, a = 22) {
  if (!e || !e.length) return l;
  const s = Math.max(...e, 1), n = e.reduce((i, r) => i + r, 0);
  return o`<svg width=${e.length * (t + 1)} height=${a} role="img"
    aria-label="Traffic per hour over 24 hours, ${L(n)} total" style="vertical-align:middle;color:var(--primary-color)">
    ${e.map((i, r) => {
    const h = Math.max(1, Math.round(a * i / s));
    return de`<rect x=${r * (t + 1)} y=${a - h} width=${t} height=${h} fill="currentColor" opacity=${r === e.length - 1 ? 1 : 0.55}></rect>`;
  })}
  </svg>`;
}
const xe = { new: "warn", trusted: "ok", ignored: "", quarantined: "bad" };
function wt(e) {
  return e.blocked && e.state !== "quarantined" ? o`<span class="badge bad">blocked</span>` : o`<span class="badge ${xe[e.state] ?? ""}">${e.state}</span>`;
}
function M(e) {
  switch (e.containment) {
    case "holding":
      return o`<span class="badge ok">contained</span>`;
    case "quiet":
      return o`<span class="badge ok">contained · quiet</span>`;
    case "leaking":
      return o`<span class="badge bad">NOT contained</span>`;
    default:
      return e.is_camera ? o`<span class="badge warn">internet open</span>` : l;
  }
}
function lt(e) {
  const t = e.vulns?.worst;
  return t === "affected" ? o`<span class="badge bad">exploited bug</span>` : t === "likely" ? o`<span class="badge bad">likely exploited bug</span>` : t === "check" ? o`<span class="badge warn">check firmware</span>` : (e.vulns?.firmware_age_years ?? 0) >= 5 ? o`<span class="badge warn">firmware ${e.vulns.firmware_age_years}y old</span>` : l;
}
function ct(e) {
  const t = e.overview.category_labels || {};
  return Object.entries(t).sort((a, s) => a[1].localeCompare(s[1]));
}
const jt = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }, _t = (e, t) => (jt[e.priority] ?? 5) - (jt[t.priority] ?? 5);
function ke(e, t, a) {
  const s = t.action_data?.mac || a;
  if (!s) return l;
  const n = e.snap.clients.find((r) => r.mac.toLowerCase() === s.toLowerCase()), i = n ? m(n) : s;
  switch (t.action) {
    case "local_only":
      return o`<button class="btn primary" @click=${() => e.act(
        "localnet_assign",
        { mac: s, category: t.action_data?.category || n?.category || "iot" },
        { confirm: `Put ${i} on local-only? It gets a ${e.snap.localnet.prefix || "192.168.2"}.x address and is blocked from the internet. It reconnects to pick up the new address.`, done: `${i} is now local-only` }
      )}>Make local-only</button>`;
    case "block_internet":
      return o`<button class="btn primary" @click=${() => e.act(
        "block_internet",
        { mac: s },
        { confirm: `Block ${i} from the internet? It keeps its address and keeps working on your network.`, done: `${i} blocked from the internet` }
      )}>Block internet</button>`;
    case "quarantine":
      return o`<button class="btn danger" @click=${() => e.act("quarantine", { mac: s }, { confirm: `Quarantine ${i}? It's blocked on the controller and can't use the network at all.`, danger: !0, done: `${i} quarantined` })}>Quarantine</button>`;
    case "review":
      return o`<button class="btn" @click=${() => e.open(s)}>Open device</button>`;
    default:
      return n ? o`<button class="btn" @click=${() => e.open(s)}>Open device</button>` : l;
  }
}
function xt(e, t, a) {
  const s = a ? e.snap.clients.find((n) => n.mac.toLowerCase() === a.toLowerCase()) : void 0;
  return o`<div class="rec ${t.priority}">
    <div class="row">
      <span class="badge ${t.priority === "critical" ? "bad" : t.priority === "high" ? "warn" : t.priority === "medium" ? "info" : ""}">${t.priority}</span>
      <span class="t">${t.title}</span>
      ${s ? o`<span class="muted small">· ${m(s)}</span>` : l}
    </div>
    <div class="d">${t.detail}</div>
    <div class="row">${ke(e, t, a)}</div>
  </div>`;
}
var Ce = Object.defineProperty, Ae = Object.getOwnPropertyDescriptor, dt = (e, t, a, s) => {
  for (var n = s > 1 ? void 0 : s ? Ae(t, a) : t, i = e.length - 1, r; i >= 0; i--)
    (r = e[i]) && (n = (s ? r(t, a, n) : r(n)) || n);
  return s && n && Ce(t, a, n), n;
};
let F = class extends $ {
  constructor() {
    super(...arguments), this.quantify = null, this.running = !1;
  }
  async runQuantify() {
    this.running = !0;
    const e = await this.ctx.act("deep_scan_unknowns", {}, { confirm: "Deep-scan every device that's still unknown? It probes each one (web, TLS, SSH, mDNS, NetBIOS) and takes a few minutes." });
    this.running = !1, e && (this.quantify = e);
  }
  render() {
    const { snap: e } = this.ctx;
    if (!e.loaded) return o`<div class="empty">Loading…</div>`;
    const t = e.overview, a = e.clients.filter((c) => c.is_camera), s = a.filter((c) => c.containment === "holding" || c.containment === "quiet").length, n = e.clients.filter((c) => c.containment === "leaking"), i = e.clients.filter((c) => c.vulns?.worst === "affected" || c.vulns?.worst === "likely").length, r = e.clients.filter((c) => c.category === "unknown").length, h = [
      ...(e.recs.network_recs || []).map((c) => ({ r: c })),
      ...Object.entries(e.recs.device_recs || {}).flatMap(([c, p]) => p.map((u) => ({ r: u, mac: c })))
    ].filter((c) => c.r.priority === "critical" || c.r.priority === "high").sort((c, p) => _t(c.r, p.r));
    return o`
      <h1>Overview</h1>
      <p class="sub">${t.health?.connection_ok === !1 ? "Can't reach the controller." : `Connected to ${t.health?.hostname || "the controller"}${t.health?.version ? ` (UniFi Network ${t.health.version})` : ""}.`}</p>

      <div class="tiles">
        <button class="tile" @click=${() => this.ctx.go("devices", "all")}><div class="n">${t.total_clients ?? 0}</div><div class="l">devices online</div></button>
        <button class="tile ${t.new_count ? "warn" : ""}" @click=${() => this.ctx.go("devices", "new")}><div class="n">${t.new_count ?? 0}</div><div class="l">waiting for review</div></button>
        <button class="tile ${a.length && s < a.length ? "warn" : "ok"}" @click=${() => this.ctx.go("cameras")}><div class="n">${s}/${a.length}</div><div class="l">cameras contained</div></button>
        <button class="tile ${n.length ? "bad" : ""}" @click=${() => this.ctx.go("cameras")}><div class="n">${n.length}</div><div class="l">not contained</div></button>
        <button class="tile ${i ? "bad" : ""}" @click=${() => this.ctx.go("cameras")}><div class="n">${i}</div><div class="l">with exploited bugs</div></button>
        <button class="tile ${t.threat_events ? "warn" : ""}" @click=${() => this.ctx.go("security")}><div class="n">${t.threat_events ?? 0}</div><div class="l">security events (24 h)</div></button>
        <button class="tile ${t.suspicious_count ? "warn" : ""}" @click=${() => this.ctx.go("devices", "suspicious")}><div class="n">${t.suspicious_count ?? 0}</div><div class="l">suspicious</div></button>
        <button class="tile" @click=${() => this.ctx.go("devices", "unknown")}><div class="n">${r}</div><div class="l">not identified</div></button>
      </div>

      <div class="grid two">
        <div class="card">
          <h2>Needs attention</h2>
          ${h.length ? h.slice(0, 6).map((c) => xt(this.ctx, c.r, c.mac)) : o`<div class="empty">Nothing critical or high right now.</div>`}
          ${h.length > 6 ? o`<button class="btn" @click=${() => this.ctx.go("security")}>All ${h.length} on the Security page</button>` : l}
        </div>

        <div>
          <div class="card">
            <h2>Cameras</h2>
            ${a.length ? o`<div class="scroll"><table>
              <tbody>${a.map((c) => o`<tr class="click" tabindex="0" @click=${() => this.ctx.open(c.mac)} @keydown=${(p) => p.key === "Enter" && this.ctx.open(c.mac)}>
                <td>${m(c)}<div class="muted small">${c.ip}</div></td>
                <td>${M(c)} ${lt(c)}</td>
                <td class="small muted">${c.phone_home ? `${y(c.phone_home.attempts, "attempt")} blocked${c.phone_home.window_minutes ? ` in ${c.phone_home.window_minutes < 120 ? `${c.phone_home.window_minutes} min` : `${Math.round(c.phone_home.window_minutes / 60)} h`}` : ""}` : ""}</td>
              </tr>`)}</tbody></table></div>` : o`<div class="empty">No cameras found.</div>`}
          </div>
          <div class="card">
            <h2>Controller</h2>
            <div class="kv">
              <span>Status</span><span>${t.health?.connection_ok === !1 ? o`<span class="badge bad">unreachable</span>` : o`<span class="badge ok">connected</span>`}</span>
              <span>Host</span><span>${t.health?.hostname || "—"}</span>
              <span>Version</span><span>${t.health?.version || "—"}</span>
              <span>Uptime</span><span>${Kt(t.health?.uptime)}</span>
              <span>Wi-Fi / wired</span><span>${t.wireless_count ?? 0} / ${t.wired_count ?? 0}</span>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="row"><h2 style="margin:0">Quantify unknown devices</h2><span class="spacer"></span>
          <button class="btn primary" ?disabled=${this.running} @click=${() => this.runQuantify()}>${this.running ? "Scanning… (a few minutes)" : `Scan ${y(r, "unknown device")}`}</button>
        </div>
        <p class="sub" style="margin:8px 0 0">Probes each unknown device to work out what it is. High-confidence results are applied; the rest become suggestions you can accept.</p>
        ${this.quantify ? this.renderQuantify() : l}
      </div>
    `;
  }
  renderQuantify() {
    const e = this.quantify, t = Object.entries(e.results || {});
    return o`<p class="small">${e.scanned} scanned · ${e.identified} applied · ${e.suggested} suggested</p>
      <div class="scroll"><table>
        <thead><tr><th>Device</th><th>Best guess</th><th>Confidence</th><th>Based on</th><th></th></tr></thead>
        <tbody>${t.map(([a, s]) => o`<tr>
          <td>${s.name || o`<span class="mono">${a}</span>`}<div class="muted small">${s.ip}</div></td>
          <td>${s.best_guess === "unknown" ? o`<span class="muted">still unknown</span>` : o`${s.best_guess}<div class="muted small">${s.best_description}</div>`}</td>
          <td>${s.best_guess === "unknown" ? "—" : s.best_confidence}</td>
          <td class="small">${(s.techniques_used || []).join(", ") || "—"}</td>
          <td>${s.best_guess === "unknown" ? l : s.applied ? o`<span class="badge ok">applied</span> <button class="btn" @click=${() => this.ctx.act("clear_category", { mac: a }, { done: "Undone" })}>Undo</button>` : o`<button class="btn" @click=${() => this.ctx.act("set_category", { mac: a, category: s.best_guess }, { done: `Set to ${s.best_guess}` })}>Accept</button>`}</td>
        </tr>`)}</tbody>
      </table></div>`;
  }
};
F.styles = [k];
dt([
  g({ attribute: !1 })
], F.prototype, "ctx", 2);
dt([
  v()
], F.prototype, "quantify", 2);
dt([
  v()
], F.prototype, "running", 2);
F = dt([
  x("ub-overview")
], F);
var Se = Object.defineProperty, Pe = Object.getOwnPropertyDescriptor, D = (e, t, a, s) => {
  for (var n = s > 1 ? void 0 : s ? Pe(t, a) : t, i = e.length - 1, r; i >= 0; i--)
    (r = e[i]) && (n = (s ? r(t, a, n) : r(n)) || n);
  return s && n && Se(t, a, n), n;
};
const It = [
  ["all", "All", () => !0],
  ["new", "To review", (e) => e.state === "new"],
  ["unknown", "Not identified", (e) => e.category === "unknown" || e.confidence === "low"],
  ["suspicious", "Suspicious", (e) => e.suspicious],
  ["cameras", "Cameras", (e) => e.is_camera],
  ["home", "Home automation", (e) => !!e.home_automation],
  ["contained", "Off the internet", (e) => !!e.containment],
  ["blocked", "Blocked", (e) => e.blocked || e.state === "quarantined"],
  ["trusted", "Trusted", (e) => e.state === "trusted"],
  ["wireless", "Wi-Fi", (e) => !e.wired],
  ["wired", "Wired", (e) => e.wired]
], Ht = (e) => (e.traffic_24h || []).reduce((t, a) => t + a, 0) || (e.tx_bytes || 0) + (e.rx_bytes || 0);
let C = class extends $ {
  constructor() {
    super(...arguments), this.filter = "all", this.q = "", this.category = "", this.sort = "name", this.asc = !0;
  }
  setFilter(e) {
    this.dispatchEvent(new CustomEvent("filter", { detail: e }));
  }
  sortBy(e) {
    this.sort === e ? this.asc = !this.asc : (this.sort = e, this.asc = e !== "traffic");
  }
  rows() {
    const e = It.find((s) => s[0] === this.filter)?.[2] ?? (() => !0), t = this.q.trim().toLowerCase(), a = (s) => {
      switch (this.sort) {
        case "name":
          return m(s).toLowerCase();
        case "category":
          return s.category_label || s.category;
        case "ip":
          return (s.ip || "").split(".").map((n) => n.padStart(3, "0")).join(".");
        case "vendor":
          return (s.vendor || "").toLowerCase();
        case "state":
          return s.state;
        case "traffic":
          return Ht(s);
        case "signal":
          return s.rssi ?? -999;
      }
    };
    return this.ctx.snap.clients.filter(e).filter((s) => !this.category || s.category === this.category).filter((s) => !t || [
      s.mac,
      s.name,
      s.hostname,
      s.ip,
      s.vendor,
      s.essid,
      s.category_label,
      s.state,
      s.home_automation?.brand,
      s.onvif_manufacturer
    ].some((n) => (n || "").toLowerCase().includes(t))).sort((s, n) => {
      const i = a(s), r = a(n), h = typeof i == "number" && typeof r == "number" ? i - r : String(i).localeCompare(String(r));
      return this.asc ? h : -h;
    });
  }
  th(e, t) {
    const a = this.sort === e;
    return o`<th aria-sort=${a ? this.asc ? "ascending" : "descending" : "none"}>
      <button @click=${() => this.sortBy(e)}>${t}${a ? this.asc ? " ▲" : " ▼" : ""}</button></th>`;
  }
  render() {
    const { snap: e } = this.ctx, t = this.rows(), a = e.clients;
    return o`
      <h1>Devices</h1>
      <p class="sub">Everything the controller sees right now. Select a device for details and actions.</p>
      <div class="chips" role="group" aria-label="Filter devices">
        ${It.map(([s, n, i]) => o`<button class="chip" aria-pressed=${this.filter === s ? "true" : "false"} @click=${() => this.setFilter(s)}>${n} ${a.filter(i).length}</button>`)}
      </div>
      <div class="row" style="margin-bottom:12px">
        <input type="search" placeholder="Search name, IP, MAC, maker…" aria-label="Search devices" .value=${this.q} @input=${(s) => this.q = s.target.value} style="flex:1;min-width:200px">
        <select aria-label="Category" @change=${(s) => this.category = s.target.value}>
          <option value="">All categories</option>
          ${ct(e).map(([s, n]) => o`<option value=${s} ?selected=${this.category === s}>${n} (${a.filter((i) => i.category === s).length})</option>`)}
        </select>
      </div>
      ${this.filter === "wireless" ? this.wifiSummary(t) : this.filter === "wired" ? this.wiredSummary(t) : l}
      <div class="card scroll" style="padding:0">
        <table>
          <thead><tr>
            ${this.th("name", "Device")}${this.th("category", "Category")}${this.th("ip", "IP")}${this.th("vendor", "Maker")}
            ${this.th("state", "Status")}<th>Internet</th>${this.th("traffic", "24 h")}${this.filter === "wireless" ? this.th("signal", "Signal") : l}
          </tr></thead>
          <tbody>
            ${t.map((s) => o`<tr class="click" tabindex="0" @click=${() => this.ctx.open(s.mac)} @keydown=${(n) => n.key === "Enter" && this.ctx.open(s.mac)}>
              <td><strong>${m(s)}</strong>${s.suspicious ? o` <span class="badge warn">suspicious</span>` : l}<div class="mono muted">${s.mac}</div></td>
              <td>${s.category_icon} ${s.category_label}${s.confidence === "low" ? o` <span class="muted small">(guess)</span>` : l}</td>
              <td class="mono">${s.ip || "—"}</td>
              <td class="small">${s.home_automation?.brand || s.onvif_manufacturer || s.vendor || "—"}</td>
              <td>${wt(s)}</td>
              <td>${M(s)} ${lt(s)}</td>
              <td>${yt(s.traffic_24h)}${s.traffic_spike ? o` <span class="badge bad">spike</span>` : l}</td>
              ${this.filter === "wireless" ? o`<td class=${(s.rssi ?? 0) < -80 ? "bad" : ""}>${s.rssi != null ? `${s.rssi} dBm` : "—"}</td>` : l}
            </tr>`)}
          </tbody>
        </table>
        ${t.length ? l : o`<div class="empty">No devices match.</div>`}
      </div>
    `;
  }
  wifiSummary(e) {
    const t = (s) => Object.entries(e.reduce((n, i) => ({ ...n, [s(i)]: (n[s(i)] || 0) + 1 }), {})).sort((n, i) => i[1] - n[1]), a = (s) => s == null ? "unknown" : s > -50 ? "excellent" : s > -65 ? "good" : s > -75 ? "fair" : s > -85 ? "weak" : "very weak";
    return o`<div class="grid two">
      <div class="card"><h3>By network</h3>${t((s) => s.essid || "unknown").map(([s, n]) => o`<div class="row small"><span>${s}</span><span class="spacer"></span><span>${n}</span></div>`)}</div>
      <div class="card"><h3>Signal</h3>${t((s) => a(s.rssi)).map(([s, n]) => o`<div class="row small"><span>${s}</span><span class="spacer"></span><span>${n}</span></div>`)}
        <h3>By channel</h3><div class="small">${t((s) => String(s.channel ?? "?")).sort((s, n) => Number(s[0]) - Number(n[0])).map(([s, n]) => o`<span class="badge" style="margin:2px">ch ${s}: ${n}</span>`)}</div></div>
    </div>`;
  }
  wiredSummary(e) {
    return o`<div class="tiles">
      <div class="tile"><div class="n">${e.length}</div><div class="l">wired devices</div></div>
      <div class="tile"><div class="n">${L(e.reduce((t, a) => t + Ht(a), 0))}</div><div class="l">moved in 24 h</div></div>
    </div>`;
  }
};
C.styles = [k];
D([
  g({ attribute: !1 })
], C.prototype, "ctx", 2);
D([
  g()
], C.prototype, "filter", 2);
D([
  v()
], C.prototype, "q", 2);
D([
  v()
], C.prototype, "category", 2);
D([
  v()
], C.prototype, "sort", 2);
D([
  v()
], C.prototype, "asc", 2);
C = D([
  x("ub-devices")
], C);
var Oe = Object.defineProperty, Ee = Object.getOwnPropertyDescriptor, Z = (e, t, a, s) => {
  for (var n = s > 1 ? void 0 : s ? Ee(t, a) : t, i = e.length - 1, r; i >= 0; i--)
    (r = e[i]) && (n = (s ? r(t, a, n) : r(n)) || n);
  return s && n && Oe(t, a, n), n;
};
let U = class extends $ {
  constructor() {
    super(...arguments), this.scanning = !1, this.newName = "", this.onKey = (e) => e.key === "Escape" && this.close(), this.close = () => this.dispatchEvent(new CustomEvent("close"));
  }
  connectedCallback() {
    super.connectedCallback(), window.addEventListener("keydown", this.onKey);
  }
  disconnectedCallback() {
    super.disconnectedCallback(), window.removeEventListener("keydown", this.onKey);
  }
  firstUpdated() {
    this.renderRoot.querySelector(".close")?.focus();
  }
  async scan() {
    this.scanning = !0, await this.ctx.act("scan_device", { mac: this.client.mac }, { done: "Port scan finished" }), this.scanning = !1;
  }
  render() {
    const e = this.client, { act: t, snap: a } = this.ctx, s = m(e), n = !!a.localnet.assignments?.[e.mac.toLowerCase()], i = [...a.recs.device_recs?.[e.mac.toLowerCase()] || []].sort(_t);
    return o`
      <div class="scrim" @click=${this.close}></div>
      <aside role="dialog" aria-modal="true" aria-label="Device ${s}">
        <header>
          <div style="flex:1;min-width:0">
            <h1>${e.category_icon} ${s}</h1>
            <div class="row small">${wt(e)} ${M(e)} ${lt(e)}
              ${e.suspicious ? o`<span class="badge warn">suspicious · ${e.suspicion_score}</span>` : l}
              <span class="mono muted">${e.mac}</span></div>
          </div>
          <button class="close btn" aria-label="Close" @click=${this.close}>✕</button>
        </header>

        <div class="actions row">
          ${e.state !== "trusted" ? o`<button class="btn" @click=${() => t("trust", { mac: e.mac }, { done: `${s} trusted` })}>Trust</button>` : l}
          ${e.state === "new" ? o`<button class="btn" @click=${() => t("ignore", { mac: e.mac }, { done: `${s} ignored` })}>Ignore</button>` : l}
          ${e.internet_blocked && n ? l : e.internet_blocked ? o`<button class="btn" @click=${() => t("allow_internet", { mac: e.mac }, { confirm: `Let ${s} reach the internet again?`, done: `${s} can reach the internet again` })}>Allow internet again</button>` : o`<button class="btn primary" @click=${() => t("block_internet", { mac: e.mac }, { confirm: `Block ${s} from the internet? It keeps its address and keeps working on your network.`, done: `${s} blocked from the internet` })}>Block internet</button>`}
          ${n ? o`<button class="btn" @click=${() => t("localnet_remove", { mac: e.mac }, { confirm: `Take ${s} off local-only? It gets internet access again.`, done: `${s} is no longer local-only` })}>Remove local-only</button>` : o`<button class="btn" @click=${() => t(
      "localnet_assign",
      { mac: e.mac, category: e.category === "unknown" ? "iot" : e.category },
      { confirm: `Put ${s} on local-only? It gets a ${a.localnet.prefix || "192.168.2"}.x address and is blocked from the internet, but keeps working on your network. It reconnects to pick up the new address.`, done: `${s} is now local-only` }
    )}>Make local-only</button>`}
          ${e.state === "quarantined" || e.blocked ? o`<button class="btn" @click=${() => t("unblock", { mac: e.mac }, { done: `${s} unblocked` })}>Unblock</button>` : o`<button class="btn danger" @click=${() => t("quarantine", { mac: e.mac }, { confirm: `Quarantine ${s}? It's blocked on the controller and can't use the network at all.`, danger: !0, done: `${s} quarantined` })}>Quarantine</button>`}
          <button class="btn" @click=${() => t("reconnect", { mac: e.mac }, { confirm: `Disconnect ${s} so it reconnects?`, done: "Reconnect sent" })}>Reconnect</button>
        </div>

        ${i.length ? o`<section><h2>Recommendations</h2>${i.map((r) => xt(this.ctx, r, e.mac))}</section>` : l}

        <section>
          <h2>Internet</h2>
          ${this.internet(e)}
        </section>

        <section>
          <h2>Summary</h2>
          <div class="kv">
            <span>IP</span><span class="mono">${e.ip ? o`<a href="http://${e.ip}" target="_blank" rel="noopener noreferrer">${e.ip}</a>` : "—"}</span>
            <span>Maker</span><span>${e.vendor || "—"}</span>
            ${e.hostname && e.hostname !== e.name ? o`<span>Hostname</span><span>${e.hostname}</span>` : l}
            <span>Connection</span><span>${e.wired ? "wired" : `Wi-Fi${e.essid ? ` · ${e.essid}` : ""}${e.channel ? ` · ch ${e.channel}` : ""}${e.rssi != null ? ` · ${e.rssi} dBm` : ""}`}</span>
            <span>Uptime</span><span>${Kt(e.uptime_seconds)}</span>
            <span>Total traffic</span><span>${L(e.tx_bytes)} / ${L(e.rx_bytes)}</span>
            ${e.unifi_fingerprint ? o`<span>UniFi ID</span><span>category ${e.unifi_fingerprint.dev_cat ?? "?"}${e.unifi_fingerprint.os_name ? `, ${e.unifi_fingerprint.os_name}` : ""}${e.unifi_fingerprint.camera ? o` <span class="badge info">camera</span>` : l}</span>` : l}
            ${e.home_automation ? o`<span>Home</span><span>${e.home_automation.brand || "unknown brand"} · ${e.home_automation.tier_label}</span>` : l}
          </div>
          ${e.home_automation?.local_option ? o`<p class="small" style="margin-top:8px">${e.home_automation.local_option}</p>` : l}
        </section>

        <section>
          <h2>Category</h2>
          <p class="small muted">${e.category_label} · ${e.confidence} confidence · from ${e.source}${e.manual_category ? " (set by hand)" : ""}</p>
          ${e.suggested_category && !e.manual_category ? o`<p class="small">Quantify suggests <strong>${e.suggested_category.category}</strong> (${e.suggested_category.confidence}).
            <button class="btn" @click=${() => t("set_category", { mac: e.mac, category: e.suggested_category.category }, { done: "Category set" })}>Accept</button></p>` : l}
          <div class="row">
            <select aria-label="Category" id="cat">
              ${ct(a).map(([r, h]) => o`<option value=${r} ?selected=${r === e.category}>${h}</option>`)}
            </select>
            <input type="text" placeholder="Rename (optional)" aria-label="New name" .value=${this.newName} @input=${(r) => this.newName = r.target.value}>
            <button class="btn primary" @click=${() => t("set_category", { mac: e.mac, category: this.renderRoot.querySelector("#cat").value, ...this.newName ? { name: this.newName } : {} }, { done: "Saved" })}>Save</button>
            ${e.manual_category ? o`<button class="btn" @click=${() => t("clear_category", { mac: e.mac }, { done: "Back to automatic" })}>Clear override</button>` : l}
          </div>
        </section>

        ${e.vulns || e.onvif?.onvif || e.onvif_manufacturer ? o`<section>
          <h2>Firmware &amp; ONVIF</h2>
          ${e.onvif?.onvif ? o`<p class="small"><span class="badge ok">ONVIF</span> ${e.onvif.manufacturer} ${e.onvif.model}${e.onvif.auth_required ? o` <span class="badge">login needed</span>` : l}</p>` : l}
          <div class="kv">
            ${e.vulns?.family ? o`<span>Firmware by</span><span>${e.vulns.family}</span>` : l}
            <span>Firmware</span><span class="mono">${e.vulns?.firmware || e.onvif_firmware || "not reported"}</span>
            <span>Built</span><span>${e.vulns?.firmware_date ? `${e.vulns.firmware_date} (${e.vulns.firmware_age_years} years ago)` : "unknown"}</span>
            ${e.onvif_serial ? o`<span>Serial</span><span class="mono">${e.onvif_serial}</span>` : l}
          </div>
          ${(e.vulns?.findings || []).map((r) => o`<div class="rec ${r.status === "check" ? "high" : "critical"}">
            <div class="row"><span class="badge ${r.status === "check" ? "warn" : "bad"}">${r.status === "affected" ? "affected" : r.status === "likely" ? "probably affected" : "couldn't check"}</span>
              <span class="t">${r.cve}</span>${r.kev ? o`<span class="badge">exploited (CISA)</span>` : l}</div>
            <div class="d">${r.detail}</div><div class="small muted">${r.source}</div></div>`)}
        </section>` : l}

        <section>
          <div class="row"><h2 style="margin:0">Open ports</h2><span class="spacer"></span>
            <button class="btn" ?disabled=${this.scanning || !e.ip} @click=${() => this.scan()}>${this.scanning ? "Scanning…" : a.scans[e.mac.toLowerCase()] ? "Scan again" : "Scan ports"}</button></div>
          ${this.ports(e)}
        </section>

        ${e.ip_history && e.ip_history.length > 1 ? o`<section><h2>IP history</h2>
          ${e.ip_history.map((r) => o`<div class="mono">${r.ip} <span class="muted">${r.type === "current" ? "now" : `until ${r.until} (${r.type})`}</span></div>`)}</section>` : l}

        ${e.suspicion_flags?.length ? o`<section><h2>Why it's flagged</h2><ul class="small">${e.suspicion_flags.map((r) => o`<li>${r}</li>`)}</ul></section>` : l}
      </aside>
    `;
  }
  internet(e) {
    const t = e.phone_home, a = t?.window_minutes ? t.window_minutes < 120 ? `${t.window_minutes} min` : `${Math.round(t.window_minutes / 60)} h` : "";
    return o`
      <div class="row small" style="margin-bottom:8px">
        ${yt(e.traffic_24h, 5, 32)}
        <span>${e.traffic_24h ? `${L(e.traffic_24h.reduce((s, n) => s + n, 0))} in the last 24 h` : "No traffic history yet"}</span>
        ${e.traffic_spike ? o`<span class="badge bad">spike: ${L(e.traffic_spike.last_hour_bytes)} last hour</span>` : l}
      </div>
      ${t ? o`
        <p>${M(e)} ${y(t.attempts, "connection attempt")}${a ? ` in ${a}` : ""}, ${t.allowed ? o`<strong>${t.allowed} let through</strong>` : "all blocked"}${t.blocked_by_our_rule ? ` (${t.blocked_by_our_rule} by its local-only rule)` : ""}.</p>
        ${Object.keys(t.clouds).length ? o`<p class="small">Calls home to: <strong>${Object.keys(t.clouds).join(", ")}</strong></p>` : l}
        ${t.port_sweep ? o`<p class="small"><span class="badge warn">probing</span> tried ${t.port_sweep.ports} ports on ${t.port_sweep.host}</p>` : l}
        ${Object.keys(t.dns_bypass).length ? o`<p class="small"><span class="badge warn">own DNS</span> ${Object.keys(t.dns_bypass).join(", ")}</p>` : l}
        <div class="scroll"><table class="small"><thead><tr><th>Tries to reach</th><th>Port</th><th>Country</th><th>Times</th></tr></thead>
          <tbody>${t.top_destinations.map((s) => o`<tr><td class="mono">${s.host}</td><td>${s.port ?? s.protocol}</td><td>${s.region || "—"}</td><td>${s.count}</td></tr>`)}</tbody></table></div>` : e.containment ? o`<p>${M(e)} No connection attempts logged.</p>` : e.is_camera || e.home_automation?.tier === "cloud" || e.home_automation?.tier === "cloud_local" ? o`<p class="small muted">UniFi only logs blocked connections, so what this device reaches on the internet isn't visible. Block its internet to see what it tries.</p>` : l}
      ${e.security_events_24h ? o`<p class="small"><span class="badge warn">${y(e.security_events_24h, "security event")}</span> in UniFi's log today.</p>` : l}
    `;
  }
  ports(e) {
    const t = this.ctx.snap.scans[e.mac.toLowerCase()];
    return !t || t.status !== "complete" ? o`<p class="small muted">Not scanned yet.</p>` : o`
      <p class="small">${t.guess_description || ""} <span class="muted">(${t.guess_category}, ${t.guess_confidence} confidence${t.scan_time ? `, ${new Date(t.scan_time * 1e3).toLocaleDateString()}` : ""})</span></p>
      ${t.port_details?.length ? o`<div class="row">${t.port_details.map((a) => o`<span class="badge ${/insecure|backdoor|xmeye/.test(a.group) ? "bad" : /cloud/.test(a.group) ? "warn" : ""}" title=${a.group}>${a.port} ${a.name}</span>`)}</div>` : o`<p class="small muted">No open ports.</p>`}
      ${(t.warnings || []).map((a) => o`<p class="small"><span class="badge bad">!</span> ${a}</p>`)}
    `;
  }
};
U.styles = [k, vt`
    .scrim { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.35); z-index: 5; }
    aside {
      position: fixed; z-index: 6; top: 0; right: 0; bottom: 0; width: min(640px, 100vw); overflow-y: auto;
      background: var(--primary-background-color); box-shadow: -8px 0 30px rgba(0, 0, 0, 0.25); padding: 20px; box-sizing: border-box;
    }
    header { display: flex; gap: 12px; align-items: flex-start; margin-bottom: 12px; }
    h1 { font-size: 20px; word-break: break-word; }
    .actions { margin-bottom: 16px; }
    section { background: var(--ub-card); border: 1px solid var(--ha-card-border-color, var(--ub-line)); border-radius: var(--ub-radius); padding: 14px; margin-bottom: 12px; }
    a { color: var(--primary-color); }
  `];
Z([
  g({ attribute: !1 })
], U.prototype, "ctx", 2);
Z([
  g({ attribute: !1 })
], U.prototype, "client", 2);
Z([
  v()
], U.prototype, "scanning", 2);
Z([
  v()
], U.prototype, "newName", 2);
U = Z([
  x("ub-device-detail")
], U);
var Ne = Object.defineProperty, Me = Object.getOwnPropertyDescriptor, Xt = (e, t, a, s) => {
  for (var n = s > 1 ? void 0 : s ? Me(t, a) : t, i = e.length - 1, r; i >= 0; i--)
    (r = e[i]) && (n = (s ? r(t, a, n) : r(n)) || n);
  return s && n && Ne(t, a, n), n;
};
let at = class extends $ {
  render() {
    const { snap: e } = this.ctx, t = e.clients.filter((n) => n.is_camera).sort((n, i) => +!i.containment - +!n.containment || m(n).localeCompare(m(i))), a = t.filter((n) => !n.containment), s = e.overview.hotspots || [];
    return o`
      <h1>Cameras</h1>
      <p class="sub">Each camera's containment, what it tries to reach, and whether its firmware has known-exploited bugs.</p>
      <div class="tiles">
        <div class="tile ${a.length ? "warn" : "ok"}"><div class="n">${t.length - a.length}/${t.length}</div><div class="l">off the internet</div></div>
        <div class="tile ${t.some((n) => n.containment === "leaking") ? "bad" : ""}"><div class="n">${t.filter((n) => n.containment === "leaking").length}</div><div class="l">not contained</div></div>
        <div class="tile"><div class="n">${t.reduce((n, i) => n + (i.phone_home?.attempts || 0), 0)}</div><div class="l">blocked attempts (recent)</div></div>
        <div class="tile ${t.some((n) => n.vulns?.worst === "affected" || n.vulns?.worst === "likely") ? "bad" : ""}"><div class="n">${t.filter((n) => n.vulns?.findings?.length).length}</div><div class="l">firmware warnings</div></div>
      </div>
      ${a.length ? o`<div class="card"><div class="row">
        <span>${y(a.length, "camera")} can still reach the internet.</span><span class="spacer"></span>
        <button class="btn primary" @click=${() => this.containAll(a.map((n) => n.mac))}>Block internet for all ${a.length}</button></div></div>` : l}
      <div class="card scroll" style="padding:0">
        <table>
          <thead><tr><th>Camera</th><th>Internet</th><th>Calls home to</th><th>Firmware</th><th>ONVIF</th><th></th></tr></thead>
          <tbody>${t.map((n) => o`<tr>
            <td><button class="linkish" @click=${() => this.ctx.open(n.mac)}><strong>${m(n)}</strong></button><div class="muted small">${n.ip} · ${n.vulns?.family || n.onvif_manufacturer || n.vendor}</div></td>
            <td>${M(n)}${n.phone_home ? o`<div class="small muted">${y(n.phone_home.attempts, "attempt")}${n.phone_home.allowed ? `, ${n.phone_home.allowed} through` : ", all blocked"}</div>` : l}
              ${n.phone_home?.port_sweep ? o`<div class="small"><span class="badge warn">probing ${n.phone_home.port_sweep.ports} ports</span></div>` : l}</td>
            <td class="small">${n.phone_home ? Object.keys(n.phone_home.clouds).join(", ") || Object.keys(n.phone_home.regions).join(", ") || "—" : o`<span class="muted">not visible</span>`}</td>
            <td>${lt(n)}<div class="small muted">${n.vulns?.firmware_date || ""}</div></td>
            <td>${n.onvif?.onvif ? o`<span class="badge ok">yes</span>${n.onvif.auth_required ? o` <span class="small muted">login</span>` : l}` : o`<span class="muted small">—</span>`}</td>
            <td>${n.containment ? l : o`<button class="btn" @click=${() => this.ctx.act("block_internet", { mac: n.mac }, { confirm: `Block ${m(n)} from the internet? It keeps its address, so recording keeps working.`, done: `${m(n)} blocked from the internet` })}>Block internet</button>`}</td>
          </tr>`)}</tbody>
        </table>
        ${t.length ? l : o`<div class="empty">No cameras found yet. Run ONVIF discovery or Quantify from Tools.</div>`}
      </div>
      ${s.length ? o`<div class="card"><h2>Camera Wi-Fi networks</h2>
        <p class="sub">A camera running its own Wi-Fi access point can be reached by anyone nearby, around your firewall. Turn that mode off in the camera's settings.</p>
        <table><thead><tr><th>Network</th><th>Why it's listed</th><th>Signal</th><th>Channel</th><th>Security</th></tr></thead>
        <tbody>${s.map((n) => o`<tr><td>${n.essid || "(hidden)"}<div class="mono muted">${n.bssid}</div></td>
          <td>${n.reason === "own_camera" ? o`<span class="badge bad">your camera ${n.camera_name || n.camera_mac}</span>` : "camera setup name"}</td>
          <td>${n.rssi != null ? `${n.rssi} dBm` : "—"}</td><td>${n.channel ?? "—"}</td><td>${n.security || "open"}</td></tr>`)}</tbody></table></div>` : l}
      <div class="card small muted">
        UniFi only logs blocked connections, so a camera's internet use shows up once it's blocked: every attempt it makes is then blocked and listed. "Not contained" means UniFi logged traffic it let through from a camera that should be cut off. Most UniFi gateways log only blocked connections, though, so a block that isn't working can look the same as a quiet camera: test a new kind of block from a laptop on the same addresses.
      </div>
    `;
  }
  async containAll(e) {
    if (!await this.ctx.confirm(`Block ${y(e.length, "camera")} from the internet? They keep their addresses, so your recorder keeps working.`)) return;
    let a = 0;
    for (const s of e)
      await this.ctx.act("block_internet", { mac: s }, { refresh: !1 }) && a++;
    this.ctx.say(`${y(a, "camera")} blocked from the internet`), this.ctx.reload();
  }
};
at.styles = [k];
Xt([
  g({ attribute: !1 })
], at.prototype, "ctx", 2);
at = Xt([
  x("ub-cameras")
], at);
var Te = Object.defineProperty, Ue = Object.getOwnPropertyDescriptor, Gt = (e, t, a, s) => {
  for (var n = s > 1 ? void 0 : s ? Ue(t, a) : t, i = e.length - 1, r; i >= 0; i--)
    (r = e[i]) && (n = (s ? r(t, a, n) : r(n)) || n);
  return s && n && Te(t, a, n), n;
};
const Lt = [
  { id: "cloud", title: "Cloud only", text: "Only work through the maker's servers. Cutting them off breaks them, so local-only isn't an option; if that worries you, look for a local alternative." },
  { id: "cloud_local", title: "Cloud, with a local option", text: "Ship talking to a cloud but can be controlled locally. Switch Home Assistant to the local route first, then they can go on local-only without breaking." },
  { id: "unknown", title: "Not sure", text: "Home automation devices we can't place yet. Set their category or brand by hand from the device's page." },
  { id: "local", title: "Local", text: "Firmware you control or no cloud at all (ESPHome, WLED, Tasmota, Zigbee coordinators). Nothing to do." }
];
let nt = class extends $ {
  render() {
    const e = this.ctx.snap.clients.filter((a) => a.home_automation), t = (a) => e.filter((s) => s.home_automation.tier === a).sort((s, n) => (s.home_automation.brand || "~").localeCompare(n.home_automation.brand || "~") || m(s).localeCompare(m(n)));
    return o`
      <h1>Home automation</h1>
      <p class="sub">Smart home devices, sorted by how much they depend on someone else's cloud. Cheap cloud-tied gear has the same problems as cheap cameras.</p>
      <div class="tiles">${Lt.map((a) => o`<div class="tile ${a.id === "cloud" && t(a.id).length ? "warn" : ""}"><div class="n">${t(a.id).length}</div><div class="l">${a.title.toLowerCase()}</div></div>`)}</div>
      ${Lt.map((a) => {
      const s = t(a.id);
      return s.length ? o`<div class="card"><h2>${a.title} (${s.length})</h2><p class="sub">${a.text}</p>
          <div class="scroll"><table><thead><tr><th>Device</th><th>Brand</th><th>Internet</th><th>24 h</th>${a.id === "cloud_local" ? o`<th>Local option</th>` : l}</tr></thead>
          <tbody>${s.map((n) => this.row(n, a.id === "cloud_local"))}</tbody></table></div></div>` : l;
    })}
      ${e.length ? l : o`<div class="empty">No home automation devices found.</div>`}
    `;
  }
  row(e, t) {
    const a = e.phone_home;
    return o`<tr class="click" tabindex="0" @click=${() => this.ctx.open(e.mac)} @keydown=${(s) => s.key === "Enter" && this.ctx.open(e.mac)}>
      <td><strong>${m(e)}</strong><div class="muted small">${e.ip}</div></td>
      <td>${e.home_automation.brand || o`<span class="muted">—</span>`}</td>
      <td>${M(e)}${a ? o`<div class="small muted">${a.attempts} attempts${Object.keys(a.clouds).length ? ` to ${Object.keys(a.clouds).join(", ")}` : ""}</div>` : l}</td>
      <td>${yt(e.traffic_24h)}</td>
      ${t ? o`<td class="small">${e.home_automation.local_option}</td>` : l}
    </tr>`;
  }
};
nt.styles = [k];
Gt([
  g({ attribute: !1 })
], nt.prototype, "ctx", 2);
nt = Gt([
  x("ub-home")
], nt);
var Re = Object.defineProperty, De = Object.getOwnPropertyDescriptor, kt = (e, t, a, s) => {
  for (var n = s > 1 ? void 0 : s ? De(t, a) : t, i = e.length - 1, r; i >= 0; i--)
    (r = e[i]) && (n = (s ? r(t, a, n) : r(n)) || n);
  return s && n && Re(t, a, n), n;
};
const je = ["critical", "high", "medium", "low", "info"];
let G = class extends $ {
  constructor() {
    super(...arguments), this.show = /* @__PURE__ */ new Set(["critical", "high", "medium"]);
  }
  toggle(e) {
    const t = new Set(this.show);
    t.has(e) ? t.delete(e) : t.add(e), this.show = t;
  }
  render() {
    const { snap: e } = this.ctx, t = [
      ...(e.recs.network_recs || []).map((i) => ({ r: i })),
      ...Object.entries(e.recs.device_recs || {}).flatMap(([i, r]) => r.map((h) => ({ r: h, mac: i })))
    ].sort((i, r) => _t(i.r, r.r)), a = t.filter((i) => this.show.has(i.r.priority)), s = e.overview.security_events || [], n = e.clients.filter((i) => i.suspicious).sort((i, r) => r.suspicion_score - i.suspicion_score);
    return o`
      <h1>Security</h1>
      <p class="sub">What to fix, most urgent first, plus UniFi's security log and devices that behave oddly.</p>
      <div class="chips" role="group" aria-label="Show priorities">
        ${je.map((i) => o`<button class="chip" aria-pressed=${this.show.has(i) ? "true" : "false"} @click=${() => this.toggle(i)}>${i} ${t.filter((r) => r.r.priority === i).length}</button>`)}
      </div>
      <div class="card">
        <h2>Recommendations (${a.length})</h2>
        ${a.length ? a.slice(0, 80).map((i) => xt(this.ctx, i.r, i.mac)) : o`<div class="empty">Nothing at these levels.</div>`}
        ${a.length > 80 ? o`<p class="small muted">Showing the first 80.</p>` : l}
      </div>
      <div class="grid two">
        <div class="card"><h2>UniFi security log, last 24 h (${s.length})</h2>
          <p class="sub">Blocks made by UniFi Blocker's own local-only rules aren't listed here; they show on each camera as proof the rule works (${e.overview.contained_blocks_24h ?? 0} today).</p>
          ${s.length ? o`<div class="scroll"><table class="small"><thead><tr><th>When</th><th>What</th><th>Rule</th></tr></thead>
            <tbody>${s.map((i) => o`<tr><td class="mono">${i.time ? new Date(i.time).toLocaleString() : "—"}</td><td>${i.msg || i.title || i.key}</td><td>${i.rule || i.catname || "—"}</td></tr>`)}</tbody></table></div>` : o`<div class="empty">Nothing in UniFi's security log.</div>`}
        </div>
        <div class="card"><h2>Suspicious devices (${n.length})</h2>
          ${n.length ? n.slice(0, 20).map((i) => o`<div style="padding:6px 0;border-bottom:1px solid var(--ub-line)">
            <div class="row"><button class="linkish" @click=${() => this.ctx.open(i.mac)}>${m(i)}</button>
              <span class="badge ${i.threat_level === "high" ? "bad" : "warn"}">${i.threat_level} · ${i.suspicion_score}</span><span class="muted small">${i.vendor}</span></div>
            <ul class="small" style="margin:4px 0 0 0;padding-left:18px">${i.suspicion_flags.map((r) => o`<li>${r}</li>`)}</ul></div>`) : o`<div class="empty">No device is acting suspiciously.</div>`}
        </div>
      </div>
    `;
  }
};
G.styles = [k];
kt([
  g({ attribute: !1 })
], G.prototype, "ctx", 2);
kt([
  v()
], G.prototype, "show", 2);
G = kt([
  x("ub-security")
], G);
var Ie = Object.defineProperty, He = Object.getOwnPropertyDescriptor, q = (e, t, a, s) => {
  for (var n = s > 1 ? void 0 : s ? He(t, a) : t, i = e.length - 1, r; i >= 0; i--)
    (r = e[i]) && (n = (s ? r(t, a, n) : r(n)) || n);
  return s && n && Ie(t, a, n), n;
};
function Le(e, t) {
  const [a, s] = t.split("/"), n = Number(s), i = (h) => h.split(".").reduce((c, p) => c * 256 + Number(p), 0);
  if (!a || !(n >= 0 && n <= 32) || a.split(".").length !== 4) return !1;
  const r = n === 0 ? 0 : 2 ** 32 - 2 ** (32 - n);
  return (i(e) & r) >>> 0 === (i(a) & r) >>> 0;
}
let O = class extends $ {
  constructor() {
    super(...arguments), this.ipResult = null, this.ip = "", this.showCandidates = !1, this.cidr = "";
  }
  async checkIp() {
    this.ip.trim() && (this.ipResult = await this.ctx.act("check_ip", { ip: this.ip.trim() }, { refresh: !1 }));
  }
  rangeCard(e) {
    const { snap: t, act: a } = this.ctx, s = t.localnet.range_block;
    if (!s) return l;
    const n = this.cidr || s.cidr || `${e}.0/24`, i = t.clients.filter((h) => h.ip && Le(h.ip, n)), r = i.filter((h) => !h.is_camera && ["nas", "computer", "phone", "tablet", "networking", "crypto", "streaming", "gaming"].includes(h.category));
    return o`<div class="card">
      <h2>Block the whole range</h2>
      <p>Two firewall rules on the gateway cut every address in a range off from the internet, including any device you later give an address in it. New devices get their address from the DHCP pool, so they aren't covered until you reserve one in the range. Time sync (NTP, to any server) stays allowed so camera timestamps and light schedules stay right. Nothing on your own network is affected.</p>
      ${s.supported ? s.enabled ? o`<div class="row"><span class="badge ok">on</span><span class="mono">${s.cidr}</span>
            <span class="small muted">${y(i.length, "device")} online in it${s.ntp_allowed ? ", time sync allowed" : ""}</span><span class="spacer"></span>
            <button class="btn" @click=${() => a("localnet_range_block", { enabled: !1 }, { confirm: `Remove the block on ${s.cidr}? Devices in it get internet access again unless they have their own rule.`, done: "Range block removed" })}>Turn off</button></div>` : o`<div class="row">
            <label class="small" for="cidr">Range</label>
            <input id="cidr" class="mono" style="width:150px" .value=${n} @input=${(h) => this.cidr = h.target.value.trim()}>
            <span class="small muted">${y(i.length, "device")} online in it</span><span class="spacer"></span>
            <button class="btn primary" @click=${() => a(
      "localnet_range_block",
      { enabled: !0, cidr: n },
      { confirm: `Block every address in ${n} from the internet? ${y(i.length, "device")} online now${r.length ? `, including ${r.map(m).join(", ")}` : ""}.`, danger: r.length > 0, done: `${n} blocked from the internet` }
    )}>Block this range</button></div>
          ${r.length ? o`<p class="small"><span class="badge warn">check</span> ${r.map(m).join(", ")} ${r.length === 1 ? "is in this range and probably needs" : "are in this range and probably need"} the internet. Use a smaller range (e.g. ${e}.0/25 covers .0–.127) to leave ${r.length === 1 ? "it" : "them"} out.</p>` : l}` : o`<p><span class="badge warn">not available</span> ${s.reason}</p>`}
    </div>`;
  }
  render() {
    const { snap: e, act: t } = this.ctx, a = e.localnet, s = a.prefix || "192.168.2", n = a.assignments || {}, i = (d) => !!n[d.mac.toLowerCase()], r = {
      blocked: e.clients.filter((d) => d.blocked || d.state === "quarantined"),
      local: e.clients.filter((d) => !(d.blocked || d.state === "quarantined") && i(d)),
      review: e.clients.filter((d) => !(d.blocked || d.state === "quarantined") && !i(d) && d.state === "new"),
      internet: e.clients.filter((d) => !(d.blocked || d.state === "quarantined") && !i(d) && d.state !== "new")
    }, h = a.firewall || {}, c = (h.total_devices || 0) - (h.blocked_count || 0), p = e.clients.filter((d) => !i(d) && d.category !== "unknown" && d.state !== "quarantined" && !d.blocked), u = e.clients.filter((d) => d.category === "nas");
    return o`
      <h1>Network</h1>
      <p class="sub">Who can reach what, and the local-only setup.</p>
      <div class="tiles">
        <div class="tile"><div class="n">${r.internet.length}</div><div class="l">internet access</div></div>
        <div class="tile ok"><div class="n">${r.local.length}</div><div class="l">local-only</div></div>
        <div class="tile"><div class="n">${r.blocked.length}</div><div class="l">blocked</div></div>
        <button class="tile ${r.review.length > 10 ? "warn" : ""}" @click=${() => this.ctx.go("devices", "new")}><div class="n">${r.review.length}</div><div class="l">not reviewed yet</div></button>
      </div>

      ${this.rangeCard(s)}

      <div class="card">
        <h2>Local-only</h2>
        <p>Local-only devices get an address in <span class="mono">${a.subnet || `${s}.0/24`}</span> and a per-device traffic rule on the gateway that blocks them from the internet. They keep working on your network.</p>
        <p class="small muted">Local-only stops internet access, not access to the rest of your LAN: those addresses are on the same network as everything else. Keeping a camera away from your other devices takes a separate VLAN.</p>
        <div class="row" style="margin:8px 0">
          ${h.total_devices ? o`<span class="badge ${c ? "warn" : "ok"}">${h.blocked_count}/${h.total_devices} rules in place</span>` : o`<span class="badge">no devices yet</span>`}
          ${c > 0 ? o`<button class="btn primary" @click=${() => t("localnet_ensure_rule", {}, { done: "Missing rules created" })}>Create ${y(c, "missing rule")}</button>` : l}
        </div>
        ${Object.keys(n).length ? o`<div class="scroll"><table>
          <thead><tr><th>Device</th><th>Address</th><th>Category</th><th>Internet</th><th></th></tr></thead>
          <tbody>${Object.entries(n).map(([d, f]) => {
      const b = e.clients.find((j) => j.mac.toLowerCase() === d);
      return o`<tr><td>${b ? o`<button class="linkish" @click=${() => this.ctx.open(d)}>${m(b)}</button>` : o`${f.name || d} <span class="muted small">(offline)</span>`}</td>
              <td class="mono">${f.ip}</td><td>${f.category}</td>
              <td>${b?.phone_home ? o`<span class="small">${b.phone_home.attempts} attempts blocked</span>` : o`<span class="muted small">—</span>`}</td>
              <td><button class="btn" @click=${() => t("localnet_remove", { mac: d }, { confirm: `Take ${b ? m(b) : d} off local-only? It gets internet access again.`, done: "Removed from local-only" })}>Remove</button></td></tr>`;
    })}</tbody></table></div>` : l}
        <button class="btn" style="margin-top:12px" aria-expanded=${this.showCandidates ? "true" : "false"} @click=${() => this.showCandidates = !this.showCandidates}>${this.showCandidates ? "Hide" : "Add devices"}</button>
        ${this.showCandidates ? o`<div class="scroll" style="margin-top:8px"><table><thead><tr><th>Device</th><th>Category</th><th></th></tr></thead>
          <tbody>${p.slice(0, 60).map((d) => o`<tr><td>${m(d)}<div class="muted small">${d.ip} · ${d.vendor}</div></td><td>${d.category_label}</td>
            <td><button class="btn" @click=${() => t("localnet_assign", { mac: d.mac, category: d.category }, { confirm: `Put ${m(d)} on local-only?`, done: `${m(d)} is now local-only` })}>Make local-only</button></td></tr>`)}</tbody></table></div>` : l}
        ${(a.ranges || []).length ? o`<details style="margin-top:12px"><summary class="small">Address ranges by category</summary>
          <table class="small"><thead><tr><th>Category</th><th>Range</th><th>Used</th></tr></thead>
          <tbody>${(a.ranges || []).map((d) => o`<tr><td>${Object.fromEntries(ct(e))[d.category] || d.category}</td><td class="mono">${d.range}</td><td>${d.used}/${d.total}</td></tr>`)}</tbody></table></details>` : l}
      </div>

      <div class="grid two">
        <div class="card">
          <h2>Is this address free?</h2>
          <p class="sub">Checks clients, offline devices, UniFi devices, reservations and local-only assignments before you hand an address out.</p>
          <div class="row"><input type="text" placeholder="${s}.35" aria-label="IP address" .value=${this.ip} @input=${(d) => this.ip = d.target.value} @keydown=${(d) => d.key === "Enter" && this.checkIp()}>
            <button class="btn primary" @click=${() => this.checkIp()}>Check</button></div>
          ${this.ipResult ? o`<p style="margin-top:10px"><strong>${this.ipResult.summary}</strong></p>
            <table class="small"><tbody>${(this.ipResult.checks || []).map((d) => o`<tr><td>${d.icon}</td><td>${d.check}</td><td>${d.result}</td></tr>`)}</tbody></table>` : l}
        </div>
        <div class="card">
          <h2>Storage (${u.length})</h2>
          ${u.length ? o`<table class="small"><tbody>${u.map((d) => o`<tr class="click" @click=${() => this.ctx.open(d.mac)}><td>${m(d)}</td><td class="mono">${d.ip}</td><td>${d.vendor}</td><td>${wt(d)}</td></tr>`)}</tbody></table>
            <p class="small muted" style="margin-top:8px">A NAS should stay on your main network with internet for updates and cloud backup. Don't put it on local-only.</p>` : o`<div class="empty">No NAS found.</div>`}
        </div>
      </div>
    `;
  }
};
O.styles = [k];
q([
  g({ attribute: !1 })
], O.prototype, "ctx", 2);
q([
  v()
], O.prototype, "ipResult", 2);
q([
  v()
], O.prototype, "ip", 2);
q([
  v()
], O.prototype, "showCandidates", 2);
q([
  v()
], O.prototype, "cidr", 2);
O = q([
  x("ub-network")
], O);
var Be = Object.defineProperty, ze = Object.getOwnPropertyDescriptor, Jt = (e, t, a, s) => {
  for (var n = s > 1 ? void 0 : s ? ze(t, a) : t, i = e.length - 1, r; i >= 0; i--)
    (r = e[i]) && (n = (s ? r(t, a, n) : r(n)) || n);
  return s && n && Be(t, a, n), n;
};
let it = class extends $ {
  render() {
    const { rigs: e, summary: t } = this.ctx.snap.miners, a = t.profit_usd_day ?? 0;
    return o`
      <h1>Mining</h1>
      <p class="sub">Crypto miners found on the network, with live profitability at $${(t.electricity_usd_per_kwh ?? 0.08).toFixed(3)}/kWh.</p>
      <div class="tiles">
        <div class="tile"><div class="n">${t.rig_count ?? 0}</div><div class="l">rigs</div></div>
        <div class="tile"><div class="n">${t.reachable ?? 0}/${t.rig_count ?? 0}</div><div class="l">answering</div></div>
        <div class="tile"><div class="n">${Dt(t.total_hashrate_hs)}</div><div class="l">hashrate</div></div>
        <div class="tile"><div class="n">${Math.round(t.total_power_w ?? 0)} W</div><div class="l">power</div></div>
        <div class="tile"><div class="n">${I(t.revenue_usd_day)}</div><div class="l">revenue / day</div></div>
        <div class="tile"><div class="n">${I(t.cost_usd_day)}</div><div class="l">power cost / day</div></div>
        <div class="tile ${a > 0 ? "ok" : a < 0 ? "bad" : ""}"><div class="n">${I(a)}</div><div class="l">profit / day</div></div>
      </div>
      ${e.length ? o`<div class="card scroll" style="padding:0"><table>
        <thead><tr><th>Rig</th><th>Model</th><th>Coin</th><th>Hashrate</th><th>Temp</th><th>Power</th><th>Revenue</th><th>Cost</th><th>Profit</th></tr></thead>
        <tbody>${e.map((s) => o`<tr>
          <td class="mono"><a href="http://${s.ip}" target="_blank" rel="noopener noreferrer" style="color:var(--primary-color)">${s.ip}</a></td>
          <td>${s.model || "—"}${s.reachable ? o` <span class="badge info">${s.source || "api"}</span>` : o` <span class="badge warn">no API</span>`}</td>
          <td>${s.coin || "—"}</td><td>${s.hashrate_display || Dt(s.hashrate_hs)}</td>
          <td>${s.extras?.temp_c != null ? `${s.extras.temp_c} °C` : "—"}</td>
          <td>${s.power_w != null ? `${Math.round(s.power_w)} W${s.power_source === "rated" ? " (rated)" : ""}` : "—"}</td>
          <td>${I(s.revenue_usd_day)}</td><td>${I(s.cost_usd_day)}</td>
          <td class=${(s.profit_usd_day ?? 0) < 0 ? "bad" : ""}>${I(s.profit_usd_day)}</td>
        </tr>`)}</tbody></table></div>` : o`<div class="card empty">No miners found. They're picked up from port scans (CGMiner API on 4028) and known miner makers' MAC addresses.</div>`}
      ${(t.revenue_usd_day ?? 0) === 0 && e.length ? o`<p class="small muted">Revenue shows $0 when coin prices can't be fetched (minerstat.com now needs an API key).</p>` : l}
    `;
  }
};
it.styles = [k];
Jt([
  g({ attribute: !1 })
], it.prototype, "ctx", 2);
it = Jt([
  x("ub-mining")
], it);
var Fe = Object.defineProperty, qe = Object.getOwnPropertyDescriptor, Y = (e, t, a, s) => {
  for (var n = s > 1 ? void 0 : s ? qe(t, a) : t, i = e.length - 1, r; i >= 0; i--)
    (r = e[i]) && (n = (s ? r(t, a, n) : r(n)) || n);
  return s && n && Fe(t, a, n), n;
};
const Ve = [
  [34567, "XMEye / Xiongmai", "DVR protocol; these phone home to Xiongmai's cloud", "bad"],
  [34568, "XMEye media", "XMEye video stream", "bad"],
  [9530, "Dahua debug", "debug service on older Dahua firmware", "bad"],
  ["6789, 32100, 19000", "P2P relays", "camera cloud relays (P2P)", "bad"],
  [554, "RTSP", "camera video stream (local use is fine)", ""],
  [8e3, "Hikvision SDK", "Hikvision management, also used by other things", ""],
  [37777, "Dahua TCP", "Dahua NVR/DVR protocol", ""],
  [23, "Telnet", "unencrypted remote shell; Mirai's way in", "warn"],
  [21, "FTP", "unencrypted file transfer", "warn"],
  [445, "SMB", "file sharing; lateral movement", "warn"],
  [1900, "UPnP", "can open ports on your router by itself", "warn"]
];
let R = class extends $ {
  constructor() {
    super(...arguments), this.preview = null, this.discovering = !1, this.debug = null;
  }
  async discover() {
    this.discovering = !0;
    const e = await this.ctx.act("onvif_discover", {}, { refresh: !0 });
    this.discovering = !1, e && this.ctx.say(`ONVIF discovery found ${e.count ?? 0} camera${e.count === 1 ? "" : "s"}`);
  }
  async showDebug(e) {
    const t = await this.ctx.act(e, {}, { refresh: !1 });
    t && (this.debug = JSON.stringify(t, null, 2));
  }
  render() {
    const { snap: e, act: t } = this.ctx, a = e.report, s = e.learned, n = ct(e), i = s ? [
      ...Object.entries(s.vendor_rules || {}).map(([r, h]) => ["vendor", r, `maker contains “${r}”`, h]),
      ...Object.entries(s.hostname_rules || {}).map(([r, h]) => ["hostname", r, `name starts “${r}”`, h]),
      ...Object.entries(s.mac_rules || {}).map(([r, h]) => ["mac", r, `MAC starts ${r}`, h]),
      ...(s.port_rules || []).map((r) => ["port", r.ports.join(","), `ports ${r.ports.join(", ")}`, r.category])
    ] : [];
    return o`
      <h1>Tools</h1>
      <p class="sub">Scans, learned rules, and settings for the usage report.</p>
      <div class="grid two">
        <div class="card">
          <h2>Find cameras</h2>
          <p class="sub">ONVIF discovery runs at startup and every 6 hours. Run it now after adding a camera. Quantify (on Overview) deep-scans everything still unknown.</p>
          <div class="row"><button class="btn primary" ?disabled=${this.discovering} @click=${() => this.discover()}>${this.discovering ? "Looking…" : "Run ONVIF discovery"}</button>
            <button class="btn" @click=${() => this.ctx.go("overview")}>Quantify…</button></div>
        </div>

        <div class="card">
          <h2>Help improve UniFi Blocker</h2>
          ${a ? o`
            <p>Off unless you turn it on. Once a day it sends counts and versions so problems on other networks can be found: device counts by category, which tools get used, poll times, API errors, warnings logged. <strong>Never</strong> MAC or IP addresses, names, vendor strings from your network, or entity ids, and the whole report is refused if anything like that is in it.</p>
            <div class="row">
              ${a.enabled ? o`<span class="badge ok">on</span><span class="small muted">${a.last_day ? `last sent ${a.last_day}` : "nothing sent yet"}</span>` : o`<span class="badge">off</span>`}
              <span class="spacer"></span>
              ${a.enabled ? o`<button class="btn" @click=${() => t("report_set", { enabled: !1 }, { done: "Usage report off" })}>Turn off</button>
                       <button class="btn" @click=${async () => {
      const r = await t("report_send", {}, { refresh: !0 });
      r && this.ctx.say(r.sent ? `Report sent (${r.bytes} bytes)` : `Not sent: ${r.reason}`, !r.sent);
    }}>Send now</button>
                       <button class="btn" @click=${() => t("report_new_id", {}, { confirm: "Replace the anonymous ID? Reports after this count as a new install.", done: "New ID made" })}>New ID</button>` : o`<button class="btn primary" @click=${() => t("report_set", { enabled: !0 }, { done: "Usage report on" })}>Turn on</button>`}
              <button class="btn" @click=${async () => this.preview = await t("report_preview", {}, { refresh: !1 })}>Preview</button>
            </div>
            ${this.preview ? o`<p class="small" style="margin-top:8px">${this.preview.bytes} bytes to ${this.preview.url}${this.preview.problems?.length ? o` · <span class="badge bad">would be refused: ${this.preview.problems.join("; ")}</span>` : l}</p>
              <pre class="mono" style="max-height:300px;overflow:auto;white-space:pre-wrap">${JSON.stringify(this.preview.payload, null, 2)}</pre>` : l}
          ` : o`<p class="muted">Not available.</p>`}
        </div>
      </div>

      <div class="card">
        <h2>Learned rules (${i.length})</h2>
        <p class="sub">Picked up when you set a device's category by hand, and used for devices nothing else identifies. Fix or delete wrong ones.</p>
        ${i.length ? o`<div class="scroll"><table><thead><tr><th>Rule</th><th>Category</th><th></th></tr></thead>
          <tbody>${i.map(([r, h, c, p]) => o`<tr><td>${c}</td>
            <td><select aria-label="Category for ${c}" @change=${(u) => t("learned_rule_update", { kind: r, key: h, category: u.target.value }, { done: "Rule updated" })}>
              ${n.map(([u, d]) => o`<option value=${u} ?selected=${u === p}>${d}</option>`)}</select></td>
            <td><button class="btn" @click=${() => t("learned_rule_update", { kind: r, key: h, category: null }, { confirm: `Delete the rule “${c}”?`, done: "Rule deleted" })}>Delete</button></td></tr>`)}</tbody></table></div>` : o`<div class="empty">No learned rules yet.</div>`}
      </div>

      <div class="card">
        <h2>Port reference</h2>
        <table class="small"><thead><tr><th>Port</th><th>What</th><th>Why it matters</th></tr></thead>
          <tbody>${Ve.map(([r, h, c, p]) => o`<tr><td class="mono">${r}</td><td>${p ? o`<span class="badge ${p}">${h}</span>` : h}</td><td>${c}</td></tr>`)}</tbody></table>
      </div>

      <details class="card"><summary>Troubleshooting</summary>
        <div class="row" style="margin-top:8px"><button class="btn" @click=${() => this.showDebug("traffic_rules_debug")}>Show traffic rules</button>
          <button class="btn" @click=${() => this.showDebug("firewall_rules_debug")}>Show firewall rules</button></div>
        ${this.debug ? o`<pre class="mono" style="max-height:400px;overflow:auto;white-space:pre-wrap">${this.debug}</pre>` : l}
      </details>
    `;
  }
};
R.styles = [k];
Y([
  g({ attribute: !1 })
], R.prototype, "ctx", 2);
Y([
  v()
], R.prototype, "preview", 2);
Y([
  v()
], R.prototype, "discovering", 2);
Y([
  v()
], R.prototype, "debug", 2);
R = Y([
  x("ub-tools")
], R);
var We = Object.defineProperty, Qe = Object.getOwnPropertyDescriptor, A = (e, t, a, s) => {
  for (var n = s > 1 ? void 0 : s ? Qe(t, a) : t, i = e.length - 1, r; i >= 0; i--)
    (r = e[i]) && (n = (s ? r(t, a, n) : r(n)) || n);
  return s && n && We(t, a, n), n;
};
const Ke = "0.3.61", Bt = [
  { id: "overview", label: "Overview", icon: "M12 3 2 12h3v8h6v-6h2v6h6v-8h3z" },
  { id: "devices", label: "Devices", icon: "M4 6h16v10H4zM2 18h20v2H2z" },
  { id: "cameras", label: "Cameras", icon: "M17 10.5V7a1 1 0 0 0-1-1H4a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-3.5l4 4v-11z" },
  { id: "home", label: "Home", icon: "M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z" },
  { id: "security", label: "Security", icon: "M12 1 3 5v6c0 5.6 3.8 10.7 9 12 5.2-1.3 9-6.4 9-12V5z" },
  { id: "network", label: "Network", icon: "M17 16l-4-4V8.8a3 3 0 1 0-2 0V12l-4 4H3v5h5v-3.1l4-4.1 4 4.1V21h5v-5z" },
  { id: "mining", label: "Mining", icon: "M14.8 2.2 13.4 3.6l7 7 1.4-1.4zM12 5 2 15l7 7 10-10z" },
  { id: "tools", label: "Tools", icon: "M22.7 19 13.6 9.9a6.4 6.4 0 0 0-8.4-8.4l4.3 4.3-3 3-4.4-4.3a6.4 6.4 0 0 0 8.4 8.4l9.1 9.1z" }
];
let w = class extends $ {
  constructor() {
    super(...arguments), this.narrow = !1, this.view = "overview", this.snap = {
      overview: {},
      clients: [],
      recs: {},
      localnet: {},
      miners: { rigs: [], summary: {} },
      scans: {},
      report: null,
      learned: null,
      loaded: !1,
      error: "",
      updated: 0
    }, this.toast = null, this.ask = null, this.openMac = null, this.devicesFilter = "all", this.lastReportedView = "", this.onVisibility = () => {
      document.visibilityState === "visible" ? this.schedule(0) : window.clearTimeout(this.timer);
    }, this.act = async (e, t = {}, a = {}) => {
      if (a.confirm && !await this.confirm(a.confirm, a.danger)) return null;
      try {
        const s = await _(this.hass, e, t);
        if (s && s.ok === !1) throw new pt("failed", s.error || "The controller refused it");
        return a.done && this.say(a.done), a.refresh !== !1 && this.schedule(800), s ?? {};
      } catch (s) {
        return this.say(s instanceof pt ? s.message : String(s), !0), null;
      }
    }, this.say = (e, t = !1) => {
      this.toast = { text: e, bad: t }, window.clearTimeout(this.toastTimer), this.toastTimer = window.setTimeout(() => this.toast = null, t ? 8e3 : 4e3);
    }, this.confirm = (e, t = !1) => new Promise((a) => this.ask = { text: e, danger: t, resolve: a }), this.openDevice = (e) => this.openMac = e.toLowerCase(), this.go = (e, t) => {
      this.view = e, t && (this.devicesFilter = t), this.renderRoot.querySelector("main")?.scrollTo?.(0, 0);
    };
  }
  connectedCallback() {
    super.connectedCallback();
    const e = new URLSearchParams(location.search).get("view");
    e && Bt.some((t) => t.id === e) && (this.view = e), document.addEventListener("visibilitychange", this.onVisibility), this.schedule(0);
  }
  disconnectedCallback() {
    super.disconnectedCallback(), document.removeEventListener("visibilitychange", this.onVisibility), window.clearTimeout(this.timer);
  }
  schedule(e) {
    window.clearTimeout(this.timer), this.timer = window.setTimeout(() => this.load(), e);
  }
  async load() {
    if (!this.hass) return this.schedule(500);
    try {
      this.snap = await _e(this.hass);
    } catch (e) {
      this.snap = { ...this.snap, error: e?.message ?? String(e) };
    }
    document.visibilityState === "visible" && this.schedule(3e4);
  }
  updated() {
    this.snap.report?.enabled && this.view !== this.lastReportedView && (this.lastReportedView = this.view, _(this.hass, "report_view", { view: this.view }).catch(() => {
    }));
  }
  ctxObj() {
    return {
      hass: this.hass,
      snap: this.snap,
      act: this.act,
      open: this.openDevice,
      go: this.go,
      say: this.say,
      confirm: this.confirm,
      reload: () => this.schedule(800)
    };
  }
  answer(e) {
    this.ask?.resolve(e), this.ask = null;
  }
  renderView() {
    const e = this.ctxObj();
    switch (this.view) {
      case "overview":
        return o`<ub-overview .ctx=${e}></ub-overview>`;
      case "devices":
        return o`<ub-devices .ctx=${e} .filter=${this.devicesFilter} @filter=${(t) => this.devicesFilter = t.detail}></ub-devices>`;
      case "cameras":
        return o`<ub-cameras .ctx=${e}></ub-cameras>`;
      case "home":
        return o`<ub-home .ctx=${e}></ub-home>`;
      case "security":
        return o`<ub-security .ctx=${e}></ub-security>`;
      case "network":
        return o`<ub-network .ctx=${e}></ub-network>`;
      case "mining":
        return o`<ub-mining .ctx=${e}></ub-mining>`;
      case "tools":
        return o`<ub-tools .ctx=${e}></ub-tools>`;
    }
  }
  render() {
    const e = this.snap.overview, t = this.snap.clients.filter((n) => n.containment === "leaking").length, a = this.snap.recs.critical_count || 0, s = this.openMac ? this.snap.clients.find((n) => n.mac.toLowerCase() === this.openMac) : void 0;
    return o`
      <div class="toolbar">
        ${this.narrow ? o`<ha-menu-button .hass=${this.hass} .narrow=${this.narrow}></ha-menu-button>` : l}
        <div class="title">UniFi Blocker</div>
        <span class="status ${e.health?.connection_ok === !1 ? "bad" : ""}" title="Controller">
          ${this.snap.loaded ? e.health?.connection_ok === !1 ? "Controller unreachable" : `${e.health?.hostname || "Controller"} · ${e.total_clients ?? 0} devices` : "Loading…"}
        </span>
        <button class="icon" aria-label="Refresh" title="Refresh" @click=${() => this.load()}>
          <svg viewBox="0 0 24 24" width="22" height="22"><path fill="currentColor" d="M17.65 6.35A8 8 0 1 0 19.7 14h-2.1a6 6 0 1 1-1.4-6.2L13 11h7V4z"/></svg>
        </button>
      </div>
      <nav aria-label="UniFi Blocker sections">
        ${Bt.map((n) => o`
          <button class="tab" aria-current=${this.view === n.id ? "page" : "false"} @click=${() => this.go(n.id)}>
            <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true"><path fill="currentColor" d=${n.icon}/></svg>
            <span>${n.label}</span>
            ${n.id === "security" && a ? o`<span class="dot" aria-label="${a} critical">${a}</span>` : l}
            ${n.id === "cameras" && t ? o`<span class="dot" aria-label="${t} not contained">${t}</span>` : l}
            ${n.id === "devices" && (e.new_count || 0) > 0 ? o`<span class="dot soft">${e.new_count}</span>` : l}
          </button>`)}
      </nav>
      <main>
        ${this.snap.error ? o`<div class="card error" role="alert">Couldn't load data: ${this.snap.error}</div>` : l}
        ${this.renderView()}
        <footer class="muted small">UniFi Blocker ${Ke}${this.snap.updated ? o` · updated ${new Date(this.snap.updated).toLocaleTimeString()}` : l}</footer>
      </main>
      ${s ? o`<ub-device-detail .ctx=${this.ctxObj()} .client=${s} @close=${() => this.openMac = null}></ub-device-detail>` : l}
      ${this.ask ? o`
        <div class="scrim" @click=${() => this.answer(!1)}></div>
        <div class="dialog" role="alertdialog" aria-modal="true" aria-label="Confirm">
          <p>${this.ask.text}</p>
          <div class="row"><span class="spacer"></span>
            <button class="btn" @click=${() => this.answer(!1)}>Cancel</button>
            <button class="btn ${this.ask.danger ? "danger" : "primary"}" @click=${() => this.answer(!0)}>Continue</button>
          </div>
        </div>` : l}
      ${this.toast ? o`<div class="toast ${this.toast.bad ? "bad" : ""}" role="status">${this.toast.text}</div>` : l}
    `;
  }
};
w.styles = [k, vt`
    :host { display: flex; flex-direction: column; height: 100%; background: var(--primary-background-color); }
    .toolbar {
      display: flex; align-items: center; gap: 8px; height: var(--header-height, 56px); padding: 0 12px 0 16px;
      background: var(--app-header-background-color, var(--primary-color)); color: var(--app-header-text-color, #fff);
      box-sizing: border-box; flex-shrink: 0;
    }
    .title { font-size: 20px; flex: 1; }
    .status { font-size: 13px; opacity: 0.9; }
    .status.bad { font-weight: 600; }
    button.icon { all: unset; cursor: pointer; padding: 8px; border-radius: 50%; display: flex; }
    button.icon:focus-visible { outline: 2px solid currentColor; }
    nav {
      display: flex; gap: 2px; padding: 0 8px; overflow-x: auto; flex-shrink: 0;
      background: var(--app-header-background-color, var(--primary-color)); color: var(--app-header-text-color, #fff);
    }
    .tab {
      all: unset; display: flex; align-items: center; gap: 6px; padding: 10px 14px; cursor: pointer; white-space: nowrap;
      border-bottom: 3px solid transparent; opacity: 0.8; font-size: 14px; position: relative;
    }
    .tab[aria-current="page"] { opacity: 1; border-bottom-color: currentColor; }
    .tab:hover, .tab:focus-visible { opacity: 1; }
    .tab:focus-visible { outline: 2px solid currentColor; outline-offset: -2px; }
    .dot { background: var(--error-color, #db4437); color: #fff; border-radius: 10px; font-size: 11px; padding: 0 6px; line-height: 16px; }
    .dot.soft { background: rgba(255, 255, 255, 0.25); }
    main { flex: 1; overflow-y: auto; padding: 16px; box-sizing: border-box; }
    @media (min-width: 900px) { main { padding: 24px; } }
    main > * { max-width: 1400px; margin-left: auto; margin-right: auto; display: block; }
    footer { text-align: center; padding: 12px 0 4px; }
    .card.error { border-color: var(--error-color); }
    .scrim { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.4); z-index: 10; }
    .dialog {
      position: fixed; z-index: 11; left: 50%; top: 30%; transform: translate(-50%, -30%); width: min(440px, 90vw);
      background: var(--ub-card); border-radius: var(--ub-radius); padding: 20px; box-shadow: 0 8px 30px rgba(0, 0, 0, 0.3);
    }
    .toast {
      position: fixed; z-index: 12; left: 50%; bottom: 24px; transform: translateX(-50%); max-width: min(560px, 90vw);
      background: var(--primary-text-color); color: var(--primary-background-color); padding: 10px 16px; border-radius: 8px;
      font-size: 14px; box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
    }
    .toast.bad { background: var(--error-color, #db4437); color: #fff; }
  `];
A([
  g({ attribute: !1 })
], w.prototype, "hass", 2);
A([
  g({ type: Boolean })
], w.prototype, "narrow", 2);
A([
  v()
], w.prototype, "view", 2);
A([
  v()
], w.prototype, "snap", 2);
A([
  v()
], w.prototype, "toast", 2);
A([
  v()
], w.prototype, "ask", 2);
A([
  v()
], w.prototype, "openMac", 2);
A([
  v()
], w.prototype, "devicesFilter", 2);
w = A([
  x("unifiblocker-panel")
], w);
export {
  w as UniFiBlockerPanel,
  Ke as VERSION
};
