/**
 * @license
 * Copyright 2019 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const et = globalThis, vt = et.ShadowRoot && (et.ShadyCSS === void 0 || et.ShadyCSS.nativeShadow) && "adoptedStyleSheets" in Document.prototype && "replace" in CSSStyleSheet.prototype, $t = Symbol(), Pt = /* @__PURE__ */ new WeakMap();
let Wt = class {
  constructor(e, a, s) {
    if (this._$cssResult$ = !0, s !== $t) throw Error("CSSResult is not constructable. Use `unsafeCSS` or `css` instead.");
    this.cssText = e, this.t = a;
  }
  get styleSheet() {
    let e = this.o;
    const a = this.t;
    if (vt && e === void 0) {
      const s = a !== void 0 && a.length === 1;
      s && (e = Pt.get(a)), e === void 0 && ((this.o = e = new CSSStyleSheet()).replaceSync(this.cssText), s && Pt.set(a, e));
    }
    return e;
  }
  toString() {
    return this.cssText;
  }
};
const re = (t) => new Wt(typeof t == "string" ? t : t + "", void 0, $t), gt = (t, ...e) => {
  const a = t.length === 1 ? t[0] : e.reduce((s, i, r) => s + ((o) => {
    if (o._$cssResult$ === !0) return o.cssText;
    if (typeof o == "number") return o;
    throw Error("Value passed to 'css' function must be a 'css' function result: " + o + ". Use 'unsafeCSS' to pass non-literal values, but take care to ensure page security.");
  })(i) + t[r + 1], t[0]);
  return new Wt(a, t, $t);
}, oe = (t, e) => {
  if (vt) t.adoptedStyleSheets = e.map((a) => a instanceof CSSStyleSheet ? a : a.styleSheet);
  else for (const a of e) {
    const s = document.createElement("style"), i = et.litNonce;
    i !== void 0 && s.setAttribute("nonce", i), s.textContent = a.cssText, t.appendChild(s);
  }
}, Et = vt ? (t) => t : (t) => t instanceof CSSStyleSheet ? ((e) => {
  let a = "";
  for (const s of e.cssRules) a += s.cssText;
  return re(a);
})(t) : t;
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const { is: le, defineProperty: ce, getOwnPropertyDescriptor: de, getOwnPropertyNames: he, getOwnPropertySymbols: pe, getPrototypeOf: ue } = Object, ot = globalThis, Ot = ot.trustedTypes, me = Ot ? Ot.emptyScript : "", be = ot.reactiveElementPolyfillSupport, K = (t, e) => t, st = { toAttribute(t, e) {
  switch (e) {
    case Boolean:
      t = t ? me : null;
      break;
    case Object:
    case Array:
      t = t == null ? t : JSON.stringify(t);
  }
  return t;
}, fromAttribute(t, e) {
  let a = t;
  switch (e) {
    case Boolean:
      a = t !== null;
      break;
    case Number:
      a = t === null ? null : Number(t);
      break;
    case Object:
    case Array:
      try {
        a = JSON.parse(t);
      } catch {
        a = null;
      }
  }
  return a;
} }, ft = (t, e) => !le(t, e), Tt = { attribute: !0, type: String, converter: st, reflect: !1, useDefault: !1, hasChanged: ft };
Symbol.metadata ??= Symbol("metadata"), ot.litPropertyMetadata ??= /* @__PURE__ */ new WeakMap();
let L = class extends HTMLElement {
  static addInitializer(e) {
    this._$Ei(), (this.l ??= []).push(e);
  }
  static get observedAttributes() {
    return this.finalize(), this._$Eh && [...this._$Eh.keys()];
  }
  static createProperty(e, a = Tt) {
    if (a.state && (a.attribute = !1), this._$Ei(), this.prototype.hasOwnProperty(e) && ((a = Object.create(a)).wrapped = !0), this.elementProperties.set(e, a), !a.noAccessor) {
      const s = Symbol(), i = this.getPropertyDescriptor(e, s, a);
      i !== void 0 && ce(this.prototype, e, i);
    }
  }
  static getPropertyDescriptor(e, a, s) {
    const { get: i, set: r } = de(this.prototype, e) ?? { get() {
      return this[a];
    }, set(o) {
      this[a] = o;
    } };
    return { get: i, set(o) {
      const h = i?.call(this);
      r?.call(this, o), this.requestUpdate(e, h, s);
    }, configurable: !0, enumerable: !0 };
  }
  static getPropertyOptions(e) {
    return this.elementProperties.get(e) ?? Tt;
  }
  static _$Ei() {
    if (this.hasOwnProperty(K("elementProperties"))) return;
    const e = ue(this);
    e.finalize(), e.l !== void 0 && (this.l = [...e.l]), this.elementProperties = new Map(e.elementProperties);
  }
  static finalize() {
    if (this.hasOwnProperty(K("finalized"))) return;
    if (this.finalized = !0, this._$Ei(), this.hasOwnProperty(K("properties"))) {
      const a = this.properties, s = [...he(a), ...pe(a)];
      for (const i of s) this.createProperty(i, a[i]);
    }
    const e = this[Symbol.metadata];
    if (e !== null) {
      const a = litPropertyMetadata.get(e);
      if (a !== void 0) for (const [s, i] of a) this.elementProperties.set(s, i);
    }
    this._$Eh = /* @__PURE__ */ new Map();
    for (const [a, s] of this.elementProperties) {
      const i = this._$Eu(a, s);
      i !== void 0 && this._$Eh.set(i, a);
    }
    this.elementStyles = this.finalizeStyles(this.styles);
  }
  static finalizeStyles(e) {
    const a = [];
    if (Array.isArray(e)) {
      const s = new Set(e.flat(1 / 0).reverse());
      for (const i of s) a.unshift(Et(i));
    } else e !== void 0 && a.push(Et(e));
    return a;
  }
  static _$Eu(e, a) {
    const s = a.attribute;
    return s === !1 ? void 0 : typeof s == "string" ? s : typeof e == "string" ? e.toLowerCase() : void 0;
  }
  constructor() {
    super(), this._$Ep = void 0, this.isUpdatePending = !1, this.hasUpdated = !1, this._$Em = null, this._$Ev();
  }
  _$Ev() {
    this._$ES = new Promise((e) => this.enableUpdating = e), this._$AL = /* @__PURE__ */ new Map(), this._$E_(), this.requestUpdate(), this.constructor.l?.forEach((e) => e(this));
  }
  addController(e) {
    (this._$EO ??= /* @__PURE__ */ new Set()).add(e), this.renderRoot !== void 0 && this.isConnected && e.hostConnected?.();
  }
  removeController(e) {
    this._$EO?.delete(e);
  }
  _$E_() {
    const e = /* @__PURE__ */ new Map(), a = this.constructor.elementProperties;
    for (const s of a.keys()) this.hasOwnProperty(s) && (e.set(s, this[s]), delete this[s]);
    e.size > 0 && (this._$Ep = e);
  }
  createRenderRoot() {
    const e = this.shadowRoot ?? this.attachShadow(this.constructor.shadowRootOptions);
    return oe(e, this.constructor.elementStyles), e;
  }
  connectedCallback() {
    this.renderRoot ??= this.createRenderRoot(), this.enableUpdating(!0), this._$EO?.forEach((e) => e.hostConnected?.());
  }
  enableUpdating(e) {
  }
  disconnectedCallback() {
    this._$EO?.forEach((e) => e.hostDisconnected?.());
  }
  attributeChangedCallback(e, a, s) {
    this._$AK(e, s);
  }
  _$ET(e, a) {
    const s = this.constructor.elementProperties.get(e), i = this.constructor._$Eu(e, s);
    if (i !== void 0 && s.reflect === !0) {
      const r = (s.converter?.toAttribute !== void 0 ? s.converter : st).toAttribute(a, s.type);
      this._$Em = e, r == null ? this.removeAttribute(i) : this.setAttribute(i, r), this._$Em = null;
    }
  }
  _$AK(e, a) {
    const s = this.constructor, i = s._$Eh.get(e);
    if (i !== void 0 && this._$Em !== i) {
      const r = s.getPropertyOptions(i), o = typeof r.converter == "function" ? { fromAttribute: r.converter } : r.converter?.fromAttribute !== void 0 ? r.converter : st;
      this._$Em = i;
      const h = o.fromAttribute(a, r.type);
      this[i] = h ?? this._$Ej?.get(i) ?? h, this._$Em = null;
    }
  }
  requestUpdate(e, a, s, i = !1, r) {
    if (e !== void 0) {
      const o = this.constructor;
      if (i === !1 && (r = this[e]), s ??= o.getPropertyOptions(e), !((s.hasChanged ?? ft)(r, a) || s.useDefault && s.reflect && r === this._$Ej?.get(e) && !this.hasAttribute(o._$Eu(e, s)))) return;
      this.C(e, a, s);
    }
    this.isUpdatePending === !1 && (this._$ES = this._$EP());
  }
  C(e, a, { useDefault: s, reflect: i, wrapped: r }, o) {
    s && !(this._$Ej ??= /* @__PURE__ */ new Map()).has(e) && (this._$Ej.set(e, o ?? a ?? this[e]), r !== !0 || o !== void 0) || (this._$AL.has(e) || (this.hasUpdated || s || (a = void 0), this._$AL.set(e, a)), i === !0 && this._$Em !== e && (this._$Eq ??= /* @__PURE__ */ new Set()).add(e));
  }
  async _$EP() {
    this.isUpdatePending = !0;
    try {
      await this._$ES;
    } catch (a) {
      Promise.reject(a);
    }
    const e = this.scheduleUpdate();
    return e != null && await e, !this.isUpdatePending;
  }
  scheduleUpdate() {
    return this.performUpdate();
  }
  performUpdate() {
    if (!this.isUpdatePending) return;
    if (!this.hasUpdated) {
      if (this.renderRoot ??= this.createRenderRoot(), this._$Ep) {
        for (const [i, r] of this._$Ep) this[i] = r;
        this._$Ep = void 0;
      }
      const s = this.constructor.elementProperties;
      if (s.size > 0) for (const [i, r] of s) {
        const { wrapped: o } = r, h = this[i];
        o !== !0 || this._$AL.has(i) || h === void 0 || this.C(i, void 0, r, h);
      }
    }
    let e = !1;
    const a = this._$AL;
    try {
      e = this.shouldUpdate(a), e ? (this.willUpdate(a), this._$EO?.forEach((s) => s.hostUpdate?.()), this.update(a)) : this._$EM();
    } catch (s) {
      throw e = !1, this._$EM(), s;
    }
    e && this._$AE(a);
  }
  willUpdate(e) {
  }
  _$AE(e) {
    this._$EO?.forEach((a) => a.hostUpdated?.()), this.hasUpdated || (this.hasUpdated = !0, this.firstUpdated(e)), this.updated(e);
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
  shouldUpdate(e) {
    return !0;
  }
  update(e) {
    this._$Eq &&= this._$Eq.forEach((a) => this._$ET(a, this[a])), this._$EM();
  }
  updated(e) {
  }
  firstUpdated(e) {
  }
};
L.elementStyles = [], L.shadowRootOptions = { mode: "open" }, L[K("elementProperties")] = /* @__PURE__ */ new Map(), L[K("finalized")] = /* @__PURE__ */ new Map(), be?.({ ReactiveElement: L }), (ot.reactiveElementVersions ??= []).push("2.1.2");
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const yt = globalThis, Nt = (t) => t, at = yt.trustedTypes, Dt = at ? at.createPolicy("lit-html", { createHTML: (t) => t }) : void 0, Xt = "$lit$", E = `lit$${Math.random().toFixed(9).slice(2)}$`, Kt = "?" + E, ve = `<${Kt}>`, M = document, Q = () => M.createComment(""), G = (t) => t === null || typeof t != "object" && typeof t != "function", wt = Array.isArray, $e = (t) => wt(t) || typeof t?.[Symbol.iterator] == "function", ut = `[ 	
\f\r]`, X = /<(?:(!--|\/[^a-zA-Z])|(\/?[a-zA-Z][^>\s]*)|(\/?$))/g, Mt = /-->/g, Ut = />/g, N = RegExp(`>|${ut}(?:([^\\s"'>=/]+)(${ut}*=${ut}*(?:[^ 	
\f\r"'\`<>=]|("|')|))|$)`, "g"), Rt = /'/g, jt = /"/g, Qt = /^(?:script|style|textarea|title)$/i, Gt = (t) => (e, ...a) => ({ _$litType$: t, strings: e, values: a }), n = Gt(1), ge = Gt(2), z = Symbol.for("lit-noChange"), l = Symbol.for("lit-nothing"), Ht = /* @__PURE__ */ new WeakMap(), D = M.createTreeWalker(M, 129);
function Yt(t, e) {
  if (!wt(t) || !t.hasOwnProperty("raw")) throw Error("invalid template strings array");
  return Dt !== void 0 ? Dt.createHTML(e) : e;
}
const fe = (t, e) => {
  const a = t.length - 1, s = [];
  let i, r = e === 2 ? "<svg>" : e === 3 ? "<math>" : "", o = X;
  for (let h = 0; h < a; h++) {
    const c = t[h];
    let p, u, d = -1, f = 0;
    for (; f < c.length && (o.lastIndex = f, u = o.exec(c), u !== null); ) f = o.lastIndex, o === X ? u[1] === "!--" ? o = Mt : u[1] !== void 0 ? o = Ut : u[2] !== void 0 ? (Qt.test(u[2]) && (i = RegExp("</" + u[2], "g")), o = N) : u[3] !== void 0 && (o = N) : o === N ? u[0] === ">" ? (o = i ?? X, d = -1) : u[1] === void 0 ? d = -2 : (d = o.lastIndex - u[2].length, p = u[1], o = u[3] === void 0 ? N : u[3] === '"' ? jt : Rt) : o === jt || o === Rt ? o = N : o === Mt || o === Ut ? o = X : (o = N, i = void 0);
    const v = o === N && t[h + 1].startsWith("/>") ? " " : "";
    r += o === X ? c + ve : d >= 0 ? (s.push(p), c.slice(0, d) + Xt + c.slice(d) + E + v) : c + E + (d === -2 ? h : v);
  }
  return [Yt(t, r + (t[a] || "<?>") + (e === 2 ? "</svg>" : e === 3 ? "</math>" : "")), s];
};
class Y {
  constructor({ strings: e, _$litType$: a }, s) {
    let i;
    this.parts = [];
    let r = 0, o = 0;
    const h = e.length - 1, c = this.parts, [p, u] = fe(e, a);
    if (this.el = Y.createElement(p, s), D.currentNode = this.el.content, a === 2 || a === 3) {
      const d = this.el.content.firstChild;
      d.replaceWith(...d.childNodes);
    }
    for (; (i = D.nextNode()) !== null && c.length < h; ) {
      if (i.nodeType === 1) {
        if (i.hasAttributes()) for (const d of i.getAttributeNames()) if (d.endsWith(Xt)) {
          const f = u[o++], v = i.getAttribute(d).split(E), H = /([.?@])?(.*)/.exec(f);
          c.push({ type: 1, index: r, name: H[2], strings: v, ctor: H[1] === "." ? we : H[1] === "?" ? _e : H[1] === "@" ? ke : lt }), i.removeAttribute(d);
        } else d.startsWith(E) && (c.push({ type: 6, index: r }), i.removeAttribute(d));
        if (Qt.test(i.tagName)) {
          const d = i.textContent.split(E), f = d.length - 1;
          if (f > 0) {
            i.textContent = at ? at.emptyScript : "";
            for (let v = 0; v < f; v++) i.append(d[v], Q()), D.nextNode(), c.push({ type: 2, index: ++r });
            i.append(d[f], Q());
          }
        }
      } else if (i.nodeType === 8) if (i.data === Kt) c.push({ type: 2, index: r });
      else {
        let d = -1;
        for (; (d = i.data.indexOf(E, d + 1)) !== -1; ) c.push({ type: 7, index: r }), d += E.length - 1;
      }
      r++;
    }
  }
  static createElement(e, a) {
    const s = M.createElement("template");
    return s.innerHTML = e, s;
  }
}
function q(t, e, a = t, s) {
  if (e === z) return e;
  let i = s !== void 0 ? a._$Co?.[s] : a._$Cl;
  const r = G(e) ? void 0 : e._$litDirective$;
  return i?.constructor !== r && (i?._$AO?.(!1), r === void 0 ? i = void 0 : (i = new r(t), i._$AT(t, a, s)), s !== void 0 ? (a._$Co ??= [])[s] = i : a._$Cl = i), i !== void 0 && (e = q(t, i._$AS(t, e.values), i, s)), e;
}
class ye {
  constructor(e, a) {
    this._$AV = [], this._$AN = void 0, this._$AD = e, this._$AM = a;
  }
  get parentNode() {
    return this._$AM.parentNode;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  u(e) {
    const { el: { content: a }, parts: s } = this._$AD, i = (e?.creationScope ?? M).importNode(a, !0);
    D.currentNode = i;
    let r = D.nextNode(), o = 0, h = 0, c = s[0];
    for (; c !== void 0; ) {
      if (o === c.index) {
        let p;
        c.type === 2 ? p = new Z(r, r.nextSibling, this, e) : c.type === 1 ? p = new c.ctor(r, c.name, c.strings, this, e) : c.type === 6 && (p = new xe(r, this, e)), this._$AV.push(p), c = s[++h];
      }
      o !== c?.index && (r = D.nextNode(), o++);
    }
    return D.currentNode = M, i;
  }
  p(e) {
    let a = 0;
    for (const s of this._$AV) s !== void 0 && (s.strings !== void 0 ? (s._$AI(e, s, a), a += s.strings.length - 2) : s._$AI(e[a])), a++;
  }
}
class Z {
  get _$AU() {
    return this._$AM?._$AU ?? this._$Cv;
  }
  constructor(e, a, s, i) {
    this.type = 2, this._$AH = l, this._$AN = void 0, this._$AA = e, this._$AB = a, this._$AM = s, this.options = i, this._$Cv = i?.isConnected ?? !0;
  }
  get parentNode() {
    let e = this._$AA.parentNode;
    const a = this._$AM;
    return a !== void 0 && e?.nodeType === 11 && (e = a.parentNode), e;
  }
  get startNode() {
    return this._$AA;
  }
  get endNode() {
    return this._$AB;
  }
  _$AI(e, a = this) {
    e = q(this, e, a), G(e) ? e === l || e == null || e === "" ? (this._$AH !== l && this._$AR(), this._$AH = l) : e !== this._$AH && e !== z && this._(e) : e._$litType$ !== void 0 ? this.$(e) : e.nodeType !== void 0 ? this.T(e) : $e(e) ? this.k(e) : this._(e);
  }
  O(e) {
    return this._$AA.parentNode.insertBefore(e, this._$AB);
  }
  T(e) {
    this._$AH !== e && (this._$AR(), this._$AH = this.O(e));
  }
  _(e) {
    this._$AH !== l && G(this._$AH) ? this._$AA.nextSibling.data = e : this.T(M.createTextNode(e)), this._$AH = e;
  }
  $(e) {
    const { values: a, _$litType$: s } = e, i = typeof s == "number" ? this._$AC(e) : (s.el === void 0 && (s.el = Y.createElement(Yt(s.h, s.h[0]), this.options)), s);
    if (this._$AH?._$AD === i) this._$AH.p(a);
    else {
      const r = new ye(i, this), o = r.u(this.options);
      r.p(a), this.T(o), this._$AH = r;
    }
  }
  _$AC(e) {
    let a = Ht.get(e.strings);
    return a === void 0 && Ht.set(e.strings, a = new Y(e)), a;
  }
  k(e) {
    wt(this._$AH) || (this._$AH = [], this._$AR());
    const a = this._$AH;
    let s, i = 0;
    for (const r of e) i === a.length ? a.push(s = new Z(this.O(Q()), this.O(Q()), this, this.options)) : s = a[i], s._$AI(r), i++;
    i < a.length && (this._$AR(s && s._$AB.nextSibling, i), a.length = i);
  }
  _$AR(e = this._$AA.nextSibling, a) {
    for (this._$AP?.(!1, !0, a); e !== this._$AB; ) {
      const s = Nt(e).nextSibling;
      Nt(e).remove(), e = s;
    }
  }
  setConnected(e) {
    this._$AM === void 0 && (this._$Cv = e, this._$AP?.(e));
  }
}
class lt {
  get tagName() {
    return this.element.tagName;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  constructor(e, a, s, i, r) {
    this.type = 1, this._$AH = l, this._$AN = void 0, this.element = e, this.name = a, this._$AM = i, this.options = r, s.length > 2 || s[0] !== "" || s[1] !== "" ? (this._$AH = Array(s.length - 1).fill(new String()), this.strings = s) : this._$AH = l;
  }
  _$AI(e, a = this, s, i) {
    const r = this.strings;
    let o = !1;
    if (r === void 0) e = q(this, e, a, 0), o = !G(e) || e !== this._$AH && e !== z, o && (this._$AH = e);
    else {
      const h = e;
      let c, p;
      for (e = r[0], c = 0; c < r.length - 1; c++) p = q(this, h[s + c], a, c), p === z && (p = this._$AH[c]), o ||= !G(p) || p !== this._$AH[c], p === l ? e = l : e !== l && (e += (p ?? "") + r[c + 1]), this._$AH[c] = p;
    }
    o && !i && this.j(e);
  }
  j(e) {
    e === l ? this.element.removeAttribute(this.name) : this.element.setAttribute(this.name, e ?? "");
  }
}
class we extends lt {
  constructor() {
    super(...arguments), this.type = 3;
  }
  j(e) {
    this.element[this.name] = e === l ? void 0 : e;
  }
}
class _e extends lt {
  constructor() {
    super(...arguments), this.type = 4;
  }
  j(e) {
    this.element.toggleAttribute(this.name, !!e && e !== l);
  }
}
class ke extends lt {
  constructor(e, a, s, i, r) {
    super(e, a, s, i, r), this.type = 5;
  }
  _$AI(e, a = this) {
    if ((e = q(this, e, a, 0) ?? l) === z) return;
    const s = this._$AH, i = e === l && s !== l || e.capture !== s.capture || e.once !== s.once || e.passive !== s.passive, r = e !== l && (s === l || i);
    i && this.element.removeEventListener(this.name, this, s), r && this.element.addEventListener(this.name, this, e), this._$AH = e;
  }
  handleEvent(e) {
    typeof this._$AH == "function" ? this._$AH.call(this.options?.host ?? this.element, e) : this._$AH.handleEvent(e);
  }
}
class xe {
  constructor(e, a, s) {
    this.element = e, this.type = 6, this._$AN = void 0, this._$AM = a, this.options = s;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  _$AI(e) {
    q(this, e);
  }
}
const Ae = yt.litHtmlPolyfillSupport;
Ae?.(Y, Z), (yt.litHtmlVersions ??= []).push("3.3.3");
const Ce = (t, e, a) => {
  const s = a?.renderBefore ?? e;
  let i = s._$litPart$;
  if (i === void 0) {
    const r = a?.renderBefore ?? null;
    s._$litPart$ = i = new Z(e.insertBefore(Q(), r), r, void 0, a ?? {});
  }
  return i._$AI(t), i;
};
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const _t = globalThis;
class $ extends L {
  constructor() {
    super(...arguments), this.renderOptions = { host: this }, this._$Do = void 0;
  }
  createRenderRoot() {
    const e = super.createRenderRoot();
    return this.renderOptions.renderBefore ??= e.firstChild, e;
  }
  update(e) {
    const a = this.render();
    this.hasUpdated || (this.renderOptions.isConnected = this.isConnected), super.update(e), this._$Do = Ce(a, this.renderRoot, this.renderOptions);
  }
  connectedCallback() {
    super.connectedCallback(), this._$Do?.setConnected(!0);
  }
  disconnectedCallback() {
    super.disconnectedCallback(), this._$Do?.setConnected(!1);
  }
  render() {
    return z;
  }
}
$._$litElement$ = !0, $.finalized = !0, _t.litElementHydrateSupport?.({ LitElement: $ });
const Se = _t.litElementPolyfillSupport;
Se?.({ LitElement: $ });
(_t.litElementVersions ??= []).push("4.2.2");
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const k = (t) => (e, a) => {
  a !== void 0 ? a.addInitializer(() => {
    customElements.define(t, e);
  }) : customElements.define(t, e);
};
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const Pe = { attribute: !0, type: String, converter: st, reflect: !1, hasChanged: ft }, Ee = (t = Pe, e, a) => {
  const { kind: s, metadata: i } = a;
  let r = globalThis.litPropertyMetadata.get(i);
  if (r === void 0 && globalThis.litPropertyMetadata.set(i, r = /* @__PURE__ */ new Map()), s === "setter" && ((t = Object.create(t)).wrapped = !0), r.set(a.name, t), s === "accessor") {
    const { name: o } = a;
    return { set(h) {
      const c = e.get.call(this);
      e.set.call(this, h), this.requestUpdate(o, c, t, !0, h);
    }, init(h) {
      return h !== void 0 && this.C(o, void 0, t, h), h;
    } };
  }
  if (s === "setter") {
    const { name: o } = a;
    return function(h) {
      const c = this[o];
      e.call(this, h), this.requestUpdate(o, c, t, !0, h);
    };
  }
  throw Error("Unsupported decorator location: " + s);
};
function g(t) {
  return (e, a) => typeof a == "object" ? Ee(t, e, a) : ((s, i, r) => {
    const o = i.hasOwnProperty(r);
    return i.constructor.createProperty(r, s), o ? Object.getOwnPropertyDescriptor(i, r) : void 0;
  })(t, e, a);
}
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
function m(t) {
  return g({ ...t, state: !0, attribute: !1 });
}
class bt extends Error {
  constructor(e, a) {
    super(a), this.code = e;
  }
}
async function _(t, e, a = {}) {
  try {
    return await t.callWS({ type: `unifiblocker/${e}`, ...a });
  } catch (s) {
    throw new bt(s?.code ?? "error", s?.message ?? String(s));
  }
}
async function C(t, e) {
  try {
    return await t;
  } catch {
    return e;
  }
}
async function Oe(t) {
  const [e, a, s, i, r, o, h, c, p] = await Promise.all([
    C(_(t, "overview"), {}),
    C(_(t, "clients"), { clients: [] }),
    C(_(t, "recommendations"), {}),
    C(_(t, "localnet_status"), {}),
    C(_(t, "miners"), { rigs: [], summary: {} }),
    C(_(t, "scan_results"), { results: {} }),
    C(_(t, "report_status"), null),
    C(_(t, "learned_rules"), null),
    C(_(t, "licence_status"), { pro: !1, has_key: !1 })
  ]);
  return {
    overview: e,
    clients: a.clients || [],
    recs: s,
    localnet: i,
    miners: r,
    scans: o.results || {},
    report: h,
    learned: c,
    licence: p,
    loaded: !0,
    error: "",
    updated: Date.now()
  };
}
const x = gt`
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
  button.btn:hover, button.btn:focus-visible, a.btn:hover, a.btn:focus-visible { border-color: var(--primary-color); outline: none; }
  button.btn.primary, a.btn.primary { background: var(--primary-color); border-color: var(--primary-color); color: var(--text-primary-color, #fff); }
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
  input[type="search"], input[type="text"], input[type="email"], select {
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
function I(t) {
  if (!t) return "0 B";
  const e = ["B", "KB", "MB", "GB", "TB"];
  let a = 0, s = t;
  for (; s >= 1e3 && a < e.length - 1; )
    s /= 1e3, a++;
  return `${s >= 100 || a === 0 ? Math.round(s) : s.toFixed(1)} ${e[a]}`;
}
function y(t, e, a = `${e}s`) {
  return `${t} ${t === 1 ? e : a}`;
}
function Jt(t) {
  if (!t) return "—";
  const e = Math.floor(t / 86400), a = Math.floor(t % 86400 / 3600), s = Math.floor(t % 3600 / 60);
  return e ? `${e}d ${a}h` : a ? `${a}h ${s}m` : `${s}m`;
}
function Bt(t) {
  if (!t) return "—";
  const e = ["H/s", "kH/s", "MH/s", "GH/s", "TH/s", "PH/s"];
  let a = 0, s = t;
  for (; s >= 1e3 && a < e.length - 1; )
    s /= 1e3, a++;
  return `${s.toFixed(s >= 100 ? 0 : 1)} ${e[a]}`;
}
const B = (t) => t == null ? "—" : `$${t.toFixed(2)}`;
function b(t) {
  return t.name || t.hostname || t.mac;
}
function kt(t, e = 3, a = 22) {
  if (!t || !t.length) return l;
  const s = Math.max(...t, 1), i = t.reduce((r, o) => r + o, 0);
  return n`<svg width=${t.length * (e + 1)} height=${a} role="img"
    aria-label="Traffic per hour over 24 hours, ${I(i)} total" style="vertical-align:middle;color:var(--primary-color)">
    ${t.map((r, o) => {
    const h = Math.max(1, Math.round(a * r / s));
    return ge`<rect x=${o * (e + 1)} y=${a - h} width=${e} height=${h} fill="currentColor" opacity=${o === t.length - 1 ? 1 : 0.55}></rect>`;
  })}
  </svg>`;
}
const Te = { new: "warn", trusted: "ok", ignored: "", quarantined: "bad" };
function xt(t) {
  return t.blocked && t.state !== "quarantined" ? n`<span class="badge bad">blocked</span>` : n`<span class="badge ${Te[t.state] ?? ""}">${t.state}</span>`;
}
function O(t) {
  switch (t.containment) {
    case "holding":
      return n`<span class="badge ok">contained</span>`;
    case "quiet":
      return n`<span class="badge ok">contained · quiet</span>`;
    case "leaking":
      return n`<span class="badge bad">NOT contained</span>`;
    default:
      return t.is_camera ? n`<span class="badge warn">internet open</span>` : l;
  }
}
function ct(t) {
  const e = t.vulns?.worst;
  return e === "affected" ? n`<span class="badge bad">exploited bug</span>` : e === "likely" ? n`<span class="badge bad">likely exploited bug</span>` : e === "check" ? n`<span class="badge warn">check firmware</span>` : (t.vulns?.firmware_age_years ?? 0) >= 5 ? n`<span class="badge warn">firmware ${t.vulns.firmware_age_years}y old</span>` : l;
}
function dt(t) {
  const e = t.overview.category_labels || {};
  return Object.entries(e).sort((a, s) => a[1].localeCompare(s[1]));
}
const Lt = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }, At = (t, e) => (Lt[t.priority] ?? 5) - (Lt[e.priority] ?? 5);
function Ne(t, e, a) {
  const s = e.action_data?.mac || a;
  if (!s) return l;
  const i = t.snap.clients.find((o) => o.mac.toLowerCase() === s.toLowerCase()), r = i ? b(i) : s;
  switch (e.action) {
    case "local_only":
      return n`<button class="btn primary" @click=${() => t.act(
        "localnet_assign",
        { mac: s, category: e.action_data?.category || i?.category || "iot" },
        { confirm: `Put ${r} on local-only? It gets a ${t.snap.localnet.prefix || "192.168.2"}.x address and is blocked from the internet. It reconnects to pick up the new address.`, done: `${r} is now local-only` }
      )}>Make local-only</button>`;
    case "block_internet":
      return n`<button class="btn primary" @click=${() => t.act(
        "block_internet",
        { mac: s },
        { confirm: `Block ${r} from the internet? It keeps its address and keeps working on your network.`, done: `${r} blocked from the internet` }
      )}>Block internet</button>`;
    case "quarantine":
      return n`<button class="btn danger" @click=${() => t.act("quarantine", { mac: s }, { confirm: `Quarantine ${r}? It's blocked on the controller and can't use the network at all.`, danger: !0, done: `${r} quarantined` })}>Quarantine</button>`;
    case "review":
      return n`<button class="btn" @click=${() => t.open(s)}>Open device</button>`;
    default:
      return i ? n`<button class="btn" @click=${() => t.open(s)}>Open device</button>` : l;
  }
}
function Ct(t, e, a) {
  const s = a ? t.snap.clients.find((i) => i.mac.toLowerCase() === a.toLowerCase()) : void 0;
  return n`<div class="rec ${e.priority}">
    <div class="row">
      <span class="badge ${e.priority === "critical" ? "bad" : e.priority === "high" ? "warn" : e.priority === "medium" ? "info" : ""}">${e.priority}</span>
      <span class="t">${e.title}</span>
      ${s ? n`<span class="muted small">· ${b(s)}</span>` : l}
    </div>
    <div class="d">${e.detail}</div>
    <div class="row">${Ne(t, e, a)}</div>
  </div>`;
}
function ht(t, e) {
  return n`<p class="small"><span class="badge info">Pro</span> ${e} is part of UniFi Blocker Pro
    (${t.snap.licence.price || "$35 CAD/year"}).
    <button class="linkish" @click=${() => t.go("tools")}>Licence and free trial</button></p>`;
}
var De = Object.defineProperty, Me = Object.getOwnPropertyDescriptor, pt = (t, e, a, s) => {
  for (var i = s > 1 ? void 0 : s ? Me(e, a) : e, r = t.length - 1, o; r >= 0; r--)
    (o = t[r]) && (i = (s ? o(e, a, i) : o(i)) || i);
  return s && i && De(e, a, i), i;
};
let V = class extends $ {
  constructor() {
    super(...arguments), this.quantify = null, this.running = !1;
  }
  async runQuantify() {
    this.running = !0;
    const t = await this.ctx.act("deep_scan_unknowns", {}, { confirm: "Deep-scan every device that's still unknown? It probes each one (web, TLS, SSH, mDNS, NetBIOS) and takes a few minutes." });
    this.running = !1, t && (this.quantify = t);
  }
  render() {
    const { snap: t } = this.ctx;
    if (!t.loaded) return n`<div class="empty">Loading…</div>`;
    const e = t.overview, a = t.clients.filter((c) => c.is_camera), s = a.filter((c) => c.containment === "holding" || c.containment === "quiet").length, i = t.clients.filter((c) => c.containment === "leaking"), r = t.clients.filter((c) => c.vulns?.worst === "affected" || c.vulns?.worst === "likely").length, o = t.clients.filter((c) => c.category === "unknown").length, h = [
      ...(t.recs.network_recs || []).map((c) => ({ r: c })),
      ...Object.entries(t.recs.device_recs || {}).flatMap(([c, p]) => p.map((u) => ({ r: u, mac: c })))
    ].filter((c) => c.r.priority === "critical" || c.r.priority === "high").sort((c, p) => At(c.r, p.r));
    return n`
      <h1>Overview</h1>
      <p class="sub">${e.health?.connection_ok === !1 ? "Can't reach the controller." : `Connected to ${e.health?.hostname || "the controller"}${e.health?.version ? ` (UniFi Network ${e.health.version})` : ""}.`}</p>

      <div class="tiles">
        <button class="tile" @click=${() => this.ctx.go("devices", "all")}><div class="n">${e.total_clients ?? 0}</div><div class="l">devices online</div></button>
        <button class="tile ${e.new_count ? "warn" : ""}" @click=${() => this.ctx.go("devices", "new")}><div class="n">${e.new_count ?? 0}</div><div class="l">waiting for review</div></button>
        <button class="tile ${a.length && s < a.length ? "warn" : "ok"}" @click=${() => this.ctx.go("cameras")}><div class="n">${s}/${a.length}</div><div class="l">cameras contained</div></button>
        <button class="tile ${i.length ? "bad" : ""}" @click=${() => this.ctx.go("cameras")}><div class="n">${i.length}</div><div class="l">not contained</div></button>
        <button class="tile ${r ? "bad" : ""}" @click=${() => this.ctx.go("cameras")}><div class="n">${r}</div><div class="l">with exploited bugs</div></button>
        <button class="tile ${e.threat_events ? "warn" : ""}" @click=${() => this.ctx.go("security")}><div class="n">${e.threat_events ?? 0}</div><div class="l">security events (24 h)</div></button>
        <button class="tile ${e.suspicious_count ? "warn" : ""}" @click=${() => this.ctx.go("devices", "suspicious")}><div class="n">${e.suspicious_count ?? 0}</div><div class="l">suspicious</div></button>
        <button class="tile" @click=${() => this.ctx.go("devices", "unknown")}><div class="n">${o}</div><div class="l">not identified</div></button>
      </div>

      <div class="grid two">
        <div class="card">
          <h2>Needs attention</h2>
          ${h.length ? h.slice(0, 6).map((c) => Ct(this.ctx, c.r, c.mac)) : n`<div class="empty">Nothing critical or high right now.</div>`}
          ${h.length > 6 ? n`<button class="btn" @click=${() => this.ctx.go("security")}>All ${h.length} on the Security page</button>` : l}
        </div>

        <div>
          <div class="card">
            <h2>Cameras</h2>
            ${a.length ? n`<div class="scroll"><table>
              <tbody>${a.map((c) => n`<tr class="click" tabindex="0" @click=${() => this.ctx.open(c.mac)} @keydown=${(p) => p.key === "Enter" && this.ctx.open(c.mac)}>
                <td>${b(c)}<div class="muted small">${c.ip}</div></td>
                <td>${O(c)} ${ct(c)}</td>
                <td class="small muted">${c.phone_home ? `${y(c.phone_home.attempts, "attempt")} blocked${c.phone_home.window_minutes ? ` in ${c.phone_home.window_minutes < 120 ? `${c.phone_home.window_minutes} min` : `${Math.round(c.phone_home.window_minutes / 60)} h`}` : ""}` : ""}</td>
              </tr>`)}</tbody></table></div>` : n`<div class="empty">No cameras found.</div>`}
          </div>
          <div class="card">
            <h2>Controller</h2>
            <div class="kv">
              <span>Status</span><span>${e.health?.connection_ok === !1 ? n`<span class="badge bad">unreachable</span>` : n`<span class="badge ok">connected</span>`}</span>
              <span>Host</span><span>${e.health?.hostname || "—"}</span>
              <span>Version</span><span>${e.health?.version || "—"}</span>
              <span>Uptime</span><span>${Jt(e.health?.uptime)}</span>
              <span>Wi-Fi / wired</span><span>${e.wireless_count ?? 0} / ${e.wired_count ?? 0}</span>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="row"><h2 style="margin:0">Quantify unknown devices</h2><span class="spacer"></span>
          <button class="btn primary" ?disabled=${this.running} @click=${() => this.runQuantify()}>${this.running ? "Scanning… (a few minutes)" : `Scan ${y(o, "unknown device")}`}</button>
        </div>
        <p class="sub" style="margin:8px 0 0">Probes each unknown device to work out what it is. High-confidence results are applied; the rest become suggestions you can accept.</p>
        ${this.quantify ? this.renderQuantify() : l}
      </div>
    `;
  }
  renderQuantify() {
    const t = this.quantify, e = Object.entries(t.results || {});
    return n`<p class="small">${t.scanned} scanned · ${t.identified} applied · ${t.suggested} suggested</p>
      <div class="scroll"><table>
        <thead><tr><th>Device</th><th>Best guess</th><th>Confidence</th><th>Based on</th><th></th></tr></thead>
        <tbody>${e.map(([a, s]) => n`<tr>
          <td>${s.name || n`<span class="mono">${a}</span>`}<div class="muted small">${s.ip}</div></td>
          <td>${s.best_guess === "unknown" ? n`<span class="muted">still unknown</span>` : n`${s.best_guess}<div class="muted small">${s.best_description}</div>`}</td>
          <td>${s.best_guess === "unknown" ? "—" : s.best_confidence}</td>
          <td class="small">${(s.techniques_used || []).join(", ") || "—"}</td>
          <td>${s.best_guess === "unknown" ? l : s.applied ? n`<span class="badge ok">applied</span> <button class="btn" @click=${() => this.ctx.act("clear_category", { mac: a }, { done: "Undone" })}>Undo</button>` : n`<button class="btn" @click=${() => this.ctx.act("set_category", { mac: a, category: s.best_guess }, { done: `Set to ${s.best_guess}` })}>Accept</button>`}</td>
        </tr>`)}</tbody>
      </table></div>`;
  }
};
V.styles = [x];
pt([
  g({ attribute: !1 })
], V.prototype, "ctx", 2);
pt([
  m()
], V.prototype, "quantify", 2);
pt([
  m()
], V.prototype, "running", 2);
V = pt([
  k("ub-overview")
], V);
var Ue = Object.defineProperty, Re = Object.getOwnPropertyDescriptor, R = (t, e, a, s) => {
  for (var i = s > 1 ? void 0 : s ? Re(e, a) : e, r = t.length - 1, o; r >= 0; r--)
    (o = t[r]) && (i = (s ? o(e, a, i) : o(i)) || i);
  return s && i && Ue(e, a, i), i;
};
const It = [
  ["all", "All", () => !0],
  ["new", "To review", (t) => t.state === "new"],
  ["unknown", "Not identified", (t) => t.category === "unknown" || t.confidence === "low"],
  ["suspicious", "Suspicious", (t) => t.suspicious],
  ["cameras", "Cameras", (t) => t.is_camera],
  ["home", "Home automation", (t) => !!t.home_automation],
  ["contained", "Off the internet", (t) => !!t.containment],
  ["blocked", "Blocked", (t) => t.blocked || t.state === "quarantined"],
  ["trusted", "Trusted", (t) => t.state === "trusted"],
  ["wireless", "Wi-Fi", (t) => !t.wired],
  ["wired", "Wired", (t) => t.wired]
], Ft = (t) => (t.traffic_24h || []).reduce((e, a) => e + a, 0) || (t.tx_bytes || 0) + (t.rx_bytes || 0);
let S = class extends $ {
  constructor() {
    super(...arguments), this.filter = "all", this.q = "", this.category = "", this.sort = "name", this.asc = !0;
  }
  setFilter(t) {
    this.dispatchEvent(new CustomEvent("filter", { detail: t }));
  }
  sortBy(t) {
    this.sort === t ? this.asc = !this.asc : (this.sort = t, this.asc = t !== "traffic");
  }
  rows() {
    const t = It.find((s) => s[0] === this.filter)?.[2] ?? (() => !0), e = this.q.trim().toLowerCase(), a = (s) => {
      switch (this.sort) {
        case "name":
          return b(s).toLowerCase();
        case "category":
          return s.category_label || s.category;
        case "ip":
          return (s.ip || "").split(".").map((i) => i.padStart(3, "0")).join(".");
        case "vendor":
          return (s.vendor || "").toLowerCase();
        case "state":
          return s.state;
        case "traffic":
          return Ft(s);
        case "signal":
          return s.rssi ?? -999;
      }
    };
    return this.ctx.snap.clients.filter(t).filter((s) => !this.category || s.category === this.category).filter((s) => !e || [
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
    ].some((i) => (i || "").toLowerCase().includes(e))).sort((s, i) => {
      const r = a(s), o = a(i), h = typeof r == "number" && typeof o == "number" ? r - o : String(r).localeCompare(String(o));
      return this.asc ? h : -h;
    });
  }
  th(t, e) {
    const a = this.sort === t;
    return n`<th aria-sort=${a ? this.asc ? "ascending" : "descending" : "none"}>
      <button @click=${() => this.sortBy(t)}>${e}${a ? this.asc ? " ▲" : " ▼" : ""}</button></th>`;
  }
  render() {
    const { snap: t } = this.ctx, e = this.rows(), a = t.clients;
    return n`
      <h1>Devices</h1>
      <p class="sub">Everything the controller sees right now. Select a device for details and actions.</p>
      <div class="chips" role="group" aria-label="Filter devices">
        ${It.map(([s, i, r]) => n`<button class="chip" aria-pressed=${this.filter === s ? "true" : "false"} @click=${() => this.setFilter(s)}>${i} ${a.filter(r).length}</button>`)}
      </div>
      <div class="row" style="margin-bottom:12px">
        <input type="search" placeholder="Search name, IP, MAC, maker…" aria-label="Search devices" .value=${this.q} @input=${(s) => this.q = s.target.value} style="flex:1;min-width:200px">
        <select aria-label="Category" @change=${(s) => this.category = s.target.value}>
          <option value="">All categories</option>
          ${dt(t).map(([s, i]) => n`<option value=${s} ?selected=${this.category === s}>${i} (${a.filter((r) => r.category === s).length})</option>`)}
        </select>
      </div>
      ${this.filter === "wireless" ? this.wifiSummary(e) : this.filter === "wired" ? this.wiredSummary(e) : l}
      <div class="card scroll" style="padding:0">
        <table>
          <thead><tr>
            ${this.th("name", "Device")}${this.th("category", "Category")}${this.th("ip", "IP")}${this.th("vendor", "Maker")}
            ${this.th("state", "Status")}<th>Internet</th>${this.th("traffic", "24 h")}${this.filter === "wireless" ? this.th("signal", "Signal") : l}
          </tr></thead>
          <tbody>
            ${e.map((s) => n`<tr class="click" tabindex="0" @click=${() => this.ctx.open(s.mac)} @keydown=${(i) => i.key === "Enter" && this.ctx.open(s.mac)}>
              <td><strong>${b(s)}</strong>${s.suspicious ? n` <span class="badge warn">suspicious</span>` : l}<div class="mono muted">${s.mac}</div></td>
              <td>${s.category_icon} ${s.category_label}${s.confidence === "low" ? n` <span class="muted small">(guess)</span>` : l}</td>
              <td class="mono">${s.ip || "—"}</td>
              <td class="small">${s.home_automation?.brand || s.onvif_manufacturer || s.vendor || "—"}</td>
              <td>${xt(s)}</td>
              <td>${O(s)} ${ct(s)}</td>
              <td>${kt(s.traffic_24h)}${s.traffic_spike ? n` <span class="badge bad">spike</span>` : l}</td>
              ${this.filter === "wireless" ? n`<td class=${(s.rssi ?? 0) < -80 ? "bad" : ""}>${s.rssi != null ? `${s.rssi} dBm` : "—"}</td>` : l}
            </tr>`)}
          </tbody>
        </table>
        ${e.length ? l : n`<div class="empty">No devices match.</div>`}
      </div>
    `;
  }
  wifiSummary(t) {
    const e = (s) => Object.entries(t.reduce((i, r) => ({ ...i, [s(r)]: (i[s(r)] || 0) + 1 }), {})).sort((i, r) => r[1] - i[1]), a = (s) => s == null ? "unknown" : s > -50 ? "excellent" : s > -65 ? "good" : s > -75 ? "fair" : s > -85 ? "weak" : "very weak";
    return n`<div class="grid two">
      <div class="card"><h3>By network</h3>${e((s) => s.essid || "unknown").map(([s, i]) => n`<div class="row small"><span>${s}</span><span class="spacer"></span><span>${i}</span></div>`)}</div>
      <div class="card"><h3>Signal</h3>${e((s) => a(s.rssi)).map(([s, i]) => n`<div class="row small"><span>${s}</span><span class="spacer"></span><span>${i}</span></div>`)}
        <h3>By channel</h3><div class="small">${e((s) => String(s.channel ?? "?")).sort((s, i) => Number(s[0]) - Number(i[0])).map(([s, i]) => n`<span class="badge" style="margin:2px">ch ${s}: ${i}</span>`)}</div></div>
    </div>`;
  }
  wiredSummary(t) {
    return n`<div class="tiles">
      <div class="tile"><div class="n">${t.length}</div><div class="l">wired devices</div></div>
      <div class="tile"><div class="n">${I(t.reduce((e, a) => e + Ft(a), 0))}</div><div class="l">moved in 24 h</div></div>
    </div>`;
  }
};
S.styles = [x];
R([
  g({ attribute: !1 })
], S.prototype, "ctx", 2);
R([
  g()
], S.prototype, "filter", 2);
R([
  m()
], S.prototype, "q", 2);
R([
  m()
], S.prototype, "category", 2);
R([
  m()
], S.prototype, "sort", 2);
R([
  m()
], S.prototype, "asc", 2);
S = R([
  k("ub-devices")
], S);
var je = Object.defineProperty, He = Object.getOwnPropertyDescriptor, tt = (t, e, a, s) => {
  for (var i = s > 1 ? void 0 : s ? He(e, a) : e, r = t.length - 1, o; r >= 0; r--)
    (o = t[r]) && (i = (s ? o(e, a, i) : o(i)) || i);
  return s && i && je(e, a, i), i;
};
let U = class extends $ {
  constructor() {
    super(...arguments), this.scanning = !1, this.newName = "", this.onKey = (t) => t.key === "Escape" && this.close(), this.close = () => this.dispatchEvent(new CustomEvent("close"));
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
    const t = this.client, { act: e, snap: a } = this.ctx, s = b(t), i = !!a.localnet.assignments?.[t.mac.toLowerCase()], r = [...a.recs.device_recs?.[t.mac.toLowerCase()] || []].sort(At);
    return n`
      <div class="scrim" @click=${this.close}></div>
      <aside role="dialog" aria-modal="true" aria-label="Device ${s}">
        <header>
          <div style="flex:1;min-width:0">
            <h1>${t.category_icon} ${s}</h1>
            <div class="row small">${xt(t)} ${O(t)} ${ct(t)}
              ${t.suspicious ? n`<span class="badge warn">suspicious · ${t.suspicion_score}</span>` : l}
              <span class="mono muted">${t.mac}</span></div>
          </div>
          <button class="close btn" aria-label="Close" @click=${this.close}>✕</button>
        </header>

        <div class="actions row">
          ${t.state !== "trusted" ? n`<button class="btn" @click=${() => e("trust", { mac: t.mac }, { done: `${s} trusted` })}>Trust</button>` : l}
          ${t.state === "new" ? n`<button class="btn" @click=${() => e("ignore", { mac: t.mac }, { done: `${s} ignored` })}>Ignore</button>` : l}
          ${t.internet_blocked && i ? l : t.internet_blocked ? n`<button class="btn" @click=${() => e("allow_internet", { mac: t.mac }, { confirm: `Let ${s} reach the internet again?`, done: `${s} can reach the internet again` })}>Allow internet again</button>` : n`<button class="btn primary" @click=${() => e("block_internet", { mac: t.mac }, { confirm: `Block ${s} from the internet? It keeps its address and keeps working on your network.`, done: `${s} blocked from the internet` })}>Block internet</button>`}
          ${i ? n`<button class="btn" @click=${() => e("localnet_remove", { mac: t.mac }, { confirm: `Take ${s} off local-only? It gets internet access again.`, done: `${s} is no longer local-only` })}>Remove local-only</button>` : n`<button class="btn" @click=${() => e(
      "localnet_assign",
      { mac: t.mac, category: t.category === "unknown" ? "iot" : t.category },
      { confirm: `Put ${s} on local-only? It gets a ${a.localnet.prefix || "192.168.2"}.x address and is blocked from the internet, but keeps working on your network. It reconnects to pick up the new address.`, done: `${s} is now local-only` }
    )}>Make local-only</button>`}
          ${t.state === "quarantined" || t.blocked ? n`<button class="btn" @click=${() => e("unblock", { mac: t.mac }, { done: `${s} unblocked` })}>Unblock</button>` : n`<button class="btn danger" @click=${() => e("quarantine", { mac: t.mac }, { confirm: `Quarantine ${s}? It's blocked on the controller and can't use the network at all.`, danger: !0, done: `${s} quarantined` })}>Quarantine</button>`}
          <button class="btn" @click=${() => e("reconnect", { mac: t.mac }, { confirm: `Disconnect ${s} so it reconnects?`, done: "Reconnect sent" })}>Reconnect</button>
        </div>

        ${r.length ? n`<section><h2>Recommendations</h2>${r.map((o) => Ct(this.ctx, o, t.mac))}</section>` : l}

        <section>
          <h2>Internet</h2>
          ${this.internet(t)}
        </section>

        <section>
          <h2>Summary</h2>
          <div class="kv">
            <span>IP</span><span class="mono">${t.ip ? n`<a href="http://${t.ip}" target="_blank" rel="noopener noreferrer">${t.ip}</a>` : "—"}</span>
            <span>Maker</span><span>${t.vendor || "—"}</span>
            ${t.hostname && t.hostname !== t.name ? n`<span>Hostname</span><span>${t.hostname}</span>` : l}
            <span>Connection</span><span>${t.wired ? "wired" : `Wi-Fi${t.essid ? ` · ${t.essid}` : ""}${t.channel ? ` · ch ${t.channel}` : ""}${t.rssi != null ? ` · ${t.rssi} dBm` : ""}`}</span>
            <span>Uptime</span><span>${Jt(t.uptime_seconds)}</span>
            <span>Total traffic</span><span>${I(t.tx_bytes)} / ${I(t.rx_bytes)}</span>
            ${t.unifi_fingerprint ? n`<span>UniFi ID</span><span>category ${t.unifi_fingerprint.dev_cat ?? "?"}${t.unifi_fingerprint.os_name ? `, ${t.unifi_fingerprint.os_name}` : ""}${t.unifi_fingerprint.camera ? n` <span class="badge info">camera</span>` : l}</span>` : l}
            ${t.home_automation ? n`<span>Home</span><span>${t.home_automation.brand || "unknown brand"} · ${t.home_automation.tier_label}</span>` : l}
          </div>
          ${t.home_automation?.local_option ? n`<p class="small" style="margin-top:8px">${t.home_automation.local_option}</p>` : l}
        </section>

        <section>
          <h2>Category</h2>
          <p class="small muted">${t.category_label} · ${t.confidence} confidence · from ${t.source}${t.manual_category ? " (set by hand)" : ""}</p>
          ${t.suggested_category && !t.manual_category ? n`<p class="small">Quantify suggests <strong>${t.suggested_category.category}</strong> (${t.suggested_category.confidence}).
            <button class="btn" @click=${() => e("set_category", { mac: t.mac, category: t.suggested_category.category }, { done: "Category set" })}>Accept</button></p>` : l}
          <div class="row">
            <select aria-label="Category" id="cat">
              ${dt(a).map(([o, h]) => n`<option value=${o} ?selected=${o === t.category}>${h}</option>`)}
            </select>
            <input type="text" placeholder="Rename (optional)" aria-label="New name" .value=${this.newName} @input=${(o) => this.newName = o.target.value}>
            <button class="btn primary" @click=${() => e("set_category", { mac: t.mac, category: this.renderRoot.querySelector("#cat").value, ...this.newName ? { name: this.newName } : {} }, { done: "Saved" })}>Save</button>
            ${t.manual_category ? n`<button class="btn" @click=${() => e("clear_category", { mac: t.mac }, { done: "Back to automatic" })}>Clear override</button>` : l}
          </div>
        </section>

        ${t.vulns || t.onvif?.onvif || t.onvif_manufacturer ? n`<section>
          <h2>Firmware &amp; ONVIF</h2>
          ${t.onvif?.onvif ? n`<p class="small"><span class="badge ok">ONVIF</span> ${t.onvif.manufacturer} ${t.onvif.model}${t.onvif.auth_required ? n` <span class="badge">login needed</span>` : l}</p>` : l}
          <div class="kv">
            ${t.vulns?.family ? n`<span>Firmware by</span><span>${t.vulns.family}</span>` : l}
            <span>Firmware</span><span class="mono">${t.vulns?.firmware || t.onvif_firmware || "not reported"}</span>
            <span>Built</span><span>${t.vulns?.firmware_date ? `${t.vulns.firmware_date} (${t.vulns.firmware_age_years} years ago)` : "unknown"}</span>
            ${t.onvif_serial ? n`<span>Serial</span><span class="mono">${t.onvif_serial}</span>` : l}
          </div>
          ${(t.vulns?.findings || []).map((o) => n`<div class="rec ${o.status === "check" ? "high" : "critical"}">
            <div class="row"><span class="badge ${o.status === "check" ? "warn" : "bad"}">${o.status === "affected" ? "affected" : o.status === "likely" ? "probably affected" : "couldn't check"}</span>
              <span class="t">${o.cve}</span>${o.kev ? n`<span class="badge">exploited (CISA)</span>` : l}</div>
            <div class="d">${o.detail}</div><div class="small muted">${o.source}</div></div>`)}
        </section>` : l}

        <section>
          <div class="row"><h2 style="margin:0">Open ports</h2><span class="spacer"></span>
            <button class="btn" ?disabled=${this.scanning || !t.ip} @click=${() => this.scan()}>${this.scanning ? "Scanning…" : a.scans[t.mac.toLowerCase()] ? "Scan again" : "Scan ports"}</button></div>
          ${this.ports(t)}
        </section>

        ${t.ip_history && t.ip_history.length > 1 ? n`<section><h2>IP history</h2>
          ${t.ip_history.map((o) => n`<div class="mono">${o.ip} <span class="muted">${o.type === "current" ? "now" : `until ${o.until} (${o.type})`}</span></div>`)}</section>` : l}

        ${t.suspicion_flags?.length ? n`<section><h2>Why it's flagged</h2><ul class="small">${t.suspicion_flags.map((o) => n`<li>${o}</li>`)}</ul></section>` : l}
      </aside>
    `;
  }
  internet(t) {
    if (!this.ctx.snap.licence.pro)
      return n`${t.containment ? n`<p>${O(t)}</p>` : l}
        ${ht(this.ctx, "Traffic insight (24-hour traffic, spikes, and what the device tries to reach)")}
        ${t.security_events_24h ? n`<p class="small"><span class="badge warn">${y(t.security_events_24h, "security event")}</span> in UniFi's log today.</p>` : l}`;
    const e = t.phone_home, a = e?.window_minutes ? e.window_minutes < 120 ? `${e.window_minutes} min` : `${Math.round(e.window_minutes / 60)} h` : "";
    return n`
      <div class="row small" style="margin-bottom:8px">
        ${kt(t.traffic_24h, 5, 32)}
        <span>${t.traffic_24h ? `${I(t.traffic_24h.reduce((s, i) => s + i, 0))} in the last 24 h` : "No traffic history yet"}</span>
        ${t.traffic_spike ? n`<span class="badge bad">spike: ${I(t.traffic_spike.last_hour_bytes)} last hour</span>` : l}
      </div>
      ${e ? n`
        <p>${O(t)} ${y(e.attempts, "connection attempt")}${a ? ` in ${a}` : ""}, ${e.allowed ? n`<strong>${e.allowed} let through</strong>` : "all blocked"}${e.blocked_by_our_rule ? ` (${e.blocked_by_our_rule} by its local-only rule)` : ""}.</p>
        ${Object.keys(e.clouds).length ? n`<p class="small">Calls home to: <strong>${Object.keys(e.clouds).join(", ")}</strong></p>` : l}
        ${e.port_sweep ? n`<p class="small"><span class="badge warn">probing</span> tried ${e.port_sweep.ports} ports on ${e.port_sweep.host}</p>` : l}
        ${Object.keys(e.dns_bypass).length ? n`<p class="small"><span class="badge warn">own DNS</span> ${Object.keys(e.dns_bypass).join(", ")}</p>` : l}
        <div class="scroll"><table class="small"><thead><tr><th>Tries to reach</th><th>Port</th><th>Country</th><th>Times</th></tr></thead>
          <tbody>${e.top_destinations.map((s) => n`<tr><td class="mono">${s.host}</td><td>${s.port ?? s.protocol}</td><td>${s.region || "—"}</td><td>${s.count}</td></tr>`)}</tbody></table></div>` : t.containment ? n`<p>${O(t)} No connection attempts logged.</p>` : t.is_camera || t.home_automation?.tier === "cloud" || t.home_automation?.tier === "cloud_local" ? n`<p class="small muted">UniFi only logs blocked connections, so what this device reaches on the internet isn't visible. Block its internet to see what it tries.</p>` : l}
      ${t.security_events_24h ? n`<p class="small"><span class="badge warn">${y(t.security_events_24h, "security event")}</span> in UniFi's log today.</p>` : l}
    `;
  }
  ports(t) {
    const e = this.ctx.snap.scans[t.mac.toLowerCase()];
    return !e || e.status !== "complete" ? n`<p class="small muted">Not scanned yet.</p>` : n`
      <p class="small">${e.guess_description || ""} <span class="muted">(${e.guess_category}, ${e.guess_confidence} confidence${e.scan_time ? `, ${new Date(e.scan_time * 1e3).toLocaleDateString()}` : ""})</span></p>
      ${e.port_details?.length ? n`<div class="row">${e.port_details.map((a) => n`<span class="badge ${/insecure|backdoor|xmeye/.test(a.group) ? "bad" : /cloud/.test(a.group) ? "warn" : ""}" title=${a.group}>${a.port} ${a.name}</span>`)}</div>` : n`<p class="small muted">No open ports.</p>`}
      ${(e.warnings || []).map((a) => n`<p class="small"><span class="badge bad">!</span> ${a}</p>`)}
    `;
  }
};
U.styles = [x, gt`
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
tt([
  g({ attribute: !1 })
], U.prototype, "ctx", 2);
tt([
  g({ attribute: !1 })
], U.prototype, "client", 2);
tt([
  m()
], U.prototype, "scanning", 2);
tt([
  m()
], U.prototype, "newName", 2);
U = tt([
  k("ub-device-detail")
], U);
var Be = Object.defineProperty, Le = Object.getOwnPropertyDescriptor, Zt = (t, e, a, s) => {
  for (var i = s > 1 ? void 0 : s ? Le(e, a) : e, r = t.length - 1, o; r >= 0; r--)
    (o = t[r]) && (i = (s ? o(e, a, i) : o(i)) || i);
  return s && i && Be(e, a, i), i;
};
let it = class extends $ {
  render() {
    const { snap: t } = this.ctx, e = t.clients.filter((i) => i.is_camera).sort((i, r) => +!r.containment - +!i.containment || b(i).localeCompare(b(r))), a = e.filter((i) => !i.containment), s = t.overview.hotspots || [];
    return n`
      <h1>Cameras</h1>
      <p class="sub">Each camera's containment, what it tries to reach, and whether its firmware has known-exploited bugs.</p>
      <div class="tiles">
        <div class="tile ${a.length ? "warn" : "ok"}"><div class="n">${e.length - a.length}/${e.length}</div><div class="l">off the internet</div></div>
        <div class="tile ${e.some((i) => i.containment === "leaking") ? "bad" : ""}"><div class="n">${e.filter((i) => i.containment === "leaking").length}</div><div class="l">not contained</div></div>
        <div class="tile"><div class="n">${e.reduce((i, r) => i + (r.phone_home?.attempts || 0), 0)}</div><div class="l">blocked attempts (recent)</div></div>
        <div class="tile ${e.some((i) => i.vulns?.worst === "affected" || i.vulns?.worst === "likely") ? "bad" : ""}"><div class="n">${e.filter((i) => i.vulns?.findings?.length).length}</div><div class="l">firmware warnings</div></div>
      </div>
      ${a.length ? n`<div class="card"><div class="row">
        <span>${y(a.length, "camera")} can still reach the internet.</span><span class="spacer"></span>
        <button class="btn primary" @click=${() => this.containAll(a.map((i) => i.mac))}>Block internet for all ${a.length}</button></div></div>` : l}
      <div class="card scroll" style="padding:0">
        <table>
          <thead><tr><th>Camera</th><th>Internet</th><th>Calls home to</th><th>Firmware</th><th>ONVIF</th><th></th></tr></thead>
          <tbody>${e.map((i) => n`<tr>
            <td><button class="linkish" @click=${() => this.ctx.open(i.mac)}><strong>${b(i)}</strong></button><div class="muted small">${i.ip} · ${i.vulns?.family || i.onvif_manufacturer || i.vendor}</div></td>
            <td>${O(i)}${i.phone_home ? n`<div class="small muted">${y(i.phone_home.attempts, "attempt")}${i.phone_home.allowed ? `, ${i.phone_home.allowed} through` : ", all blocked"}</div>` : l}
              ${i.phone_home?.port_sweep ? n`<div class="small"><span class="badge warn">probing ${i.phone_home.port_sweep.ports} ports</span></div>` : l}</td>
            <td class="small">${i.phone_home ? Object.keys(i.phone_home.clouds).join(", ") || Object.keys(i.phone_home.regions).join(", ") || "—" : n`<span class="muted">${t.licence.pro ? "not visible" : "Pro"}</span>`}</td>
            <td>${ct(i)}<div class="small muted">${i.vulns?.firmware_date || ""}</div></td>
            <td>${i.onvif?.onvif ? n`<span class="badge ok">yes</span>${i.onvif.auth_required ? n` <span class="small muted">login</span>` : l}` : n`<span class="muted small">—</span>`}</td>
            <td>${i.containment ? l : n`<button class="btn" @click=${() => this.ctx.act("block_internet", { mac: i.mac }, { confirm: `Block ${b(i)} from the internet? It keeps its address, so recording keeps working.`, done: `${b(i)} blocked from the internet` })}>Block internet</button>`}</td>
          </tr>`)}</tbody>
        </table>
        ${e.length ? l : n`<div class="empty">No cameras found yet. Run ONVIF discovery or Quantify from Tools.</div>`}
      </div>
      ${s.length ? n`<div class="card"><h2>Camera Wi-Fi networks</h2>
        <p class="sub">A camera running its own Wi-Fi access point can be reached by anyone nearby, around your firewall. Turn that mode off in the camera's settings.</p>
        <table><thead><tr><th>Network</th><th>Why it's listed</th><th>Signal</th><th>Channel</th><th>Security</th></tr></thead>
        <tbody>${s.map((i) => n`<tr><td>${i.essid || "(hidden)"}<div class="mono muted">${i.bssid}</div></td>
          <td>${i.reason === "own_camera" ? n`<span class="badge bad">your camera ${i.camera_name || i.camera_mac}</span>` : "camera setup name"}</td>
          <td>${i.rssi != null ? `${i.rssi} dBm` : "—"}</td><td>${i.channel ?? "—"}</td><td>${i.security || "open"}</td></tr>`)}</tbody></table></div>` : l}
      ${t.licence.pro ? l : n`<div class="card">${ht(this.ctx, "Seeing what each camera tries to reach (the phone-home monitor)")}</div>`}
      <div class="card small muted">
        UniFi only logs blocked connections, so a camera's internet use shows up once it's blocked: every attempt it makes is then blocked and listed. "Not contained" means UniFi logged traffic it let through from a camera that should be cut off. Most UniFi gateways log only blocked connections, though, so a block that isn't working can look the same as a quiet camera: test a new kind of block from a laptop on the same addresses.
      </div>
    `;
  }
  async containAll(t) {
    if (!await this.ctx.confirm(`Block ${y(t.length, "camera")} from the internet? They keep their addresses, so your recorder keeps working.`)) return;
    let a = 0;
    for (const s of t)
      await this.ctx.act("block_internet", { mac: s }, { refresh: !1 }) && a++;
    this.ctx.say(`${y(a, "camera")} blocked from the internet`), this.ctx.reload();
  }
};
it.styles = [x];
Zt([
  g({ attribute: !1 })
], it.prototype, "ctx", 2);
it = Zt([
  k("ub-cameras")
], it);
var Ie = Object.defineProperty, Fe = Object.getOwnPropertyDescriptor, te = (t, e, a, s) => {
  for (var i = s > 1 ? void 0 : s ? Fe(e, a) : e, r = t.length - 1, o; r >= 0; r--)
    (o = t[r]) && (i = (s ? o(e, a, i) : o(i)) || i);
  return s && i && Ie(e, a, i), i;
};
const zt = [
  { id: "cloud", title: "Cloud only", text: "Only work through the maker's servers. Cutting them off breaks them, so local-only isn't an option; if that worries you, look for a local alternative." },
  { id: "cloud_local", title: "Cloud, with a local option", text: "Ship talking to a cloud but can be controlled locally. Switch Home Assistant to the local route first, then they can go on local-only without breaking." },
  { id: "unknown", title: "Not sure", text: "Home automation devices we can't place yet. Set their category or brand by hand from the device's page." },
  { id: "local", title: "Local", text: "Firmware you control or no cloud at all (ESPHome, WLED, Tasmota, Zigbee coordinators). Nothing to do." }
];
let nt = class extends $ {
  render() {
    const t = this.ctx.snap.clients.filter((a) => a.home_automation), e = (a) => t.filter((s) => s.home_automation.tier === a).sort((s, i) => (s.home_automation.brand || "~").localeCompare(i.home_automation.brand || "~") || b(s).localeCompare(b(i)));
    return n`
      <h1>Home automation</h1>
      <p class="sub">Smart home devices, sorted by how much they depend on someone else's cloud. Cheap cloud-tied gear has the same problems as cheap cameras.</p>
      <div class="tiles">${zt.map((a) => n`<div class="tile ${a.id === "cloud" && e(a.id).length ? "warn" : ""}"><div class="n">${e(a.id).length}</div><div class="l">${a.title.toLowerCase()}</div></div>`)}</div>
      ${zt.map((a) => {
      const s = e(a.id);
      return s.length ? n`<div class="card"><h2>${a.title} (${s.length})</h2><p class="sub">${a.text}</p>
          <div class="scroll"><table><thead><tr><th>Device</th><th>Brand</th><th>Internet</th><th>24 h</th>${a.id === "cloud_local" ? n`<th>Local option</th>` : l}</tr></thead>
          <tbody>${s.map((i) => this.row(i, a.id === "cloud_local"))}</tbody></table></div></div>` : l;
    })}
      ${t.length ? l : n`<div class="empty">No home automation devices found.</div>`}
    `;
  }
  row(t, e) {
    const a = t.phone_home;
    return n`<tr class="click" tabindex="0" @click=${() => this.ctx.open(t.mac)} @keydown=${(s) => s.key === "Enter" && this.ctx.open(t.mac)}>
      <td><strong>${b(t)}</strong><div class="muted small">${t.ip}</div></td>
      <td>${t.home_automation.brand || n`<span class="muted">—</span>`}</td>
      <td>${O(t)}${a ? n`<div class="small muted">${a.attempts} attempts${Object.keys(a.clouds).length ? ` to ${Object.keys(a.clouds).join(", ")}` : ""}</div>` : l}</td>
      <td>${kt(t.traffic_24h)}</td>
      ${e ? n`<td class="small">${t.home_automation.local_option}</td>` : l}
    </tr>`;
  }
};
nt.styles = [x];
te([
  g({ attribute: !1 })
], nt.prototype, "ctx", 2);
nt = te([
  k("ub-home")
], nt);
var ze = Object.defineProperty, qe = Object.getOwnPropertyDescriptor, St = (t, e, a, s) => {
  for (var i = s > 1 ? void 0 : s ? qe(e, a) : e, r = t.length - 1, o; r >= 0; r--)
    (o = t[r]) && (i = (s ? o(e, a, i) : o(i)) || i);
  return s && i && ze(e, a, i), i;
};
const Ve = ["critical", "high", "medium", "low", "info"];
let J = class extends $ {
  constructor() {
    super(...arguments), this.show = /* @__PURE__ */ new Set(["critical", "high", "medium"]);
  }
  toggle(t) {
    const e = new Set(this.show);
    e.has(t) ? e.delete(t) : e.add(t), this.show = e;
  }
  render() {
    const { snap: t } = this.ctx, e = [
      ...(t.recs.network_recs || []).map((r) => ({ r })),
      ...Object.entries(t.recs.device_recs || {}).flatMap(([r, o]) => o.map((h) => ({ r: h, mac: r })))
    ].sort((r, o) => At(r.r, o.r)), a = e.filter((r) => this.show.has(r.r.priority)), s = t.overview.security_events || [], i = t.clients.filter((r) => r.suspicious).sort((r, o) => o.suspicion_score - r.suspicion_score);
    return n`
      <h1>Security</h1>
      <p class="sub">What to fix, most urgent first, plus UniFi's security log and devices that behave oddly.</p>
      <div class="chips" role="group" aria-label="Show priorities">
        ${Ve.map((r) => n`<button class="chip" aria-pressed=${this.show.has(r) ? "true" : "false"} @click=${() => this.toggle(r)}>${r} ${e.filter((o) => o.r.priority === r).length}</button>`)}
      </div>
      <div class="card">
        <h2>Recommendations (${a.length})</h2>
        ${a.length ? a.slice(0, 80).map((r) => Ct(this.ctx, r.r, r.mac)) : n`<div class="empty">Nothing at these levels.</div>`}
        ${a.length > 80 ? n`<p class="small muted">Showing the first 80.</p>` : l}
      </div>
      <div class="grid two">
        <div class="card"><h2>UniFi security log, last 24 h (${s.length})</h2>
          <p class="sub">Blocks made by UniFi Blocker's own local-only rules aren't listed here; they show on each camera as proof the rule works (${t.overview.contained_blocks_24h ?? 0} today).</p>
          ${s.length ? n`<div class="scroll"><table class="small"><thead><tr><th>When</th><th>What</th><th>Rule</th></tr></thead>
            <tbody>${s.map((r) => n`<tr><td class="mono">${r.time ? new Date(r.time).toLocaleString() : "—"}</td><td>${r.msg || r.title || r.key}</td><td>${r.rule || r.catname || "—"}</td></tr>`)}</tbody></table></div>` : n`<div class="empty">Nothing in UniFi's security log.</div>`}
        </div>
        <div class="card"><h2>Suspicious devices (${i.length})</h2>
          ${i.length ? i.slice(0, 20).map((r) => n`<div style="padding:6px 0;border-bottom:1px solid var(--ub-line)">
            <div class="row"><button class="linkish" @click=${() => this.ctx.open(r.mac)}>${b(r)}</button>
              <span class="badge ${r.threat_level === "high" ? "bad" : "warn"}">${r.threat_level} · ${r.suspicion_score}</span><span class="muted small">${r.vendor}</span></div>
            <ul class="small" style="margin:4px 0 0 0;padding-left:18px">${r.suspicion_flags.map((o) => n`<li>${o}</li>`)}</ul></div>`) : n`<div class="empty">No device is acting suspiciously.</div>`}
        </div>
      </div>
    `;
  }
};
J.styles = [x];
St([
  g({ attribute: !1 })
], J.prototype, "ctx", 2);
St([
  m()
], J.prototype, "show", 2);
J = St([
  k("ub-security")
], J);
var We = Object.defineProperty, Xe = Object.getOwnPropertyDescriptor, W = (t, e, a, s) => {
  for (var i = s > 1 ? void 0 : s ? Xe(e, a) : e, r = t.length - 1, o; r >= 0; r--)
    (o = t[r]) && (i = (s ? o(e, a, i) : o(i)) || i);
  return s && i && We(e, a, i), i;
};
function Ke(t, e) {
  const [a, s] = e.split("/"), i = Number(s), r = (h) => h.split(".").reduce((c, p) => c * 256 + Number(p), 0);
  if (!a || !(i >= 0 && i <= 32) || a.split(".").length !== 4) return !1;
  const o = i === 0 ? 0 : 2 ** 32 - 2 ** (32 - i);
  return (r(t) & o) >>> 0 === (r(a) & o) >>> 0;
}
let T = class extends $ {
  constructor() {
    super(...arguments), this.ipResult = null, this.ip = "", this.showCandidates = !1, this.cidr = "";
  }
  async checkIp() {
    this.ip.trim() && (this.ipResult = await this.ctx.act("check_ip", { ip: this.ip.trim() }, { refresh: !1 }));
  }
  rangeCard(t) {
    const { snap: e, act: a } = this.ctx, s = e.localnet.range_block;
    if (!s) return l;
    const i = this.cidr || s.cidr || `${t}.0/24`, r = e.clients.filter((h) => h.ip && Ke(h.ip, i)), o = r.filter((h) => !h.is_camera && ["nas", "computer", "phone", "tablet", "networking", "crypto", "streaming", "gaming"].includes(h.category));
    return n`<div class="card">
      <h2>Block the whole range</h2>
      <p>Two firewall rules on the gateway cut every address in a range off from the internet, including any device you later give an address in it. New devices get their address from the DHCP pool, so they aren't covered until you reserve one in the range. Time sync (NTP, to any server) stays allowed so camera timestamps and light schedules stay right. Nothing on your own network is affected.</p>
      ${s.supported ? s.enabled ? n`<div class="row"><span class="badge ok">on</span><span class="mono">${s.cidr}</span>
            <span class="small muted">${y(r.length, "device")} online in it${s.ntp_allowed ? ", time sync allowed" : ""}</span><span class="spacer"></span>
            <button class="btn" @click=${() => a("localnet_range_block", { enabled: !1 }, { confirm: `Remove the block on ${s.cidr}? Devices in it get internet access again unless they have their own rule.`, done: "Range block removed" })}>Turn off</button></div>` : e.licence.pro ? n`<div class="row">
            <label class="small" for="cidr">Range</label>
            <input id="cidr" class="mono" style="width:150px" .value=${i} @input=${(h) => this.cidr = h.target.value.trim()}>
            <span class="small muted">${y(r.length, "device")} online in it</span><span class="spacer"></span>
            <button class="btn primary" @click=${() => a(
      "localnet_range_block",
      { enabled: !0, cidr: i },
      { confirm: `Block every address in ${i} from the internet? ${y(r.length, "device")} online now${o.length ? `, including ${o.map(b).join(", ")}` : ""}.`, danger: o.length > 0, done: `${i} blocked from the internet` }
    )}>Block this range</button></div>
          ${o.length ? n`<p class="small"><span class="badge warn">check</span> ${o.map(b).join(", ")} ${o.length === 1 ? "is in this range and probably needs" : "are in this range and probably need"} the internet. Use a smaller range (e.g. ${t}.0/25 covers .0–.127) to leave ${o.length === 1 ? "it" : "them"} out.</p>` : l}` : ht(this.ctx, "Blocking a whole range") : n`<p><span class="badge warn">not available</span> ${s.reason}</p>`}
    </div>`;
  }
  render() {
    const { snap: t, act: e } = this.ctx, a = t.localnet, s = a.prefix || "192.168.2", i = a.assignments || {}, r = (d) => !!i[d.mac.toLowerCase()], o = {
      blocked: t.clients.filter((d) => d.blocked || d.state === "quarantined"),
      local: t.clients.filter((d) => !(d.blocked || d.state === "quarantined") && r(d)),
      review: t.clients.filter((d) => !(d.blocked || d.state === "quarantined") && !r(d) && d.state === "new"),
      internet: t.clients.filter((d) => !(d.blocked || d.state === "quarantined") && !r(d) && d.state !== "new")
    }, h = a.firewall || {}, c = (h.total_devices || 0) - (h.blocked_count || 0), p = t.clients.filter((d) => !r(d) && d.category !== "unknown" && d.state !== "quarantined" && !d.blocked), u = t.clients.filter((d) => d.category === "nas");
    return n`
      <h1>Network</h1>
      <p class="sub">Who can reach what, and the local-only setup.</p>
      <div class="tiles">
        <div class="tile"><div class="n">${o.internet.length}</div><div class="l">internet access</div></div>
        <div class="tile ok"><div class="n">${o.local.length}</div><div class="l">local-only</div></div>
        <div class="tile"><div class="n">${o.blocked.length}</div><div class="l">blocked</div></div>
        <button class="tile ${o.review.length > 10 ? "warn" : ""}" @click=${() => this.ctx.go("devices", "new")}><div class="n">${o.review.length}</div><div class="l">not reviewed yet</div></button>
      </div>

      ${this.rangeCard(s)}

      <div class="card">
        <h2>Local-only</h2>
        <p>Local-only devices get an address in <span class="mono">${a.subnet || `${s}.0/24`}</span> and a per-device traffic rule on the gateway that blocks them from the internet. They keep working on your network.</p>
        <p class="small muted">Local-only stops internet access, not access to the rest of your LAN: those addresses are on the same network as everything else. Keeping a camera away from your other devices takes a separate VLAN.</p>
        <div class="row" style="margin:8px 0">
          ${h.total_devices ? n`<span class="badge ${c ? "warn" : "ok"}">${h.blocked_count}/${h.total_devices} rules in place</span>` : n`<span class="badge">no devices yet</span>`}
          ${c > 0 ? n`<button class="btn primary" @click=${() => e("localnet_ensure_rule", {}, { done: "Missing rules created" })}>Create ${y(c, "missing rule")}</button>` : l}
        </div>
        ${Object.keys(i).length ? n`<div class="scroll"><table>
          <thead><tr><th>Device</th><th>Address</th><th>Category</th><th>Internet</th><th></th></tr></thead>
          <tbody>${Object.entries(i).map(([d, f]) => {
      const v = t.clients.find((H) => H.mac.toLowerCase() === d);
      return n`<tr><td>${v ? n`<button class="linkish" @click=${() => this.ctx.open(d)}>${b(v)}</button>` : n`${f.name || d} <span class="muted small">(offline)</span>`}</td>
              <td class="mono">${f.ip}</td><td>${f.category}</td>
              <td>${v?.phone_home ? n`<span class="small">${v.phone_home.attempts} attempts blocked</span>` : n`<span class="muted small">—</span>`}</td>
              <td><button class="btn" @click=${() => e("localnet_remove", { mac: d }, { confirm: `Take ${v ? b(v) : d} off local-only? It gets internet access again.`, done: "Removed from local-only" })}>Remove</button></td></tr>`;
    })}</tbody></table></div>` : l}
        <button class="btn" style="margin-top:12px" aria-expanded=${this.showCandidates ? "true" : "false"} @click=${() => this.showCandidates = !this.showCandidates}>${this.showCandidates ? "Hide" : "Add devices"}</button>
        ${this.showCandidates ? n`<div class="scroll" style="margin-top:8px"><table><thead><tr><th>Device</th><th>Category</th><th></th></tr></thead>
          <tbody>${p.slice(0, 60).map((d) => n`<tr><td>${b(d)}<div class="muted small">${d.ip} · ${d.vendor}</div></td><td>${d.category_label}</td>
            <td><button class="btn" @click=${() => e("localnet_assign", { mac: d.mac, category: d.category }, { confirm: `Put ${b(d)} on local-only?`, done: `${b(d)} is now local-only` })}>Make local-only</button></td></tr>`)}</tbody></table></div>` : l}
        ${(a.ranges || []).length ? n`<details style="margin-top:12px"><summary class="small">Address ranges by category</summary>
          <table class="small"><thead><tr><th>Category</th><th>Range</th><th>Used</th></tr></thead>
          <tbody>${(a.ranges || []).map((d) => n`<tr><td>${Object.fromEntries(dt(t))[d.category] || d.category}</td><td class="mono">${d.range}</td><td>${d.used}/${d.total}</td></tr>`)}</tbody></table></details>` : l}
      </div>

      <div class="grid two">
        <div class="card">
          <h2>Is this address free?</h2>
          <p class="sub">Checks clients, offline devices, UniFi devices, reservations and local-only assignments before you hand an address out.</p>
          <div class="row"><input type="text" placeholder="${s}.35" aria-label="IP address" .value=${this.ip} @input=${(d) => this.ip = d.target.value} @keydown=${(d) => d.key === "Enter" && this.checkIp()}>
            <button class="btn primary" @click=${() => this.checkIp()}>Check</button></div>
          ${this.ipResult ? n`<p style="margin-top:10px"><strong>${this.ipResult.summary}</strong></p>
            <table class="small"><tbody>${(this.ipResult.checks || []).map((d) => n`<tr><td>${d.icon}</td><td>${d.check}</td><td>${d.result}</td></tr>`)}</tbody></table>` : l}
        </div>
        <div class="card">
          <h2>Storage (${u.length})</h2>
          ${u.length ? n`<table class="small"><tbody>${u.map((d) => n`<tr class="click" @click=${() => this.ctx.open(d.mac)}><td>${b(d)}</td><td class="mono">${d.ip}</td><td>${d.vendor}</td><td>${xt(d)}</td></tr>`)}</tbody></table>
            <p class="small muted" style="margin-top:8px">A NAS should stay on your main network with internet for updates and cloud backup. Don't put it on local-only.</p>` : n`<div class="empty">No NAS found.</div>`}
        </div>
      </div>
    `;
  }
};
T.styles = [x];
W([
  g({ attribute: !1 })
], T.prototype, "ctx", 2);
W([
  m()
], T.prototype, "ipResult", 2);
W([
  m()
], T.prototype, "ip", 2);
W([
  m()
], T.prototype, "showCandidates", 2);
W([
  m()
], T.prototype, "cidr", 2);
T = W([
  k("ub-network")
], T);
var Qe = Object.defineProperty, Ge = Object.getOwnPropertyDescriptor, ee = (t, e, a, s) => {
  for (var i = s > 1 ? void 0 : s ? Ge(e, a) : e, r = t.length - 1, o; r >= 0; r--)
    (o = t[r]) && (i = (s ? o(e, a, i) : o(i)) || i);
  return s && i && Qe(e, a, i), i;
};
let rt = class extends $ {
  render() {
    if (this.ctx.snap.miners.pro === !1) {
      const s = this.ctx.snap.clients.filter((i) => i.category === "crypto").length;
      return n`<h1>Mining</h1>
        <p class="sub">Crypto miners found on the network, with live hashrate, power and profitability.</p>
        <div class="card"><p>${s ? `${s} device${s === 1 ? " looks" : "s look"} like a miner (see Devices).` : "No miners found yet."}</p>
          ${ht(this.ctx, "The mining tracker (live hashrate, temperatures, power and profit per rig)")}</div>`;
    }
    const { rigs: t, summary: e } = this.ctx.snap.miners, a = e.profit_usd_day ?? 0;
    return n`
      <h1>Mining</h1>
      <p class="sub">Crypto miners found on the network, with live profitability at $${(e.electricity_usd_per_kwh ?? 0.08).toFixed(3)}/kWh.</p>
      <div class="tiles">
        <div class="tile"><div class="n">${e.rig_count ?? 0}</div><div class="l">rigs</div></div>
        <div class="tile"><div class="n">${e.reachable ?? 0}/${e.rig_count ?? 0}</div><div class="l">answering</div></div>
        <div class="tile"><div class="n">${Bt(e.total_hashrate_hs)}</div><div class="l">hashrate</div></div>
        <div class="tile"><div class="n">${Math.round(e.total_power_w ?? 0)} W</div><div class="l">power</div></div>
        <div class="tile"><div class="n">${B(e.revenue_usd_day)}</div><div class="l">revenue / day</div></div>
        <div class="tile"><div class="n">${B(e.cost_usd_day)}</div><div class="l">power cost / day</div></div>
        <div class="tile ${a > 0 ? "ok" : a < 0 ? "bad" : ""}"><div class="n">${B(a)}</div><div class="l">profit / day</div></div>
      </div>
      ${t.length ? n`<div class="card scroll" style="padding:0"><table>
        <thead><tr><th>Rig</th><th>Model</th><th>Coin</th><th>Hashrate</th><th>Temp</th><th>Power</th><th>Revenue</th><th>Cost</th><th>Profit</th></tr></thead>
        <tbody>${t.map((s) => n`<tr>
          <td class="mono"><a href="http://${s.ip}" target="_blank" rel="noopener noreferrer" style="color:var(--primary-color)">${s.ip}</a></td>
          <td>${s.model || "—"}${s.reachable ? n` <span class="badge info">${s.source || "api"}</span>` : n` <span class="badge warn">no API</span>`}</td>
          <td>${s.coin || "—"}</td><td>${s.hashrate_display || Bt(s.hashrate_hs)}</td>
          <td>${s.extras?.temp_c != null ? `${s.extras.temp_c} °C` : "—"}</td>
          <td>${s.power_w != null ? `${Math.round(s.power_w)} W${s.power_source === "rated" ? " (rated)" : ""}` : "—"}</td>
          <td>${B(s.revenue_usd_day)}</td><td>${B(s.cost_usd_day)}</td>
          <td class=${(s.profit_usd_day ?? 0) < 0 ? "bad" : ""}>${B(s.profit_usd_day)}</td>
        </tr>`)}</tbody></table></div>` : n`<div class="card empty">No miners found. They're picked up from port scans (CGMiner API on 4028) and known miner makers' MAC addresses.</div>`}
      ${(e.revenue_usd_day ?? 0) === 0 && t.length ? n`<p class="small muted">Revenue shows $0 when coin prices can't be fetched (minerstat.com now needs an API key).</p>` : l}
    `;
  }
};
rt.styles = [x];
ee([
  g({ attribute: !1 })
], rt.prototype, "ctx", 2);
rt = ee([
  k("ub-mining")
], rt);
const se = [
  ["ha", "Home Assistant"],
  ["night", "Night"],
  ["day", "Day"],
  ["graphite", "Graphite"],
  ["ocean", "Ocean"],
  ["dusk", "Dusk"],
  ["contrast", "High contrast"],
  ["light", "Light (inverted)"]
], ae = ["day", "graphite", "ocean", "dusk", "contrast"];
function qt(t, e) {
  return ae.includes(t) && !e ? "ha" : t;
}
const F = {
  bg: "#0a150e",
  card: "#0f1a12",
  inset: "#0c1a0e",
  line: "#1b3526",
  header: "#071008",
  text: "#e2e8f0",
  text2: "#94a3b8",
  accent: "#52b788",
  onAccent: "#071008",
  warn: "#f59e0b",
  error: "#f87171",
  info: "#60a5fa",
  dark: !0
}, Ye = {
  night: F,
  day: {
    bg: "#f0f2f1",
    card: "#ebeeec",
    inset: "#ecefed",
    line: "#d4e2da",
    header: "#f4f6f4",
    text: "#0f151d",
    text2: "#47566b",
    accent: "#398964",
    onAccent: "#ffffff",
    warn: "#ba7808",
    error: "#b90909",
    info: "#0657bc",
    dark: !1
  },
  graphite: { ...F, bg: "#0f0f10", card: "#131416", inset: "#121314", line: "#26272a", header: "#0b0b0c", text: "#e8e9ea", text2: "#a2a5aa" },
  ocean: { ...F, bg: "#080f17", card: "#0d141c", inset: "#0a121c", line: "#172639", header: "#060b11", text2: "#94a4b8" },
  dusk: { ...F, bg: "#110916", card: "#160e1b", inset: "#150b1b", line: "#2c1a36", header: "#0d0710", text: "#e9e5ed", text2: "#a69cb0" },
  contrast: {
    bg: "#070707",
    card: "#090909",
    inset: "#090909",
    line: "#a8a8a8",
    header: "#050505",
    text: "#ffffff",
    text2: "#dbdbdb",
    accent: "#93d2b5",
    onAccent: "#000000",
    warn: "#f9c56c",
    error: "#f87171",
    info: "#6babfa",
    dark: !0
  }
}, ie = (t) => ({
  "--primary-background-color": t.bg,
  "--secondary-background-color": t.inset,
  "--card-background-color": t.card,
  "--ha-card-background": t.card,
  "--divider-color": t.line,
  "--ha-card-border-color": t.line,
  "--primary-text-color": t.text,
  "--secondary-text-color": t.text2,
  "--primary-color": t.accent,
  "--text-primary-color": t.onAccent,
  "--app-header-background-color": t.header,
  "--app-header-text-color": t.text,
  "--success-color": t.accent,
  "--warning-color": t.warn,
  "--error-color": t.error,
  "--info-color": t.info
}), ne = "unifiblocker.theme", Je = Object.keys(ie(F));
function Ze() {
  try {
    const t = localStorage.getItem(ne);
    return t && se.some(([e]) => e === t) ? t : "ha";
  } catch {
    return "ha";
  }
}
function ts(t) {
  try {
    localStorage.setItem(ne, t);
  } catch {
  }
}
function mt(t, e) {
  for (const s of Je) t.style.removeProperty(s);
  if (t.style.removeProperty("color-scheme"), t.style.filter = "", e === "ha") return;
  const a = e === "light" ? F : Ye[e];
  for (const [s, i] of Object.entries(ie(a))) t.style.setProperty(s, i);
  t.style.setProperty("color-scheme", a.dark ? "dark" : "light"), e === "light" && (t.style.filter = "invert(1) hue-rotate(180deg)");
}
var es = Object.defineProperty, ss = Object.getOwnPropertyDescriptor, j = (t, e, a, s) => {
  for (var i = s > 1 ? void 0 : s ? ss(e, a) : e, r = t.length - 1, o; r >= 0; r--)
    (o = t[r]) && (i = (s ? o(e, a, i) : o(i)) || i);
  return s && i && es(e, a, i), i;
};
const as = [
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
let P = class extends $ {
  constructor() {
    super(...arguments), this.preview = null, this.discovering = !1, this.debug = null, this.trialEmail = "", this.shownKey = "";
  }
  async discover() {
    this.discovering = !0;
    const t = await this.ctx.act("onvif_discover", {}, { refresh: !0 });
    this.discovering = !1, t && this.ctx.say(`ONVIF discovery found ${t.count ?? 0} camera${t.count === 1 ? "" : "s"}`);
  }
  async enterKey() {
    const t = window.prompt("Your UniFi Blocker Pro key (UBLOK-XXXX-XXXX-XXXX-XXXX):");
    if (!t) return;
    const e = await this.ctx.act("licence_activate", { key: t }, { refresh: !0 });
    e && this.ctx.say(e.ok ? "UniFi Blocker Pro is on" : e.message, !e.ok);
  }
  async startTrial() {
    const t = await this.ctx.act("licence_trial", { email: this.trialEmail.trim() }, { refresh: !0 });
    t && this.ctx.say(t.ok ? `Pro trial on for ${t.days_left ?? 30} days` : t.message, !t.ok);
  }
  licenceCard() {
    const t = this.ctx.snap.licence, e = t.expires ? new Date(t.expires) : null, a = e && e.getFullYear() >= 2090, s = e && !a ? e.toLocaleDateString() : "", i = t.has_key ? t.active ? t.in_grace ? n`<p><span class="badge warn">renew</span> Your Pro licence ended on ${s}. It keeps working for ${t.grace_days ?? 14} days after that.</p>` : t.trial ? n`<p><span class="badge ok">trial</span> Pro trial, ${t.days_left ?? "?"} days left.</p>` : n`<p><span class="badge ok">Pro</span> UniFi Blocker Pro${a ? ", lifetime" : s ? `, valid until ${s}` : ""}${!a && (t.days_left ?? 99) <= 14 ? ` · renews in ${t.days_left} days` : ""}.</p>` : n`<p><span class="badge bad">expired</span> Your Pro licence ended on ${s}, so the Pro features are off. Blocks already on your controller stay where they are and can always be turned off.</p>` : n`<p>No licence on this install. Everything below "What Pro adds" is locked; everything else is free and stays free.</p>`, r = !t.has_key || !t.active || t.in_grace || t.trial;
    return n`<div class="card">
      <h2>UniFi Blocker Pro</h2>
      ${i}
      <details><summary class="small">What Pro adds</summary>
        <ul class="small">
          <li>Block a whole address range from the internet with one switch (Network page).</li>
          <li>Block new cameras from the internet automatically as they join.</li>
          <li>Traffic insight: what each device tries to reach, port sweeps, devices using their own DNS, 24-hour traffic and spikes, and an alert when a cut-off device gets through.</li>
          <li>The mining tracker: live hashrate, temperatures, power and profit per rig.</li>
          <li>The Day, Graphite, Ocean, Dusk and High contrast themes.</li>
        </ul>
        <p class="small muted">Free, always: finding and identifying every device, recommendations, the security log, firmware warnings, port scans, ONVIF, and blocking, local-only and quarantine device by device.</p>
      </details>
      <div class="row" style="margin-top:8px">
        ${r ? n`<a class="btn primary" href=${t.buy_url || "https://unifiblocker.enerx.ca/pro/"} target="_blank" rel="noopener noreferrer">${t.has_key && !t.trial ? "Renew" : "Buy"} Pro, ${t.price || "$35 CAD/year"}</a>` : l}
        <button class="btn" @click=${() => this.enterKey()}>${t.has_key ? "Replace licence key" : "Enter licence key"}</button>
        ${t.has_key ? n`<button class="btn" @click=${async () => {
      const o = await this.ctx.act("licence_reveal", {}, { refresh: !1 });
      o && (this.shownKey = o.key);
    }}>Show key</button>
          <button class="btn" @click=${() => this.ctx.act("licence_remove", {}, { confirm: "Take the licence key off this install? You can enter it again later.", done: "Licence key removed" })}>Remove key</button>` : l}
      </div>
      ${this.shownKey ? n`<p class="mono" style="margin-top:8px">${this.shownKey}</p>` : l}
      ${!t.has_key && !t.trial_used ? n`<div class="row" style="margin-top:12px">
        <span class="small">Try Pro free for ${t.trial_days ?? 30} days, once per home:</span>
        <input type="email" placeholder="your email" aria-label="Email for the trial key" .value=${this.trialEmail}
          @input=${(o) => this.trialEmail = o.target.value}>
        <button class="btn" ?disabled=${!this.trialEmail.includes("@")} @click=${() => this.startTrial()}>Start free trial</button>
      </div><p class="small muted">Your email is kept with the trial key on the licence server, nothing else. Write the key down from "Show key" if you want it elsewhere.</p>` : l}
    </div>`;
  }
  async showDebug(t) {
    const e = await this.ctx.act(t, {}, { refresh: !1 });
    e && (this.debug = JSON.stringify(e, null, 2));
  }
  render() {
    const { snap: t, act: e } = this.ctx, a = t.report, s = t.learned, i = dt(t), r = s ? [
      ...Object.entries(s.vendor_rules || {}).map(([o, h]) => ["vendor", o, `maker contains “${o}”`, h]),
      ...Object.entries(s.hostname_rules || {}).map(([o, h]) => ["hostname", o, `name starts “${o}”`, h]),
      ...Object.entries(s.mac_rules || {}).map(([o, h]) => ["mac", o, `MAC starts ${o}`, h]),
      ...(s.port_rules || []).map((o) => ["port", o.ports.join(","), `ports ${o.ports.join(", ")}`, o.category])
    ] : [];
    return n`
      <h1>Tools</h1>
      <p class="sub">Your licence, scans, learned rules, and settings for the usage report.</p>
      ${this.licenceCard()}
      <div class="grid two">
        <div class="card">
          <h2>Find cameras</h2>
          <p class="sub">ONVIF discovery runs at startup and every 6 hours. Run it now after adding a camera. Quantify (on Overview) deep-scans everything still unknown.</p>
          <div class="row"><button class="btn primary" ?disabled=${this.discovering} @click=${() => this.discover()}>${this.discovering ? "Looking…" : "Run ONVIF discovery"}</button>
            <button class="btn" @click=${() => this.ctx.go("overview")}>Quantify…</button></div>
        </div>

        <div class="card">
          <h2>Help improve UniFi Blocker</h2>
          ${a ? n`
            <p>Off unless you turn it on. Once a day it sends counts and versions so problems on other networks can be found: device counts by category, which tools get used, poll times, API errors, warnings logged. <strong>Never</strong> MAC or IP addresses, names, vendor strings from your network, or entity ids, and the whole report is refused if anything like that is in it.</p>
            <div class="row">
              ${a.enabled ? n`<span class="badge ok">on</span><span class="small muted">${a.last_day ? `last sent ${a.last_day}` : "nothing sent yet"}</span>` : n`<span class="badge">off</span>`}
              <span class="spacer"></span>
              ${a.enabled ? n`<button class="btn" @click=${() => e("report_set", { enabled: !1 }, { done: "Usage report off" })}>Turn off</button>
                       <button class="btn" @click=${async () => {
      const o = await e("report_send", {}, { refresh: !0 });
      o && this.ctx.say(o.sent ? `Report sent (${o.bytes} bytes)` : `Not sent: ${o.reason}`, !o.sent);
    }}>Send now</button>
                       <button class="btn" @click=${() => e("report_new_id", {}, { confirm: "Replace the anonymous ID? Reports after this count as a new install.", done: "New ID made" })}>New ID</button>` : n`<button class="btn primary" @click=${() => e("report_set", { enabled: !0 }, { done: "Usage report on" })}>Turn on</button>`}
              <button class="btn" @click=${async () => this.preview = await e("report_preview", {}, { refresh: !1 })}>Preview</button>
            </div>
            ${this.preview ? n`<p class="small" style="margin-top:8px">${this.preview.bytes} bytes to ${this.preview.url}${this.preview.problems?.length ? n` · <span class="badge bad">would be refused: ${this.preview.problems.join("; ")}</span>` : l}</p>
              <pre class="mono" style="max-height:300px;overflow:auto;white-space:pre-wrap">${JSON.stringify(this.preview.payload, null, 2)}</pre>` : l}
          ` : n`<p class="muted">Not available.</p>`}
        </div>
      </div>

      <div class="card">
        <h2>Theme</h2>
        <p class="sub">The same looks as PadSpan. Home Assistant follows your HA theme. This browser only.</p>
        <div class="chips" role="group" aria-label="Theme">${se.map(([o, h]) => {
      const c = ae.includes(o) && !t.licence.pro;
      return n`<button class="chip" aria-pressed=${this.ctx.theme === o && !c ? "true" : "false"} ?disabled=${c}
            title=${c ? "UniFi Blocker Pro" : ""} style=${c ? "opacity:.45;cursor:default" : ""}
            @click=${() => this.ctx.setTheme(o)}>${h}${c ? " · Pro" : ""}</button>`;
    })}</div>
        ${t.licence.pro ? l : n`<p class="small muted">Day, Graphite, Ocean, Dusk and High contrast come with Pro.</p>`}
      </div>

      <div class="card">
        <h2>Learned rules (${r.length})</h2>
        <p class="sub">Picked up when you set a device's category by hand, and used for devices nothing else identifies. Fix or delete wrong ones.</p>
        ${r.length ? n`<div class="scroll"><table><thead><tr><th>Rule</th><th>Category</th><th></th></tr></thead>
          <tbody>${r.map(([o, h, c, p]) => n`<tr><td>${c}</td>
            <td><select aria-label="Category for ${c}" @change=${(u) => e("learned_rule_update", { kind: o, key: h, category: u.target.value }, { done: "Rule updated" })}>
              ${i.map(([u, d]) => n`<option value=${u} ?selected=${u === p}>${d}</option>`)}</select></td>
            <td><button class="btn" @click=${() => e("learned_rule_update", { kind: o, key: h, category: null }, { confirm: `Delete the rule “${c}”?`, done: "Rule deleted" })}>Delete</button></td></tr>`)}</tbody></table></div>` : n`<div class="empty">No learned rules yet.</div>`}
      </div>

      <div class="card">
        <h2>Port reference</h2>
        <table class="small"><thead><tr><th>Port</th><th>What</th><th>Why it matters</th></tr></thead>
          <tbody>${as.map(([o, h, c, p]) => n`<tr><td class="mono">${o}</td><td>${p ? n`<span class="badge ${p}">${h}</span>` : h}</td><td>${c}</td></tr>`)}</tbody></table>
      </div>

      <details class="card"><summary>Troubleshooting</summary>
        <div class="row" style="margin-top:8px"><button class="btn" @click=${() => this.showDebug("traffic_rules_debug")}>Show traffic rules</button>
          <button class="btn" @click=${() => this.showDebug("firewall_rules_debug")}>Show firewall rules</button></div>
        ${this.debug ? n`<pre class="mono" style="max-height:400px;overflow:auto;white-space:pre-wrap">${this.debug}</pre>` : l}
      </details>
    `;
  }
};
P.styles = [x];
j([
  g({ attribute: !1 })
], P.prototype, "ctx", 2);
j([
  m()
], P.prototype, "preview", 2);
j([
  m()
], P.prototype, "discovering", 2);
j([
  m()
], P.prototype, "debug", 2);
j([
  m()
], P.prototype, "trialEmail", 2);
j([
  m()
], P.prototype, "shownKey", 2);
P = j([
  k("ub-tools")
], P);
var is = Object.defineProperty, ns = Object.getOwnPropertyDescriptor, A = (t, e, a, s) => {
  for (var i = s > 1 ? void 0 : s ? ns(e, a) : e, r = t.length - 1, o; r >= 0; r--)
    (o = t[r]) && (i = (s ? o(e, a, i) : o(i)) || i);
  return s && i && is(e, a, i), i;
};
const rs = "0.3.62", Vt = [
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
      licence: { pro: !1, has_key: !1 },
      loaded: !1,
      error: "",
      updated: 0
    }, this.toast = null, this.ask = null, this.openMac = null, this.theme = Ze(), this.devicesFilter = "all", this.lastReportedView = "", this.onVisibility = () => {
      document.visibilityState === "visible" ? this.schedule(0) : window.clearTimeout(this.timer);
    }, this.act = async (t, e = {}, a = {}) => {
      if (a.confirm && !await this.confirm(a.confirm, a.danger)) return null;
      try {
        const s = await _(this.hass, t, e);
        if (s && s.ok === !1) throw new bt("failed", s.error || "The controller refused it");
        return a.done && this.say(a.done), a.refresh !== !1 && this.schedule(800), s ?? {};
      } catch (s) {
        return this.say(s instanceof bt ? s.message : String(s), !0), null;
      }
    }, this.say = (t, e = !1) => {
      this.toast = { text: t, bad: e }, window.clearTimeout(this.toastTimer), this.toastTimer = window.setTimeout(() => this.toast = null, e ? 8e3 : 4e3);
    }, this.confirm = (t, e = !1) => new Promise((a) => this.ask = { text: t, danger: e, resolve: a }), this.openDevice = (t) => this.openMac = t.toLowerCase(), this.go = (t, e) => {
      this.view = t, e && (this.devicesFilter = e), this.renderRoot.querySelector("main")?.scrollTo?.(0, 0);
    }, this.setTheme = (t) => {
      this.theme = t, ts(t), mt(this, qt(t, this.snap.licence.pro));
    };
  }
  connectedCallback() {
    super.connectedCallback(), mt(this, this.theme);
    const t = new URLSearchParams(location.search).get("view");
    t && Vt.some((e) => e.id === t) && (this.view = t), document.addEventListener("visibilitychange", this.onVisibility), this.schedule(0);
  }
  disconnectedCallback() {
    super.disconnectedCallback(), document.removeEventListener("visibilitychange", this.onVisibility), window.clearTimeout(this.timer);
  }
  schedule(t) {
    window.clearTimeout(this.timer), this.timer = window.setTimeout(() => this.load(), t);
  }
  async load() {
    if (!this.hass) return this.schedule(500);
    try {
      this.snap = await Oe(this.hass), mt(this, qt(this.theme, this.snap.licence.pro));
    } catch (t) {
      this.snap = { ...this.snap, error: t?.message ?? String(t) };
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
      reload: () => this.schedule(800),
      theme: this.theme,
      setTheme: this.setTheme
    };
  }
  answer(t) {
    this.ask?.resolve(t), this.ask = null;
  }
  renderView() {
    const t = this.ctxObj();
    switch (this.view) {
      case "overview":
        return n`<ub-overview .ctx=${t}></ub-overview>`;
      case "devices":
        return n`<ub-devices .ctx=${t} .filter=${this.devicesFilter} @filter=${(e) => this.devicesFilter = e.detail}></ub-devices>`;
      case "cameras":
        return n`<ub-cameras .ctx=${t}></ub-cameras>`;
      case "home":
        return n`<ub-home .ctx=${t}></ub-home>`;
      case "security":
        return n`<ub-security .ctx=${t}></ub-security>`;
      case "network":
        return n`<ub-network .ctx=${t}></ub-network>`;
      case "mining":
        return n`<ub-mining .ctx=${t}></ub-mining>`;
      case "tools":
        return n`<ub-tools .ctx=${t}></ub-tools>`;
    }
  }
  render() {
    const t = this.snap.overview, e = this.snap.clients.filter((i) => i.containment === "leaking").length, a = this.snap.recs.critical_count || 0, s = this.openMac ? this.snap.clients.find((i) => i.mac.toLowerCase() === this.openMac) : void 0;
    return n`
      <div class="toolbar">
        ${this.narrow ? n`<ha-menu-button .hass=${this.hass} .narrow=${this.narrow}></ha-menu-button>` : l}
        <div class="title">UniFi Blocker</div>
        <span class="status ${t.health?.connection_ok === !1 ? "bad" : ""}" title="Controller">
          ${this.snap.loaded ? t.health?.connection_ok === !1 ? "Controller unreachable" : `${t.health?.hostname || "Controller"} · ${t.total_clients ?? 0} devices` : "Loading…"}
        </span>
        <button class="icon" aria-label="Refresh" title="Refresh" @click=${() => this.load()}>
          <svg viewBox="0 0 24 24" width="22" height="22"><path fill="currentColor" d="M17.65 6.35A8 8 0 1 0 19.7 14h-2.1a6 6 0 1 1-1.4-6.2L13 11h7V4z"/></svg>
        </button>
      </div>
      <nav aria-label="UniFi Blocker sections">
        ${Vt.map((i) => n`
          <button class="tab" aria-current=${this.view === i.id ? "page" : "false"} @click=${() => this.go(i.id)}>
            <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true"><path fill="currentColor" d=${i.icon}/></svg>
            <span>${i.label}</span>
            ${i.id === "security" && a ? n`<span class="dot" aria-label="${a} critical">${a}</span>` : l}
            ${i.id === "cameras" && e ? n`<span class="dot" aria-label="${e} not contained">${e}</span>` : l}
            ${i.id === "devices" && (t.new_count || 0) > 0 ? n`<span class="dot soft">${t.new_count}</span>` : l}
          </button>`)}
      </nav>
      <main>
        ${this.snap.error ? n`<div class="card error" role="alert">Couldn't load data: ${this.snap.error}</div>` : l}
        ${this.renderView()}
        <footer class="muted small">UniFi Blocker ${rs}${this.snap.updated ? n` · updated ${new Date(this.snap.updated).toLocaleTimeString()}` : l}</footer>
      </main>
      ${s ? n`<ub-device-detail .ctx=${this.ctxObj()} .client=${s} @close=${() => this.openMac = null}></ub-device-detail>` : l}
      ${this.ask ? n`
        <div class="scrim" @click=${() => this.answer(!1)}></div>
        <div class="dialog" role="alertdialog" aria-modal="true" aria-label="Confirm">
          <p>${this.ask.text}</p>
          <div class="row"><span class="spacer"></span>
            <button class="btn" @click=${() => this.answer(!1)}>Cancel</button>
            <button class="btn ${this.ask.danger ? "danger" : "primary"}" @click=${() => this.answer(!0)}>Continue</button>
          </div>
        </div>` : l}
      ${this.toast ? n`<div class="toast ${this.toast.bad ? "bad" : ""}" role="status">${this.toast.text}</div>` : l}
    `;
  }
};
w.styles = [x, gt`
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
    .dot.soft { background: color-mix(in srgb, currentColor 22%, transparent); color: inherit; }
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
  m()
], w.prototype, "view", 2);
A([
  m()
], w.prototype, "snap", 2);
A([
  m()
], w.prototype, "toast", 2);
A([
  m()
], w.prototype, "ask", 2);
A([
  m()
], w.prototype, "openMac", 2);
A([
  m()
], w.prototype, "theme", 2);
A([
  m()
], w.prototype, "devicesFilter", 2);
w = A([
  k("unifiblocker-panel")
], w);
export {
  w as UniFiBlockerPanel,
  rs as VERSION
};
