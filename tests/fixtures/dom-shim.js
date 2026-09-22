// Minimal fake DOM used to test js/render.js without a browser or a heavy
// jsdom dependency. It implements only what render.js actually calls:
// document.createElement / createTextNode, element.textContent/className,
// setAttribute, appendChild, replaceChildren, classList.toggle, style.
// Crucially, setting textContent or innerHTML never parses markup — it just
// stores a string — which is exactly what makes it a faithful stand-in for
// proving render.js never turns untrusted data into DOM nodes.

class FakeClassList {
  constructor(el) {
    this._el = el;
    this._set = new Set();
  }

  toggle(cls, force) {
    if (force === undefined) {
      if (this._set.has(cls)) {
        this._set.delete(cls);
        return false;
      }
      this._set.add(cls);
      return true;
    }
    if (force) this._set.add(cls);
    else this._set.delete(cls);
    return force;
  }

  contains(cls) {
    return this._set.has(cls);
  }
}

class FakeElement {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase();
    this.children = [];
    this.attributes = {};
    this.style = {};
    this.classList = new FakeClassList(this);
    this._text = '';
    this._html = '';
  }

  set className(v) {
    this.attributes.class = v;
  }

  get className() {
    return this.attributes.class || '';
  }

  set textContent(v) {
    this._text = v === null || v === undefined ? '' : String(v);
    this.children = [];
  }

  get textContent() {
    if (this.children.length) {
      return this.children.map((c) => c.textContent).join('');
    }
    return this._text;
  }

  set innerHTML(v) {
    this._html = String(v);
  }

  get innerHTML() {
    return this._html;
  }

  setAttribute(k, v) {
    this.attributes[k] = String(v);
  }

  getAttribute(k) {
    return Object.prototype.hasOwnProperty.call(this.attributes, k) ? this.attributes[k] : null;
  }

  appendChild(child) {
    this.children.push(child);
    return child;
  }

  replaceChildren(...nodes) {
    this.children = nodes.filter(Boolean);
    this._text = '';
  }

  querySelector() {
    return null;
  }
}

class FakeTextNode {
  constructor(text) {
    this.nodeType = 3;
    this.textContent = text === null || text === undefined ? '' : String(text);
  }
}

export function createFakeDocument() {
  return {
    createElement: (tag) => new FakeElement(tag),
    createTextNode: (text) => new FakeTextNode(text),
  };
}

// Recursively walks a fake DOM tree and returns every node.
export function walk(node, out = []) {
  out.push(node);
  for (const child of node.children || []) walk(child, out);
  return out;
}
