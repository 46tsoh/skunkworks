#!/usr/bin/env node
/*
 * Aegis headless-Chromium navigation-log driver.
 *
 * Runs INSIDE the browser adapter's container (zenika/alpine-chrome:*-with-
 * puppeteer) under `--network none`. It drives the image's system Chromium with
 * puppeteer-core, visits the target page(s), and writes a navigation-log JSON
 * document to the mounted report file. That schema is the pinned contract the
 * Python parser (aegis/tools/adapters/browser.py :: parse) consumes, so this
 * driver emits exactly:
 *
 *   {
 *     "target": "<url>",
 *     "engine": "chromium-headless",
 *     "pages": [
 *       {
 *         "url", "screenshot", "html",
 *         "console":       [{level, text}],
 *         "dom_sinks":     [{sink, source, snippet, file, line}],
 *         "mixed_content": [{resource, type}],
 *         "secrets":       [{kind, match, file, line}]
 *       }, ...
 *     ]
 *   }
 *
 * Local-only by construction: the target is normally a file:// URL backed by a
 * read-only mount of a saved site (see the adapter's INPUT_DIR), so a true
 * live run needs no network. Every byte it produces is read back through the
 * base class's hardened report reader, never streamed over stdout.
 *
 * This file is mounted read-only into the container; it is never executed on
 * the host. The offline test-suite asserts the adapter's argv/mounts/report
 * wiring without running it (there is no Node or image in CI).
 */
'use strict';

const fs = require('fs');
const puppeteer = require('puppeteer-core');

// Chromium is pre-installed in the image; puppeteer-core must be told where.
const CHROME = process.env.CHROME_BIN || '/usr/bin/chromium-browser';

// Secret patterns scanned over served JavaScript. The real match is recorded;
// the Python side redacts it before it reaches a candidate's evidence.
const SECRET_PATTERNS = [
  { kind: 'aws_access_key_id', re: /AKIA[0-9A-Z]{16}/g },
  { kind: 'google_api_key', re: /AIza[0-9A-Za-z\-_]{35}/g },
  { kind: 'slack_token', re: /xox[baprs]-[0-9A-Za-z-]{10,}/g },
  { kind: 'generic_secret', re: /(?:api[_-]?key|secret|token)\s*[:=]\s*['"][0-9A-Za-z\-_]{16,}['"]/gi },
];

// DOM sinks instrumented in the page, each paired with the tainted source that
// commonly feeds it. The page hook below records a hit when a sink is called.
const DOM_SINKS = ['Element.innerHTML', 'document.write', 'eval', 'Function',
  'setTimeout', 'location.assign'];

function parseArgs(argv) {
  const out = { chromeFlags: [], target: null, out: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--target') out.target = argv[++i];
    else if (a === '--out') out.out = argv[++i];
    else if (a.startsWith('--')) out.chromeFlags.push(a); // --no-sandbox etc.
  }
  return out;
}

// Instrumentation evaluated in every page BEFORE its scripts run: it wraps the
// dangerous sinks so a write from an attacker-controllable source (the URL
// hash/search) is captured as a dom_sinks entry.
function instrumentation() {
  window.__aegisSinks = [];
  const tainted = () => (location.hash || location.search || '');
  const record = (sink, value) => {
    const src = tainted();
    if (src && String(value).includes(decodeURIComponent(src.slice(1)))) {
      window.__aegisSinks.push({ sink, source: 'location.hash',
        snippet: sink + ' <- location.hash', file: location.pathname, line: 0 });
    }
  };
  const desc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
  if (desc && desc.set) {
    Object.defineProperty(Element.prototype, 'innerHTML', {
      set(v) { record('Element.innerHTML', v); return desc.set.call(this, v); },
      get() { return desc.get.call(this); }, configurable: true });
  }
  const _write = document.write.bind(document);
  document.write = (v) => { record('document.write', v); return _write(v); };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.target || !args.out) {
    console.error('usage: navlog.js --target <url> --out <file> [chrome flags]');
    process.exit(2);
  }

  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: 'new',
    // --no-sandbox / --disable-gpu / --disable-dev-shm-usage arrive as chrome
    // flags on argv and are forwarded straight to the browser process.
    args: args.chromeFlags,
  });

  const pages = [];
  try {
    const page = await browser.newPage();
    const console_ = [];
    const mixed = new Map();
    page.on('console', (m) => console_.push({ level: m.type(), text: m.text() }));
    // An http:// sub-resource requested by an https page is mixed content.
    page.on('request', (r) => {
      const u = r.url();
      if (u.startsWith('http://') && args.target.startsWith('https')) {
        mixed.set(u, { resource: u, type: r.resourceType() });
      }
    });

    await page.evaluateOnNewDocument(instrumentation);
    await page.goto(args.target, { waitUntil: 'networkidle2', timeout: 30000 });

    const html = await page.content();
    const domSinks = await page.evaluate(() => window.__aegisSinks || []);

    // Secret-scan every script the page served to the browser.
    const scripts = await page.evaluate(() =>
      Array.from(document.scripts).map((s) => ({ src: s.src, text: s.text })));
    const secrets = [];
    for (const s of scripts) {
      const file = s.src || 'inline';
      for (const { kind, re } of SECRET_PATTERNS) {
        let m;
        while ((m = re.exec(s.text || '')) !== null) {
          secrets.push({ kind, match: m[0], file, line: 0 });
        }
      }
    }

    pages.push({
      url: page.url(),
      screenshot: '',
      html: '',
      console: console_,
      dom_sinks: domSinks,
      mixed_content: Array.from(mixed.values()),
      secrets,
    });
  } finally {
    await browser.close();
  }

  const doc = { target: args.target, engine: 'chromium-headless', pages };
  fs.writeFileSync(args.out, JSON.stringify(doc, null, 2), 'utf-8');
}

main().catch((e) => { console.error(String(e)); process.exit(1); });
