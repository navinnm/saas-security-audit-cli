/**
 * Dependency-free PDF report (A4). Uses the PDF standard fonts (Helvetica, Courier) with
 * WinAnsi encoding, vector shapes, Flate-compressed pages, and running headers/footers.
 */
import { deflateSync } from "node:zlib";
import type { Finding } from "./engine.js";
import type { Result } from "./report.js";
import { CLI_VERSION as VERSION } from "./version.js";
import { buildView, CONTROL_SHORT, formatDate, SEVERITY_ORDER, type CoverageRow } from "./view.js";

// ---------- low-level PDF writer ----------

type FontKey = "F1" | "F2" | "F3"; // Helvetica, Helvetica-Bold, Courier
const PAGE_W = 595.28;
const PAGE_H = 841.89;

const HELV = "278,278,355,556,556,889,667,191,333,333,389,584,278,333,278,278,556,556,556,556,556,556,556,556,556,556,278,278,584,584,584,556,1015,667,667,722,722,667,611,778,722,278,500,667,556,833,722,778,667,778,722,667,611,722,667,944,667,667,611,278,278,278,469,556,333,556,556,500,556,556,278,556,556,222,222,500,222,833,556,556,556,556,333,500,278,556,500,722,500,500,500,334,260,334,584".split(",").map(Number);
const HELV_B = "278,333,474,556,556,889,722,238,333,333,389,584,278,333,278,278,556,556,556,556,556,556,556,556,556,556,333,333,584,584,584,611,975,722,722,722,722,667,611,778,722,278,556,722,611,833,722,778,667,778,722,667,611,722,667,944,667,667,611,333,278,333,584,556,333,556,611,556,611,556,333,611,611,278,278,556,278,889,611,611,611,611,389,556,333,611,556,778,556,556,500,389,280,389,584".split(",").map(Number);
// Non-ASCII characters available in WinAnsiEncoding: [code, width].
const WIN_ANSI: Record<string, [number, number]> = {
  "•": [149, 350], "–": [150, 556], "—": [151, 1000], "…": [133, 1000], "‘": [145, 222], "’": [146, 222],
  "“": [147, 333], "”": [148, 333], "·": [183, 278], "×": [215, 584], "©": [169, 737], "°": [176, 400],
};
const TRANSLIT: Record<string, string> = { "→": "->", "←": "<-", "✔": "", "✓": "", "≥": ">=", "≤": "<=", "≠": "!=", "▸": ">", "▾": "v", "◍": "*", "◌": "o", "⟦": "[", "⟧": "]" };

function normalize(s: string): string {
  return [...s].map((ch) => TRANSLIT[ch] ?? ch).join("");
}

function charWidth(ch: string, font: FontKey): number {
  if (font === "F3") return 600;
  const code = ch.codePointAt(0)!;
  if (code >= 32 && code <= 126) return (font === "F2" ? HELV_B : HELV)[code - 32];
  if (WIN_ANSI[ch]) return WIN_ANSI[ch][1];
  return 556;
}

export function textWidth(s: string, font: FontKey, size: number): number {
  let w = 0;
  for (const ch of normalize(s)) w += charWidth(ch, font);
  return (w * size) / 1000;
}

function pdfString(s: string): string {
  let out = "(";
  for (const ch of normalize(s)) {
    let code = ch.codePointAt(0)!;
    if (WIN_ANSI[ch]) code = WIN_ANSI[ch][0];
    else if (code > 255 || (code > 126 && code < 160)) code = 63; // '?'
    if (code === 40 || code === 41 || code === 92) out += "\\" + String.fromCharCode(code);
    else if (code < 32 || code > 126) out += "\\" + code.toString(8).padStart(3, "0");
    else out += String.fromCharCode(code);
  }
  return out + ")";
}

const rgb = (hex: string) => {
  const n = Number.parseInt(hex.slice(1), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((v) => (v / 255).toFixed(3)).join(" ");
};
const f2 = (n: number) => (Math.round(n * 100) / 100).toString();

class PdfDoc {
  pages: string[][] = [];
  private cur: string[] = [];

  newPage(): void {
    this.cur = [];
    this.pages.push(this.cur);
  }
  raw(op: string): void { this.cur.push(op); }

  rect(x: number, y: number, w: number, h: number, fill: string): void {
    this.raw(`${rgb(fill)} rg ${f2(x)} ${f2(PAGE_H - y - h)} ${f2(w)} ${f2(h)} re f`);
  }
  roundRect(x: number, y: number, w: number, h: number, r: number, fill: string | null, stroke?: string, lw = 0.6): void {
    const k = 0.5523 * r;
    const X = x, Y = PAGE_H - y - h;
    const p = [
      `${f2(X + r)} ${f2(Y)} m`, `${f2(X + w - r)} ${f2(Y)} l`,
      `${f2(X + w - r + k)} ${f2(Y)} ${f2(X + w)} ${f2(Y + r - k)} ${f2(X + w)} ${f2(Y + r)} c`,
      `${f2(X + w)} ${f2(Y + h - r)} l`,
      `${f2(X + w)} ${f2(Y + h - r + k)} ${f2(X + w - r + k)} ${f2(Y + h)} ${f2(X + w - r)} ${f2(Y + h)} c`,
      `${f2(X + r)} ${f2(Y + h)} l`,
      `${f2(X + r - k)} ${f2(Y + h)} ${f2(X)} ${f2(Y + h - r + k)} ${f2(X)} ${f2(Y + h - r)} c`,
      `${f2(X)} ${f2(Y + r)} l`,
      `${f2(X)} ${f2(Y + r - k)} ${f2(X + r - k)} ${f2(Y)} ${f2(X + r)} ${f2(Y)} c h`,
    ].join(" ");
    const paint = fill && stroke ? "B" : fill ? "f" : "S";
    this.raw(`${fill ? rgb(fill) + " rg " : ""}${stroke ? rgb(stroke) + " RG " + lw + " w " : ""}${p} ${paint}`);
  }
  line(x1: number, y1: number, x2: number, y2: number, color: string, width = 0.5): void {
    this.raw(`${rgb(color)} RG ${width} w ${f2(x1)} ${f2(PAGE_H - y1)} m ${f2(x2)} ${f2(PAGE_H - y2)} l S`);
  }
  text(x: number, baseline: number, s: string, font: FontKey, size: number, color: string): void {
    if (!s) return;
    this.raw(`BT /${font} ${size} Tf ${rgb(color)} rg ${f2(x)} ${f2(PAGE_H - baseline)} Td ${pdfString(s)} Tj ET`);
  }
  textRight(xRight: number, baseline: number, s: string, font: FontKey, size: number, color: string): void {
    this.text(xRight - textWidth(s, font, size), baseline, s, font, size, color);
  }
  textCenter(xCenter: number, baseline: number, s: string, font: FontKey, size: number, color: string): void {
    this.text(xCenter - textWidth(s, font, size) / 2, baseline, s, font, size, color);
  }
  /** Horizontal gradient strip from `from` to `to`. */
  gradient(x: number, y: number, w: number, h: number, from: string, to: string, steps = 60): void {
    const a = rgb(from).split(" ").map(Number);
    const b = rgb(to).split(" ").map(Number);
    const sw = w / steps;
    for (let i = 0; i < steps; i++) {
      const t = i / (steps - 1);
      const col = a.map((v, j) => (v + (b[j] - v) * t).toFixed(3)).join(" ");
      this.raw(`${col} rg ${f2(x + i * sw)} ${f2(PAGE_H - y - h)} ${f2(sw + 0.4)} ${f2(h)} re f`);
    }
  }

  build(info: { title: string; subject: string }): Buffer {
    const chunks: Buffer[] = [];
    const offsets: number[] = [];
    let length = 0;
    const push = (b: Buffer | string) => {
      const buf = typeof b === "string" ? Buffer.from(b, "latin1") : b;
      chunks.push(buf);
      length += buf.length;
    };
    const obj = (n: number, body: Buffer | string) => {
      offsets[n] = length;
      push(`${n} 0 obj\n`);
      push(body);
      push("\nendobj\n");
    };
    push("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");
    const fonts = ["Helvetica", "Helvetica-Bold", "Courier"];
    const pageCount = this.pages.length;
    const firstPage = 6;
    const kids = this.pages.map((_, i) => `${firstPage + i * 2} 0 R`).join(" ");
    obj(1, "<< /Type /Catalog /Pages 2 0 R >>");
    obj(2, `<< /Type /Pages /Kids [${kids}] /Count ${pageCount} >>`);
    fonts.forEach((name, i) => obj(3 + i, `<< /Type /Font /Subtype /Type1 /BaseFont /${name} /Encoding /WinAnsiEncoding >>`));
    this.pages.forEach((ops, i) => {
      const pageObj = firstPage + i * 2;
      const data = deflateSync(Buffer.from(ops.join("\n"), "latin1"));
      obj(pageObj, `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] ` +
        `/Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents ${pageObj + 1} 0 R >>`);
      obj(pageObj + 1, Buffer.concat([Buffer.from(`<< /Length ${data.length} /Filter /FlateDecode >>\nstream\n`, "latin1"), data, Buffer.from("\nendstream", "latin1")]));
    });
    const infoObj = firstPage + pageCount * 2;
    const d = new Date();
    const stamp = `D:${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, "0")}${String(d.getUTCDate()).padStart(2, "0")}` +
      `${String(d.getUTCHours()).padStart(2, "0")}${String(d.getUTCMinutes()).padStart(2, "0")}${String(d.getUTCSeconds()).padStart(2, "0")}Z`;
    obj(infoObj, `<< /Title ${pdfString(info.title)} /Subject ${pdfString(info.subject)} /Producer (saas-security-audit ${VERSION}) /Creator (saas-security-audit) /CreationDate (${stamp}) >>`);
    const xref = length;
    const count = infoObj + 1;
    let table = `xref\n0 ${count}\n0000000000 65535 f \n`;
    for (let n = 1; n < count; n++) table += `${String(offsets[n]).padStart(10, "0")} 00000 n \n`;
    push(table);
    push(`trailer\n<< /Size ${count} /Root 1 0 R /Info ${infoObj} 0 R >>\nstartxref\n${xref}\n%%EOF\n`);
    return Buffer.concat(chunks);
  }
}

/** Greedy word wrap; very long tokens (paths, code) are broken by character. */
export function wrap(s: string, font: FontKey, size: number, maxWidth: number, maxLines = Infinity): string[] {
  const lines: string[] = [];
  let cur = "";
  const pushLine = (l: string) => lines.push(l);
  for (const word of normalize(s).split(/\s+/).filter(Boolean)) {
    const candidate = cur ? cur + " " + word : word;
    if (textWidth(candidate, font, size) <= maxWidth) {
      cur = candidate;
      continue;
    }
    if (cur) pushLine(cur);
    cur = "";
    let piece = "";
    for (const ch of word) {
      if (textWidth(piece + ch, font, size) > maxWidth && piece) {
        pushLine(piece);
        piece = "";
      }
      piece += ch;
    }
    cur = piece;
  }
  if (cur) pushLine(cur);
  if (lines.length > maxLines) {
    const kept = lines.slice(0, maxLines);
    let last = kept[maxLines - 1];
    while (last && textWidth(last + "…", font, size) > maxWidth) last = last.slice(0, -1);
    kept[maxLines - 1] = last + "…";
    return kept;
  }
  return lines;
}

// ---------- report layout ----------

const M = 44;
const CW = PAGE_W - 2 * M;
const BOTTOM = PAGE_H - 54;
const C = {
  ink: "#0f172a", dim: "#64748b", faint: "#94a3b8", line: "#e2e8f0", soft: "#f1f5f9", panel: "#f8fafc",
  navy: "#0b1020", navy2: "#0d1628", brand1: "#22d3ee", brand2: "#8b5cf6", amber: "#fbb024", tile: "#2b5a80",
  beam: "#7decff", ok: "#16a34a", warnBg: "#fef3c7", warnInk: "#92400e",
};
const SEV: Record<string, { color: string; label: string; ink: string }> = {
  Critical: { color: "#dc2626", label: "CRITICAL", ink: "#ffffff" },
  High: { color: "#ea580c", label: "HIGH", ink: "#ffffff" },
  Medium: { color: "#ca8a04", label: "MEDIUM", ink: "#ffffff" },
  Low: { color: "#2563eb", label: "LOW", ink: "#ffffff" },
  Informational: { color: "#64748b", label: "INFO", ink: "#ffffff" },
};

class Layout {
  doc = new PdfDoc();
  y = 0;
  private onNewPage: (() => void) | null = null;

  constructor(private project: string) {}

  firstPage(): void {
    this.doc.newPage();
  }
  pageBreak(): void {
    this.doc.newPage();
    this.runningHeader();
    this.y = 70;
    this.onNewPage?.();
  }
  ensure(h: number): boolean {
    if (this.y + h > BOTTOM) {
      this.pageBreak();
      return true;
    }
    return false;
  }
  /** Re-draw something (e.g. a table header) at the top of every new page until cleared. */
  repeatOnNewPage(fn: (() => void) | null): void { this.onNewPage = fn; }

  runningHeader(): void {
    const d = this.doc;
    d.gradient(0, 0, PAGE_W, 3, C.brand1, C.brand2);
    d.text(M, 34, "SaaS Security Audit Report", "F2", 9, C.ink);
    d.textRight(PAGE_W - M, 34, this.project, "F1", 9, C.dim);
    d.line(M, 44, PAGE_W - M, 44, C.line);
  }

  footers(): void {
    const total = this.doc.pages.length;
    this.doc.pages.forEach((ops, i) => {
      const fy = PAGE_H - 28;
      ops.push(`${rgb(C.line)} RG 0.5 w ${f2(M)} ${f2(PAGE_H - (fy - 12))} m ${f2(PAGE_W - M)} ${f2(PAGE_H - (fy - 12))} l S`);
      const left = `saas-security-audit v${VERSION} · offline static analysis · secret values redacted`;
      ops.push(`BT /F1 7.5 Tf ${rgb(C.faint)} rg ${f2(M)} ${f2(PAGE_H - fy)} Td ${pdfString(left)} Tj ET`);
      const right = `Page ${i + 1} of ${total}`;
      ops.push(`BT /F1 7.5 Tf ${rgb(C.faint)} rg ${f2(PAGE_W - M - textWidth(right, "F1", 7.5))} ${f2(PAGE_H - fy)} Td ${pdfString(right)} Tj ET`);
    });
  }

  heading(title: string, count?: string, intro?: string): void {
    this.ensure(intro ? 64 : 44);
    this.y += 14;
    this.doc.text(M, this.y + 12, title, "F2", 13, C.ink);
    if (count) this.doc.text(M + textWidth(title, "F2", 13) + 7, this.y + 12, count, "F1", 10, C.faint);
    this.y += 20;
    this.doc.gradient(M, this.y, 36, 2, C.brand1, C.brand2, 12);
    this.y += 10;
    if (intro) {
      for (const l of wrap(intro, "F1", 8.5, CW)) {
        this.doc.text(M, this.y + 9, l, "F1", 8.5, C.dim);
        this.y += 12;
      }
      this.y += 4;
    }
  }
}

function drawLogo(d: PdfDoc, x: number, y: number, size: number): void {
  const s = size / 64;
  // Draw in the SVG's 64-unit space, flipped so y grows downward.
  d.raw(`q ${f2(s)} 0 0 ${f2(-s)} ${f2(x)} ${f2(PAGE_H - y)} cm`);
  d.raw(`${rgb(C.navy2)} rg ${rgb(C.brand1)} RG 3.5 w 32 4 m 24 7 16 7 9 6 c 9 30 l 9 45 19 54 32 60 c 45 54 55 45 55 30 c 55 6 l 48 7 40 7 32 4 c h B`);
  const tile = (tx: number, ty: number, col: string) => d.raw(`${rgb(col)} rg ${tx} ${ty} 11 11 re f`);
  tile(19, 18, C.tile); tile(34, 18, C.tile); tile(19, 33, C.tile); tile(34, 33, C.amber);
  d.raw(`${rgb(C.beam)} rg 12 37.5 40 2 re f`);
  d.raw("Q");
}

function pill(d: PdfDoc, x: number, y: number, sev: string): void {
  const p = SEV[sev];
  const w = textWidth(p.label, "F2", 6.5) + 10;
  d.roundRect(x, y, w, 12, 6, p.color);
  d.text(x + 5, y + 8.6, p.label, "F2", 6.5, p.ink);
}

function findingsTable(L: Layout, findings: Finding[], withEvidence: boolean): void {
  const cols = { sev: M, rule: M + 62, loc: M + 108, issue: M + 268 };
  const locW = cols.issue - cols.loc - 10;
  const issueW = M + CW - cols.issue;
  const header = () => {
    L.doc.rect(M, L.y, CW, 18, C.soft);
    for (const [label, x] of [["SEVERITY", cols.sev], ["RULE", cols.rule], ["LOCATION", cols.loc], ["ISSUE", cols.issue]] as const) {
      L.doc.text(x + 6, L.y + 12, label, "F2", 6.5, C.dim);
    }
    L.y += 22;
  };
  L.ensure(60);
  header();
  L.repeatOnNewPage(header);
  for (const f of findings) {
    const locText = `${f.file}:${f.line}${f.context === "source" ? "" : `  (${f.context})`}`;
    const locLines = wrap(locText, "F3", 7.5, locW - 6, 3);
    const issueLines = wrap(f.title, "F2", 8.5, issueW - 6, 3);
    const metaLine = `C${f.controls[0]} ${CONTROL_SHORT[f.controls[0] - 1]} · confidence ${f.confidence}`;
    const evLines = withEvidence ? wrap(f.evidence, "F3", 7, issueW - 16, 3) : [];
    const leftH = locLines.length * 10;
    const rightH = issueLines.length * 11 + 11 + (evLines.length ? evLines.length * 9 + 8 : 0);
    const h = Math.max(leftH, rightH, 14) + 10;
    L.ensure(h);
    const top = L.y + 3;
    pill(L.doc, cols.sev + 6, top, f.severity);
    L.doc.text(cols.rule + 6, top + 9, f.id, "F3", 7.5, C.dim);
    locLines.forEach((l, i) => L.doc.text(cols.loc + 6, top + 9 + i * 10, l, "F3", 7.5, C.ink));
    let iy = top + 9;
    for (const l of issueLines) {
      L.doc.text(cols.issue + 6, iy, l, "F2", 8.5, C.ink);
      iy += 11;
    }
    L.doc.text(cols.issue + 6, iy, metaLine, "F1", 7, C.faint);
    iy += 4;
    if (evLines.length) {
      const boxH = evLines.length * 9 + 5;
      L.doc.roundRect(cols.issue + 6, iy, issueW - 6, boxH, 3, C.panel, C.line, 0.4);
      evLines.forEach((l, i) => L.doc.text(cols.issue + 11, iy + 9 + i * 9, l, "F3", 7, C.dim));
    }
    L.y += h;
    L.doc.line(M, L.y - 2, M + CW, L.y - 2, C.line, 0.4);
  }
  L.repeatOnNewPage(null);
  L.y += 6;
}

function coverageTable(L: Layout, rows: CoverageRow[], leadsIds: Set<number>, noSignalIds: Set<number>): void {
  const cols = { id: M, name: M + 34, status: M + 262, leads: M + 372, sig: M + 420 };
  const header = () => {
    L.doc.rect(M, L.y, CW, 18, C.soft);
    for (const [label, x] of [["", cols.id], ["CONTROL", cols.name], ["STATUS", cols.status], ["LEADS", cols.leads], ["SIGNALS SRC / TEST", cols.sig]] as const) {
      L.doc.text(x + 6, L.y + 12, label, "F2", 6.5, C.dim);
    }
    L.y += 20;
  };
  L.ensure(80);
  header();
  L.repeatOnNewPage(header);
  for (const r of rows) {
    L.ensure(19);
    const base = L.y + 12;
    L.doc.text(cols.id + 6, base, `C${r.id}`, "F3", 7.5, C.faint);
    L.doc.text(cols.name + 6, base, wrap(r.name, "F1", 8.5, cols.status - cols.name - 10, 1)[0], "F1", 8.5, C.ink);
    const [label, bg, ink] = leadsIds.has(r.id) ? ["Leads to verify", C.warnBg, C.warnInk]
      : noSignalIds.has(r.id) ? ["No signals found", C.soft, C.dim] : ["Not verified", C.soft, C.dim];
    const w = textWidth(label, "F1", 7) + 12;
    L.doc.roundRect(cols.status + 6, L.y + 3.5, w, 12, 6, bg, C.line, 0.4);
    L.doc.text(cols.status + 12, base, label, "F1", 7, ink);
    L.doc.text(cols.leads + 6, base, r.leads ? String(r.leads) : "–", r.leads ? "F2" : "F1", 8.5, r.leads ? C.warnInk : C.faint);
    L.doc.text(cols.sig + 6, base, r.signals ? `${r.signals.source_count} / ${r.signals.test_count}` : "—", "F1", 8.5, C.dim);
    L.y += 19;
    L.doc.line(M, L.y, M + CW, L.y, C.line, 0.3);
  }
  L.repeatOnNewPage(null);
  L.y += 8;
}

export function renderPdf(result: Result, opts: { includeTests?: boolean; now?: Date } = {}): Buffer {
  const v = buildView(result, Boolean(opts.includeTests), opts.now);
  const L = new Layout(v.project);
  const d = L.doc;
  L.firstPage();

  // Cover band
  d.rect(0, 0, PAGE_W, 128, C.navy);
  d.gradient(0, 128, PAGE_W, 3.5, C.brand1, C.brand2);
  drawLogo(d, M, 30, 62);
  d.text(M + 78, 54, "SaaS Security Audit Report", "F2", 22, "#ffffff");
  d.text(M + 78, 74, v.project, "F2", 11.5, "#e2e8f0");
  d.text(M + 78, 90, wrap(result.root, "F1", 8.5, CW - 80, 1)[0], "F1", 8.5, C.faint);
  d.text(M + 78, 104, `${formatDate(v.generatedAt)}  ·  saas-security-audit v${VERSION}  ·  offline static analysis`, "F1", 8.5, C.faint);
  L.y = 152;

  // Posture
  const postureColor = { critical: SEV.Critical.color, high: SEV.High.color, medium: SEV.Medium.color, low: C.ok }[v.posture.level];
  const detail = wrap(v.posture.detail, "F1", 9.5, CW - 22);
  const postureH = 30 + detail.length * 13;
  d.roundRect(M, L.y, CW, postureH, 8, C.panel, C.line, 0.5);
  d.rect(M, L.y, 4, postureH, postureColor);
  d.text(M + 16, L.y + 21, v.posture.headline, "F2", 14, C.ink);
  detail.forEach((l, i) => d.text(M + 16, L.y + 37 + i * 13, l, "F1", 9.5, C.dim));
  L.y += postureH + 14;

  // Severity cards
  const gap = 10;
  const cardW = (CW - gap * 4) / 5;
  SEVERITY_ORDER.forEach((sev, i) => {
    const x = M + i * (cardW + gap);
    const n = v.sourceCounts[sev] ?? 0;
    d.roundRect(x, L.y, cardW, 58, 8, C.panel, C.line, 0.5);
    d.rect(x, L.y + 8, 3, 42, SEV[sev].color);
    d.text(x + 14, L.y + 31, String(n), "F2", 22, n ? SEV[sev].color : "#cbd5e1");
    d.text(x + 14, L.y + 46, SEV[sev].label, "F2", 6.5, C.dim);
  });
  L.y += 70;
  d.text(M, L.y + 2, "Counts are for findings in source code. Test files and gitignored local env files are listed separately.", "F1", 7.5, C.faint);
  L.y += 12;

  // Stacked severity bar
  const total = SEVERITY_ORDER.reduce((a, s) => a + (v.sourceCounts[s] ?? 0), 0);
  d.roundRect(M, L.y, CW, 8, 4, C.soft);
  if (total) {
    let x = M;
    for (const sev of SEVERITY_ORDER) {
      const w = (CW * (v.sourceCounts[sev] ?? 0)) / total;
      if (w > 0) { d.rect(x, L.y, w, 8, SEV[sev].color); x += w; }
    }
  }
  L.y += 22;

  // Key facts
  const facts = [
    [`${result.stats.files_scanned}`, "files analysed"],
    [`${v.controlsWithLeads}/22`, "controls with leads"],
    [`${v.hidden.length}`, "leads in tests / local env"],
    [`${result.stats.suppressed}`, "suppressed inline"],
  ];
  const fw = CW / facts.length;
  facts.forEach(([n, label], i) => {
    d.text(M + i * fw, L.y + 14, n, "F2", 15, C.ink);
    d.text(M + i * fw, L.y + 27, label, "F1", 7.5, C.dim);
  });
  L.y += 36;
  if (v.stack.length) {
    for (const l of wrap(`Stack detected: ${v.stack.join(" · ")}`, "F1", 8.5, CW)) {
      d.text(M, L.y + 9, l, "F1", 8.5, C.dim);
      L.y += 12;
    }
  }

  // Findings
  L.heading("Findings in source code", String(v.shown.length),
    "Each finding is a lead to validate in code, not a confirmed vulnerability. Evidence is redacted; secret values never appear in this report.");
  if (v.shown.length) findingsTable(L, v.shown, true);
  else {
    d.text(M, L.y + 10, "No leads in source code. That is not proof of security — verify the controls below.", "F1", 9, C.dim);
    L.y += 20;
  }

  // How to fix
  if (v.guidance.length) {
    L.heading("How to fix", `${v.guidance.length} rules`);
    for (const g of v.guidance) {
      const lines = wrap(g.guidance, "F1", 8.5, CW - 70);
      L.ensure(18 + lines.length * 11);
      d.text(M, L.y + 10, g.id, "F3", 8, C.faint);
      d.text(M + 56, L.y + 10, g.title + (g.count > 1 ? `  ×${g.count}` : ""), "F2", 9, C.ink);
      lines.forEach((l, i) => d.text(M + 56, L.y + 23 + i * 11, l, "F1", 8.5, C.dim));
      L.y += 18 + lines.length * 11 + 6;
    }
  }

  // Test / local env findings
  if (v.hidden.length) {
    L.heading("Test files & local env files", String(v.hidden.length),
      "Usually intentional samples (fixtures, mocks) or secrets in gitignored local env files. Review them, but they don't count toward the source-code totals.");
    findingsTable(L, v.hidden, false);
  }

  // Coverage
  L.heading("Control coverage", "22 controls",
    "PASS is never automatic: a control passes only when enforcement is located in code and proven by a negative test. Signals show where enforcement probably lives.");
  const rows = [...v.coverage.leads, ...v.coverage.noSignals, ...v.coverage.notVerified].sort((a, b) => a.id - b.id);
  coverageTable(L, rows, new Set(v.coverage.leads.map((r) => r.id)), new Set(v.coverage.noSignals.map((r) => r.id)));

  // Inventory & tools
  const inv = result.inventory;
  L.heading("Inventory & recommended tools");
  const invLines = [
    `Dependency manifests: ${inv.manifests.join(", ") || "none found"}`,
    `Test files: ${inv.test_files}  ·  CI files: ${inv.ci_files.join(", ") || "none found"}`,
  ];
  for (const l of invLines.flatMap((t) => wrap(t, "F1", 8.5, CW))) {
    L.ensure(12);
    d.text(M, L.y + 9, l, "F1", 8.5, C.ink);
    L.y += 12;
  }
  L.y += 6;
  for (const t of inv.recommended_tools) {
    L.ensure(14);
    d.text(M, L.y + 9, t.command, "F3", 8, C.ink);
    d.textRight(M + CW, L.y + 9, `${t.installed ? "installed" : "not installed"} · ${t.needs_network ? "needs network" : "offline"}`, "F1", 7.5, C.dim);
    L.y += 14;
  }

  // Method & limitations
  L.heading("Method & limitations");
  const notes = [
    "Read-only static analysis on the local machine. No code was executed and nothing was sent anywhere.",
    ...result.limitations,
    "For verification, fixes, and regression tests, run /saas-security-audit:audit in Claude Code.",
  ];
  for (const n of notes) {
    const lines = wrap(n, "F1", 8.5, CW - 12);
    L.ensure(lines.length * 12 + 4);
    d.text(M, L.y + 9, "•", "F1", 8.5, C.faint);
    lines.forEach((l, i) => d.text(M + 12, L.y + 9 + i * 12, l, "F1", 8.5, C.dim));
    L.y += lines.length * 12 + 4;
  }

  L.footers();
  return d.build({ title: `SaaS Security Audit — ${v.project}`, subject: `Security audit report for ${result.root}` });
}
