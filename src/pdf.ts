/**
 * Dependency-free PDF report (A4). Uses the PDF standard fonts (Helvetica, Courier) with
 * WinAnsi encoding, vector shapes, Flate-compressed pages, and running headers/footers.
 */
import { deflateSync } from "node:zlib";
import type { Result } from "./report.js";
import { depsLine } from "./report.js";
import { R, VERSION as RULES_VERSION } from "./rules.js";
import { CLI_VERSION as VERSION } from "./version.js";
import { buildView, checklistLines, controlLabel, coverageLines, formatDate, SEVERITY_ORDER, standardSections, type Issue } from "./view.js";

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
// Laid out like a security assessment document: a title block, numbered sections, hairline rules,
// one accent colour, and severity as a small square beside its name.

const M = 48;
const CW = PAGE_W - 2 * M;
const BOTTOM = PAGE_H - 58;
const C = {
  ink: "#111827", body: "#374151", muted: "#6b7280", faint: "#9ca3af", rule: "#e5e7eb", rule2: "#d1d5db", shade: "#f9fafb",
  accent: "#1f3a5f", ok: "#166534", warn: "#b45309",
};
const SEV: Record<string, { color: string; label: string }> = {
  Critical: { color: "#991b1b", label: "Critical" },
  High: { color: "#b45309", label: "High" },
  Medium: { color: "#a16207", label: "Medium" },
  Low: { color: "#1d4ed8", label: "Low" },
  Informational: { color: "#4b5563", label: "Informational" },
};
const RATING: Record<string, { label: string; color: string }> = {
  critical: { label: "Critical", color: SEV.Critical.color }, high: { label: "High", color: SEV.High.color },
  medium: { label: "Medium", color: SEV.Medium.color }, low: { label: "Low", color: C.ok },
};

class Layout {
  doc = new PdfDoc();
  y = 0;
  section = 0;
  private onNewPage: (() => void) | null = null;

  constructor(private project: string) {}

  firstPage(): void {
    this.doc.newPage();
  }
  pageBreak(): void {
    this.doc.newPage();
    this.runningHeader();
    this.y = 72;
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
    d.text(M, 36, "Source code security review", "F2", 8, C.accent);
    d.textRight(PAGE_W - M, 36, this.project, "F1", 8, C.muted);
    d.line(M, 44, PAGE_W - M, 44, C.rule2, 0.5);
  }

  footers(date: string): void {
    const total = this.doc.pages.length;
    this.doc.pages.forEach((ops, i) => {
      const fy = PAGE_H - 30;
      ops.push(`${rgb(C.rule2)} RG 0.5 w ${f2(M)} ${f2(PAGE_H - (fy - 12))} m ${f2(PAGE_W - M)} ${f2(PAGE_H - (fy - 12))} l S`);
      const left = `Confidential · saas-security-audit v${VERSION} · secret values redacted · ${date}`;
      ops.push(`BT /F1 7 Tf ${rgb(C.muted)} rg ${f2(M)} ${f2(PAGE_H - fy)} Td ${pdfString(left)} Tj ET`);
      const right = `Page ${i + 1} of ${total}`;
      ops.push(`BT /F1 7 Tf ${rgb(C.muted)} rg ${f2(PAGE_W - M - textWidth(right, "F1", 7))} ${f2(PAGE_H - fy)} Td ${pdfString(right)} Tj ET`);
    });
  }

  /** "3  Control coverage" with a rule under it; numbered in the order sections appear. */
  heading(title: string, intro?: string): void {
    this.ensure(intro ? 74 : 50);
    this.y += 18;
    const no = String(++this.section);
    this.doc.text(M, this.y + 12, no, "F2", 12.5, C.accent);
    this.doc.text(M + 22, this.y + 12, title, "F2", 12.5, C.ink);
    this.y += 19;
    this.doc.line(M, this.y, M + CW, this.y, C.rule2, 0.6);
    this.y += 10;
    if (intro) this.para(intro, 8.5, C.muted);
  }

  sub(title: string): void {
    this.ensure(34);
    this.y += 6;
    this.doc.text(M, this.y + 10, title, "F2", 9.5, C.ink);
    this.y += 16;
  }

  para(s: string, size = 8.5, color = C.body, indent = 0): void {
    for (const l of wrap(s, "F1", size, CW - indent)) {
      this.ensure(size + 4);
      this.doc.text(M + indent, this.y + size, l, "F1", size, color);
      this.y += size + 3.5;
    }
    this.y += 5;
  }

  /** Table header row on a light band, repeated on later pages. */
  tableHeader(cols: Array<[string, number, ("left" | "right")?]>): () => void {
    return () => {
      this.doc.rect(M, this.y, CW, 17, C.shade);
      this.doc.line(M, this.y + 17, M + CW, this.y + 17, C.rule2, 0.5);
      for (const [label, x, align] of cols) {
        if (align === "right") this.doc.textRight(x, this.y + 11.5, label.toUpperCase(), "F2", 6.5, C.muted);
        else this.doc.text(x, this.y + 11.5, label.toUpperCase(), "F2", 6.5, C.muted);
      }
      this.y += 21;
    };
  }
}

/** A small square in the severity's colour and its name: quiet, readable in grey print too. */
function sevMark(d: PdfDoc, x: number, baseline: number, sev: string, size = 8): void {
  const p = SEV[sev];
  d.rect(x, baseline - size + 1.2, size - 1.6, size - 1.6, p.color);
  d.text(x + size + 2, baseline, p.label, "F2", size, p.color);
}

/** Locations printed per finding; the JSON output and `saas-audit show <rule>` have every one. */
const MAX_LOCATIONS = 25;

/** One finding: heading row, facts, risk, locations with evidence, recommendation, verify step, references. */
function issueBlock(L: Layout, i: Issue): void {
  const d = L.doc;
  const labelled = (label: string, text: string, color = C.body) => {
    const lines = wrap(text, "F1", 8.5, CW);
    L.ensure(14 + Math.min(lines.length, 3) * 11.5);
    d.text(M, L.y + 8, label.toUpperCase(), "F2", 6.5, C.muted);
    L.y += 12;
    for (const l of lines) {
      L.ensure(11.5);
      d.text(M, L.y + 8.5, l, "F1", 8.5, color);
      L.y += 11.5;
    }
    L.y += 4;
  };
  const titleLines = wrap(i.title, "F2", 11, CW - 130, 2);
  L.ensure(46 + titleLines.length * 14);
  L.y += 6;
  d.line(M, L.y, M + CW, L.y, C.rule2, 0.6);
  L.y += 6;
  d.text(M, L.y + 11, i.ref, "F3", 9, C.muted);
  titleLines.forEach((l, k) => d.text(M + 44, L.y + 11 + k * 14, l, "F2", 11, C.ink));
  const sw = textWidth(SEV[i.severity].label, "F2", 8.5) + 12;
  sevMark(d, M + CW - sw, L.y + 11, i.severity, 8.5);
  L.y += titleLines.length * 14 + 2;
  const facts = `Confidence ${i.confidence} · ${controlLabel(i.controls[0])} · ${i.locations.length} location${i.locations.length === 1 ? "" : "s"} in ${i.files} file${i.files === 1 ? "" : "s"} · Rule ${i.id}`;
  for (const l of wrap(facts, "F1", 7.5, CW - 44)) { d.text(M + 44, L.y + 8, l, "F1", 7.5, C.muted); L.y += 10; }
  L.y += 6;
  if (i.risk) labelled("Risk", i.risk);

  L.ensure(30);
  d.text(M, L.y + 8, "AFFECTED LOCATIONS", "F2", 6.5, C.muted);
  L.y += 12;
  for (const f of i.locations.slice(0, MAX_LOCATIONS)) {
    const extra = [i.mixed ? f.severity : "", f.title !== i.title ? f.title : ""].filter(Boolean).join(" · ");
    const locLines = wrap(`${f.file}:${f.line}${extra ? `  (${extra})` : ""}`, "F3", 7.5, CW, 2);
    const evLines = wrap(f.evidence, "F3", 7, CW - 14, 3);
    const boxH = evLines.length * 9 + 6;
    L.ensure(locLines.length * 9.5 + boxH + 6);
    locLines.forEach((l, k) => d.text(M, L.y + 8 + k * 9.5, l, "F3", 7.5, C.body));
    L.y += locLines.length * 9.5 + 2;
    d.rect(M, L.y, CW, boxH, C.shade);
    d.rect(M, L.y, 1.5, boxH, C.rule2);
    evLines.forEach((l, k) => d.text(M + 7, L.y + 9 + k * 9, l, "F3", 7, C.ink));
    L.y += boxH + 5;
  }
  if (i.locations.length > MAX_LOCATIONS) {
    L.ensure(14);
    d.text(M, L.y + 8, `…and ${i.locations.length - MAX_LOCATIONS} more (saas-audit show ${i.id} lists them all)`, "F1", 8, C.muted);
    L.y += 14;
  }
  L.y += 2;
  labelled("Recommendation", i.guidance);
  if (i.verify) labelled("How to verify", i.verify);
  if (i.references.length) {
    for (const l of wrap(i.references.join(" · "), "F1", 7.5, CW)) { L.ensure(10); d.text(M, L.y + 7.5, l, "F1", 7.5, C.muted); L.y += 10; }
  }
  L.y += 8;
}

/** A plain table: header band, one wrapped line per cell, hairlines between rows. */
function simpleTable(L: Layout, cols: Array<{ label: string; x: number; w: number; font?: FontKey; right?: boolean }>, rows: Array<Array<{ text: string; color?: string; font?: FontKey }>>): void {
  const header = L.tableHeader(cols.map((c) => [c.label, c.right ? c.x + c.w : c.x, c.right ? "right" : "left"] as [string, number, ("left" | "right")?]));
  L.ensure(40);
  header();
  L.repeatOnNewPage(header);
  for (const row of rows) {
    const cells = row.map((cell, k) => wrap(cell.text, cell.font ?? cols[k].font ?? "F1", 8, cols[k].w - 6, 4));
    const h = Math.max(...cells.map((c) => c.length)) * 10.5 + 7;
    L.ensure(h);
    cells.forEach((lines, k) => lines.forEach((l, j) => {
      const font = row[k].font ?? cols[k].font ?? "F1";
      const y = L.y + 11 + j * 10.5;
      if (cols[k].right) L.doc.textRight(cols[k].x + cols[k].w, y, l, font, 8, row[k].color ?? C.ink);
      else L.doc.text(cols[k].x, y, l, font, 8, row[k].color ?? C.ink);
    }));
    L.y += h;
    L.doc.line(M, L.y - 2, M + CW, L.y - 2, C.rule, 0.3);
  }
  L.repeatOnNewPage(null);
  L.y += 6;
}

export function renderPdf(result: Result, opts: { includeTests?: boolean; now?: Date } = {}): Buffer {
  const v = buildView(result, Boolean(opts.includeTests), opts.now);
  const L = new Layout(v.project);
  const d = L.doc;
  const date = formatDate(v.generatedAt);
  const inv = result.inventory;
  const own = result.stats.files_scanned - (inv.third_party_files ?? 0);
  L.firstPage();

  // Title block
  d.rect(M, 52, CW, 3.5, C.accent);
  d.text(M, 80, "SOURCE CODE SECURITY REVIEW", "F2", 7.5, C.accent);
  const titleLines = wrap(v.project, "F2", 20, CW);
  titleLines.forEach((l, i) => d.text(M, 106 + i * 24, l, "F2", 20, C.ink));
  L.y = 106 + (titleLines.length - 1) * 24 + 18;
  d.line(M, L.y, M + CW, L.y, C.rule, 0.5);
  L.y += 8;
  const meta: Array<[string, string, FontKey]> = [
    ["Target", result.root, "F3"],
    ["Date", date, "F1"],
    ["Scope", `${own} files of application code${inv.third_party_files ? `, ${inv.third_party_files} files in bundled libraries` : ""}; dependencies ${depsLine(result.dependencies)}`, "F1"],
    ["Method", "Static source review: pattern rules plus code-flow analysis for JavaScript/TypeScript. Read-only; no code was run.", "F1"],
    ["Tool", `saas-security-audit v${VERSION} (rules ${RULES_VERSION})`, "F1"],
  ];
  for (const [k, val, font] of meta) {
    const lines = wrap(val, font, 8.5, CW - 110, 3);
    d.text(M, L.y + 10, k, "F1", 8.5, C.muted);
    lines.forEach((l, i) => d.text(M + 110, L.y + 10 + i * 11, l, font, 8.5, C.ink));
    L.y += lines.length * 11 + 4;
  }
  L.y += 4;
  d.line(M, L.y, M + CW, L.y, C.rule, 0.5);

  // 1 Summary: rating and prose on the left, severity counts on the right, then the key findings.
  L.heading("Summary");
  const colGap = 22;
  const leftW = (CW - colGap) * 0.58;
  const rightX = M + leftW + colGap;
  const rightW = CW - leftW - colGap;
  const top = L.y;
  const rating = RATING[v.posture.level];
  d.rect(M, top, 3, 34, rating.color);
  d.text(M + 12, top + 12, "OVERALL RISK", "F2", 6.5, C.muted);
  d.text(M + 12, top + 28, rating.label, "F2", 14, rating.color);
  let ly = top + 46;
  for (const p of v.summary) {
    for (const l of wrap(p, "F1", 8.5, leftW)) { d.text(M, ly + 8.5, l, "F1", 8.5, C.ink); ly += 11.5; }
    ly += 6;
  }
  let ry = top;
  d.rect(rightX, ry, rightW, 17, C.shade);
  d.line(rightX, ry + 17, rightX + rightW, ry + 17, C.rule2, 0.5);
  d.text(rightX + 6, ry + 11.5, "SEVERITY", "F2", 6.5, C.muted);
  d.textRight(rightX + rightW - 60, ry + 11.5, "ISSUES", "F2", 6.5, C.muted);
  d.textRight(rightX + rightW - 6, ry + 11.5, "LOCATIONS", "F2", 6.5, C.muted);
  ry += 17;
  for (const sev of SEVERITY_ORDER) {
    const list = v.issues.filter((i) => i.severity === sev);
    const n = list.length;
    const base = ry + 13;
    if (n) sevMark(d, rightX + 6, base, sev, 8);
    else { d.rect(rightX + 6, base - 6.8, 6.4, 6.4, C.rule2); d.text(rightX + 16, base, SEV[sev].label, "F1", 8, C.faint); }
    d.textRight(rightX + rightW - 60, base, String(n), n ? "F2" : "F1", 8.5, n ? C.ink : C.faint);
    d.textRight(rightX + rightW - 6, base, String(list.reduce((a, i) => a + i.locations.length, 0)), n ? "F1" : "F1", 8.5, n ? C.ink : C.faint);
    ry += 19;
    d.line(rightX, ry, rightX + rightW, ry, C.rule, 0.3);
  }
  if (v.stack.length) {
    for (const l of wrap(`Stack: ${v.stack.join(", ")}`, "F1", 7.5, rightW)) { d.text(rightX, ry + 12, l, "F1", 7.5, C.muted); ry += 10; }
  }
  L.y = Math.max(ly, ry) + 8;
  if (v.issues.length) {
    L.sub("Key findings");
    simpleTable(L, [{ label: "Ref.", x: M + 6, w: 40, font: "F3" }, { label: "Issue", x: M + 50, w: 300 }, { label: "Severity", x: M + 360, w: 80 }, { label: "Locations", x: M + CW - 66, w: 60, right: true }],
      v.issues.map((i) => [{ text: i.ref, color: C.muted }, { text: i.title }, { text: i.severity, color: SEV[i.severity].color, font: "F2" }, { text: String(i.locations.length) }]));
  }

  // 2 Findings
  L.heading("Findings");
  if (!v.issues.length) L.para("No issues found in the application's own code.", 9, C.muted);
  for (const i of v.issues) issueBlock(L, i);
  if (v.hidden.length) L.para(`${v.hidden.length} further match${v.hidden.length === 1 ? "" : "es"} in test files and gitignored local env files ${v.hidden.length === 1 ? "is" : "are"} not included (--include-tests adds them).`, 8, C.muted);

  // Bundled libraries
  if (v.libraries.length) {
    L.heading("Bundled third-party code", `${v.thirdParty.length} matches are inside libraries copied into the repository. They are not counted as findings: the code belongs to the library, and the fix is to keep the library on a supported, patched release (or install it through a package manager) rather than edit it.`);
    simpleTable(L, [{ label: "Library path", x: M + 6, w: 260, font: "F3" }, { label: "Files", x: M + 270, w: 40, right: true }, { label: "Matches", x: M + 316, w: 46, right: true }, { label: "Rules", x: M + 376, w: CW - 380, font: "F3" }],
      v.libraries.map((l) => [{ text: l.path }, { text: String(l.files) }, { text: String(l.matches) }, { text: l.rules.join(", "), color: C.muted }]));
  }

  // Control coverage
  L.heading("Control coverage", "A control passes only when its enforcement is found in code and covered by a test. A scan cannot show that, so no control is marked as passed.");
  simpleTable(L, [{ label: "Ref.", x: M + 6, w: 30, font: "F3" }, { label: "Control", x: M + 38, w: 236 }, { label: "Result", x: M + 278, w: 150 }, { label: "Findings", x: M + 432, w: CW - 436, font: "F3" }],
    coverageLines(result, v.issues).map((c) => [{ text: `C${c.id}`, color: C.muted }, { text: c.name }, { text: c.result, color: c.found ? C.warn : C.muted, font: c.found ? "F2" : "F1" }, { text: c.refs.join(", ") || "–", color: C.muted }]));

  // Common implementation mistakes
  L.heading("Common implementation mistakes", "Twelve mistakes that turn up most often in quickly built SaaS apps. \"Not found\" means no pattern matched.");
  simpleTable(L, [{ label: "Ref.", x: M + 6, w: 30, font: "F3" }, { label: "Check", x: M + 38, w: 300 }, { label: "Result", x: M + 345, w: CW - 349 }],
    checklistLines(result, v.issues).map((c) => [{ text: c.id, color: C.muted }, { text: c.title }, c.refs.length ? { text: `Found: ${c.refs.join(", ")}`, color: C.warn, font: "F2" } : { text: "Not found", color: C.muted }]));

  // Standards
  L.heading("Standards", result.standards.note);
  const sections = standardSections(result, v.issues).filter((sec) => sec.rows.length);
  if (!sections.length) L.para("No findings to map.", 8.5, C.muted);
  for (const sec of sections) {
    L.sub(sec.title);
    simpleTable(L, [{ label: "ID", x: M + 6, w: 66, font: "F3" }, { label: sec.kind, x: M + 76, w: 300 }, { label: "Findings", x: M + 380, w: CW - 384, font: "F3" }],
      sec.rows.map((r) => [{ text: r.id }, { text: r.name }, { text: r.refs.join(", "), color: C.muted }]));
  }
  const fws = result.standards.frameworks.filter((fw) => fw.requirements.length);
  if (fws.length) {
    L.sub("Compliance frameworks (related requirements)");
    simpleTable(L, [{ label: "Framework", x: M + 6, w: 140, font: "F2" }, { label: "Requirements", x: M + 150, w: CW - 154 }],
      fws.map((fw) => [{ text: fw.name }, { text: fw.requirements.map((r) => `${r.ref}${r.name ? " " + r.name : ""}`).join("; "), color: C.body }]));
  }

  // Scope and limitations
  L.heading("Scope and limitations");
  L.para(`This is an automated static review. Each finding marks code that matches a known weak pattern; a reviewer should confirm it before it is treated as a vulnerability, using the "How to verify" step. ${R.verify_note}`, 8.5, C.body);
  for (const n of result.limitations) {
    const lines = wrap(n, "F1", 8.5, CW - 12);
    L.ensure(lines.length * 12 + 4);
    d.text(M, L.y + 9, "–", "F1", 8.5, C.muted);
    lines.forEach((l, i) => d.text(M + 12, L.y + 9 + i * 12, l, "F1", 8.5, C.body));
    L.y += lines.length * 12 + 3;
  }
  L.y += 6;
  for (const [k, val] of [["Dependency manifests", inv.manifests.join(", ") || "None found"], ["Test files", String(inv.test_files)], ["CI files", inv.ci_files.join(", ") || "None found"]] as const) {
    const lines = wrap(val, "F1", 8.5, CW - 130, 4);
    L.ensure(lines.length * 11 + 4);
    d.text(M, L.y + 9, k, "F1", 8.5, C.muted);
    lines.forEach((l, i) => d.text(M + 130, L.y + 9 + i * 11, l, "F1", 8.5, C.ink));
    L.y += lines.length * 11 + 3;
  }
  L.sub("Further checks worth running");
  for (const t of inv.recommended_tools) {
    L.ensure(15);
    d.text(M + 6, L.y + 9, t.command, "F3", 7.5, C.ink);
    d.textRight(M + CW - 6, L.y + 9, `${t.installed ? "Installed" : "Not installed"} · ${t.needs_network ? "needs network" : "offline"}`, "F1", 7.5, C.muted);
    L.y += 15;
    d.line(M, L.y - 2.5, M + CW, L.y - 2.5, C.rule, 0.3);
  }

  L.footers(date);
  return d.build({ title: `Security review — ${v.project}`, subject: `Source code security review of ${result.root}` });
}
