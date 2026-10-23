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
  critical: { label: "Critical risk", color: SEV.Critical.color }, high: { label: "Elevated risk", color: SEV.High.color },
  medium: { label: "Moderate risk", color: SEV.Medium.color }, low: { label: "Low risk", color: C.ok },
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
    d.text(M, 36, "Security assessment report", "F2", 8, C.accent);
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

  /** "3  Remediation plan" with a rule under it; numbered in the order sections appear. */
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

const fRef = (i: number, total: number) => `F-${String(i + 1).padStart(Math.max(2, String(total).length), "0")}`;

function findingsTable(L: Layout, findings: Finding[], withEvidence: boolean): void {
  const cols = { ref: M + 6, sev: M + 44, body: M + 120, rule: M + CW - 6 };
  const bodyW = cols.rule - 46 - cols.body;
  const header = L.tableHeader([["Ref.", cols.ref], ["Severity", cols.sev], ["Finding and location", cols.body], ["Rule", cols.rule, "right"]]);
  L.ensure(60);
  header();
  L.repeatOnNewPage(header);
  findings.forEach((f, i) => {
    const titleLines = wrap(f.title, "F2", 8.5, bodyW, 3);
    const locText = `${f.file}:${f.line}${f.context === "source" ? "" : `  (${f.context})`}`;
    const locLines = wrap(locText, "F3", 7.5, bodyW, 3);
    const tags = f.standards ? [f.standards.owasp ? `OWASP ${f.standards.owasp}` : "", ...f.standards.owasp_api.map((a) => `OWASP ${a}`), ...f.standards.owasp_llm.map((a) => `OWASP ${a}`), ...f.standards.cwe].filter(Boolean) : [];
    const metaLines = wrap(`C${f.controls[0]} ${CONTROL_SHORT[f.controls[0] - 1]} · confidence ${f.confidence}${tags.length ? " · " + tags.join(" · ") : ""}`, "F1", 7, bodyW);
    const evLines = withEvidence ? wrap(f.evidence, "F3", 7, bodyW - 12, 3) : [];
    const fixLines = withEvidence ? wrap(`Remediation: ${f.guidance}`, "F1", 7.5, bodyW, 4) : [];
    const h = titleLines.length * 11 + locLines.length * 9.5 + metaLines.length * 9 + (evLines.length ? evLines.length * 9 + 10 : 0) + fixLines.length * 10 + 14;
    L.ensure(h);
    const top = L.y + 10;
    L.doc.text(cols.ref, top, fRef(i, findings.length), "F3", 7.5, C.muted);
    sevMark(L.doc, cols.sev, top, f.severity, 7.5);
    L.doc.textRight(cols.rule, top, f.id, "F3", 7.5, C.muted);
    let y = top;
    for (const l of titleLines) { L.doc.text(cols.body, y, l, "F2", 8.5, C.ink); y += 11; }
    for (const l of locLines) { L.doc.text(cols.body, y - 1, l, "F3", 7.5, C.body); y += 9.5; }
    for (const l of metaLines) { L.doc.text(cols.body, y, l, "F1", 7, C.muted); y += 9; }
    if (evLines.length) {
      const boxH = evLines.length * 9 + 6;
      L.doc.rect(cols.body, y - 4, bodyW, boxH, C.shade);
      L.doc.rect(cols.body, y - 4, 1.5, boxH, C.rule2);
      evLines.forEach((l, k) => L.doc.text(cols.body + 7, y + 5 + k * 9, l, "F3", 7, C.ink));
      y += boxH + 4;
    }
    for (const l of fixLines) { L.doc.text(cols.body, y + 2, l, "F1", 7.5, C.body); y += 10; }
    L.y += h;
    L.doc.line(M, L.y - 3, M + CW, L.y - 3, C.rule, 0.4);
  });
  L.repeatOnNewPage(null);
  L.y += 6;
}

function coverageTable(L: Layout, rows: CoverageRow[], leadsIds: Set<number>, noSignalIds: Set<number>): void {
  const cols = { id: M + 6, name: M + 36, status: M + 300, leads: M + 408, sig: M + CW - 6 };
  const header = L.tableHeader([["Ref.", cols.id], ["Control", cols.name], ["Status", cols.status], ["Leads", cols.leads, "right"], ["Signals src / test", cols.sig, "right"]]);
  L.ensure(80);
  header();
  L.repeatOnNewPage(header);
  for (const r of rows) {
    L.ensure(17);
    const base = L.y + 10;
    L.doc.text(cols.id, base, `C${r.id}`, "F3", 7.5, C.muted);
    L.doc.text(cols.name, base, wrap(r.name, "F1", 8.5, cols.status - cols.name - 10, 1)[0], "F1", 8.5, C.ink);
    const leads = leadsIds.has(r.id);
    const label = leads ? "Leads to verify" : noSignalIds.has(r.id) ? "No signals found" : "Not verified";
    L.doc.text(cols.status, base, label, leads ? "F2" : "F1", 8, leads ? C.warn : C.muted);
    L.doc.textRight(cols.leads, base, r.leads ? String(r.leads) : "–", r.leads ? "F2" : "F1", 8.5, r.leads ? C.ink : C.faint);
    L.doc.textRight(cols.sig, base, r.signals ? `${r.signals.source_count} / ${r.signals.test_count}` : "–", "F1", 8, C.muted);
    L.y += 17;
    L.doc.line(M, L.y - 3, M + CW, L.y - 3, C.rule, 0.3);
  }
  L.repeatOnNewPage(null);
  L.y += 6;
}

export function renderPdf(result: Result, opts: { includeTests?: boolean; now?: Date } = {}): Buffer {
  const v = buildView(result, Boolean(opts.includeTests), opts.now);
  const L = new Layout(v.project);
  const d = L.doc;
  const date = formatDate(v.generatedAt);
  L.firstPage();

  // Title block
  d.rect(M, 52, CW, 3.5, C.accent);
  d.text(M, 80, "SECURITY ASSESSMENT REPORT  ·  CONFIDENTIAL", "F2", 7.5, C.accent);
  const titleLines = wrap(`Static security review of ${v.project}`, "F2", 20, CW);
  titleLines.forEach((l, i) => d.text(M, 106 + i * 24, l, "F2", 20, C.ink));
  L.y = 106 + (titleLines.length - 1) * 24 + 18;
  d.line(M, L.y, M + CW, L.y, C.rule, 0.5);
  L.y += 8;
  const meta: Array<[string, string, FontKey]> = [
    ["Target", v.project, "F1"],
    ["Location", result.root, "F3"],
    ["Date", date, "F1"],
    ["Method", "Read-only static analysis against 22 SaaS security controls; no code executed, no network access", "F1"],
    ["Tool", `saas-security-audit v${VERSION}`, "F1"],
  ];
  for (const [k, val, font] of meta) {
    const lines = wrap(val, font, 8.5, CW - 110, 2);
    d.text(M, L.y + 10, k, "F1", 8.5, C.muted);
    lines.forEach((l, i) => d.text(M + 110, L.y + 10 + i * 11, l, font, 8.5, C.ink));
    L.y += lines.length * 11 + 4;
  }
  L.y += 4;
  d.line(M, L.y, M + CW, L.y, C.rule, 0.5);

  // 1 Executive summary
  L.heading("Executive summary");
  const colGap = 22;
  const leftW = (CW - colGap) * 0.48;
  const rightX = M + leftW + colGap;
  const rightW = CW - leftW - colGap;
  const top = L.y;
  const rating = RATING[v.posture.level];
  const ratingText = wrap(`${v.posture.headline}. ${v.posture.detail}`, "F1", 8.5, leftW - 24);
  const boxH = 44 + ratingText.length * 11.5;
  d.rect(M, top, leftW, boxH, "#ffffff");
  d.line(M, top, M + leftW, top, C.rule2, 0.6);
  d.line(M, top + boxH, M + leftW, top + boxH, C.rule2, 0.6);
  d.line(M + leftW, top, M + leftW, top + boxH, C.rule2, 0.6);
  d.rect(M, top, 3, boxH, rating.color);
  d.text(M + 14, top + 15, "OVERALL RATING", "F2", 6.5, C.muted);
  d.text(M + 14, top + 32, rating.label, "F2", 14, rating.color);
  ratingText.forEach((l, i) => d.text(M + 14, top + 47 + i * 11.5, l, "F1", 8.5, C.body));
  let ly = top + boxH + 12;
  const facts: Array<[string, string]> = [["Files analysed", String(result.stats.files_scanned)], ["Controls with leads", `${v.controlsWithLeads} of 22`]];
  if (v.hidden.length) facts.push(["Leads in test / local env files", String(v.hidden.length)]);
  if (result.stats.suppressed) facts.push(["Suppressed inline", String(result.stats.suppressed)]);
  if (v.stack.length) facts.push(["Stack detected", v.stack.join(", ")]);
  for (const [k, val] of facts) {
    const lines = wrap(val, "F2", 8.5, leftW - 130, 2);
    d.text(M, ly + 9, k, "F1", 8.5, C.muted);
    lines.forEach((l, i) => d.text(M + 130, ly + 9 + i * 11, l, "F2", 8.5, C.ink));
    ly += lines.length * 11 + 3;
  }

  // Severity table on the right
  let ry = top;
  d.rect(rightX, ry, rightW, 17, C.shade);
  d.line(rightX, ry + 17, rightX + rightW, ry + 17, C.rule2, 0.5);
  d.text(rightX + 6, ry + 11.5, "SEVERITY", "F2", 6.5, C.muted);
  d.textRight(rightX + 120, ry + 11.5, "FINDINGS", "F2", 6.5, C.muted);
  ry += 17;
  const total = SEVERITY_ORDER.reduce((a, s) => a + (v.sourceCounts[s] ?? 0), 0);
  for (const sev of SEVERITY_ORDER) {
    const n = v.sourceCounts[sev] ?? 0;
    const base = ry + 13;
    if (n) sevMark(d, rightX + 6, base, sev, 8);
    else { d.rect(rightX + 6, base - 6.8, 6.4, 6.4, C.rule2); d.text(rightX + 16, base, SEV[sev].label, "F1", 8, C.faint); }
    d.textRight(rightX + 120, base, String(n), n ? "F2" : "F1", 8.5, n ? C.ink : C.faint);
    if (n && total) d.rect(rightX + 132, base - 5.5, ((rightW - 140) * n) / total, 4, SEV[sev].color);
    ry += 19;
    d.line(rightX, ry, rightX + rightW, ry, C.rule, 0.3);
  }
  d.text(rightX + 6, ry + 13, "Total", "F2", 8.5, C.ink);
  d.textRight(rightX + 120, ry + 13, String(total), "F2", 8.5, C.ink);
  ry += 22;
  for (const l of wrap("Findings in application source code. Test files and gitignored local env files are reported separately.", "F1", 7, rightW)) {
    d.text(rightX, ry + 7, l, "F1", 7, C.muted);
    ry += 9.5;
  }
  L.y = Math.max(ly, ry) + 6;

  // 2 Findings
  L.heading("Findings", "Each finding is a lead to confirm in code, not a confirmed vulnerability. Evidence is redacted; secret values never appear in this report.");
  if (v.shown.length) findingsTable(L, v.shown, true);
  else L.para("No leads in source code. This is not evidence that the application is secure; the controls under Control coverage still need verification.", 9, C.muted);
  if (v.hidden.length) {
    L.sub(`Test files & local env files (${v.hidden.length})`);
    L.para("Usually intentional samples (fixtures, mocks) or secrets in gitignored local env files. Not counted in the totals above.", 8, C.muted);
    findingsTable(L, v.hidden, false);
  }

  // 3 Remediation plan
  if (v.guidance.length) {
    L.heading("Remediation plan", "One action per rule, most severe first.");
    const cols = { no: M + 6, act: M + 30, rule: M + CW - 100, n: M + CW - 6 };
    const header = L.tableHeader([["#", cols.no], ["Action", cols.act], ["Rule", cols.rule], ["Findings", cols.n, "right"]]);
    header();
    L.repeatOnNewPage(header);
    v.guidance.forEach((g, i) => {
      const lines = wrap(g.guidance, "F1", 8, cols.rule - cols.act - 12);
      const tl = wrap(g.title, "F2", 8.5, cols.rule - cols.act - 12, 2);
      const h = tl.length * 11 + lines.length * 10.5 + 10;
      L.ensure(h);
      const b = L.y + 10;
      d.text(cols.no, b, String(i + 1), "F1", 8, C.muted);
      tl.forEach((l, k) => d.text(cols.act, b + k * 11, l, "F2", 8.5, C.ink));
      lines.forEach((l, k) => d.text(cols.act, b + tl.length * 11 + k * 10.5, l, "F1", 8, C.body));
      d.text(cols.rule, b, g.id, "F3", 7.5, C.muted);
      d.textRight(cols.n, b, String(g.count), "F1", 8.5, C.ink);
      L.y += h;
      d.line(M, L.y - 3, M + CW, L.y - 3, C.rule, 0.3);
    });
    L.repeatOnNewPage(null);
  }

  // 4 Control coverage
  L.heading("Control coverage", "A control passes only when its enforcement is located in code and proven by a negative test; this scan never marks a control as passed. Signals show where enforcement probably lives (source / test files).");
  const rows = [...v.coverage.leads, ...v.coverage.noSignals, ...v.coverage.notVerified].sort((a, b) => a.id - b.id);
  coverageTable(L, rows, new Set(v.coverage.leads.map((r) => r.id)), new Set(v.coverage.noSignals.map((r) => r.id)));

  // 5 Vibe-code review
  const found = result.vibe_review.filter((x) => x.status === "found").length;
  L.heading("Vibe-code review", `Patterns common in AI-generated code. ${found} of ${result.vibe_review.length} were matched. "Not matched" means no lead was found; it is not a pass.`);
  {
    const cols = { t: M + 6, rules: M + 250, res: M + 380, n: M + CW - 6 };
    const header = L.tableHeader([["Pattern", cols.t], ["Rules", cols.rules], ["Result", cols.res], ["Leads", cols.n, "right"]]);
    header();
    L.repeatOnNewPage(header);
    for (const x of result.vibe_review) {
      L.ensure(17);
      const b = L.y + 10;
      const hit = x.status === "found";
      d.text(cols.t, b, wrap(x.title, "F1", 8.5, cols.rules - cols.t - 10, 1)[0], "F1", 8.5, C.ink);
      d.text(cols.rules, b, wrap(x.rules.join(", "), "F3", 7, cols.res - cols.rules - 8, 1)[0], "F3", 7, C.muted);
      d.text(cols.res, b, hit ? "Matched" : "Not matched", hit ? "F2" : "F1", 8, hit ? C.warn : C.muted);
      d.textRight(cols.n, b, hit ? String(x.leads) : "–", hit ? "F2" : "F1", 8.5, hit ? C.ink : C.faint);
      L.y += 17;
      d.line(M, L.y - 3, M + CW, L.y - 3, C.rule, 0.3);
    }
    L.repeatOnNewPage(null);
  }

  // 6 Standards mapping
  const st = result.standards;
  L.heading("Standards mapping", st.note);
  const stdTable = (title: string, rs: typeof st.owasp_top10_2021) => {
    L.sub(title);
    const cols = { id: M + 6, name: M + 56, n: M + 310, rules: M + 324 };
    const header = L.tableHeader([["ID", cols.id], ["Category", cols.name], ["Leads", cols.n, "right"], ["Rules", cols.rules]]);
    header();
    L.repeatOnNewPage(header);
    for (const r of rs) {
      L.ensure(15);
      const b = L.y + 9.5;
      d.text(cols.id, b, r.id, "F3", 7.5, r.leads ? C.ink : C.muted);
      d.text(cols.name, b, wrap(r.name, "F1", 8, cols.n - cols.name - 24, 1)[0], "F1", 8, C.ink);
      d.textRight(cols.n, b, r.checked ? (r.leads ? String(r.leads) : "–") : "–", r.leads ? "F2" : "F1", 8, r.leads ? C.ink : C.faint);
      d.text(cols.rules, b, wrap(r.checked ? r.rules.join(", ") : "Not covered by this scanner", "F3", 6.5, M + CW - cols.rules, 1)[0], "F3", 6.5, C.muted);
      L.y += 15;
      d.line(M, L.y - 2.5, M + CW, L.y - 2.5, C.rule, 0.3);
    }
    L.repeatOnNewPage(null);
    L.y += 4;
  };
  stdTable("OWASP Top 10 (2021)", st.owasp_top10_2021);
  stdTable("OWASP API Security Top 10 (2023)", st.owasp_api_2023);
  stdTable("OWASP Top 10 for LLM Applications (2025)", st.owasp_llm_2025);
  L.sub("CWE");
  if (!st.cwe.length) L.para("No CWE-mapped leads in source code.", 8, C.muted);
  else {
    const cols = { id: M + 6, name: M + 70, n: M + 380, top: M + 396 };
    const header = L.tableHeader([["CWE", cols.id], ["Weakness", cols.name], ["Leads", cols.n, "right"], ["CWE Top 25 (2024)", cols.top]]);
    header();
    L.repeatOnNewPage(header);
    for (const x of st.cwe) {
      L.ensure(15);
      const b = L.y + 9.5;
      d.text(cols.id, b, x.id, "F3", 7.5, C.ink);
      d.text(cols.name, b, wrap(x.name, "F1", 8, cols.n - cols.name - 24, 1)[0], "F1", 8, C.ink);
      d.textRight(cols.n, b, String(x.leads), "F2", 8, C.ink);
      d.text(cols.top, b, x.top25 ? "Yes" : "–", "F1", 8, x.top25 ? C.ink : C.faint);
      L.y += 15;
      d.line(M, L.y - 2.5, M + CW, L.y - 2.5, C.rule, 0.3);
    }
    L.repeatOnNewPage(null);
  }
  L.sub("Compliance frameworks (related requirements)");
  for (const fw of st.frameworks) {
    const text = fw.requirements.map((r) => `${r.ref}${r.name ? " " + r.name : ""} (${r.leads})`).join("  ·  ") || "No related leads in source code";
    const lines = wrap(text, "F1", 8, CW - 150);
    L.ensure(lines.length * 11 + 8);
    d.text(M + 6, L.y + 9, fw.name, "F2", 8, C.ink);
    lines.forEach((l, i) => d.text(M + 150, L.y + 9 + i * 11, l, "F1", 8, fw.requirements.length ? C.body : C.muted));
    L.y += lines.length * 11 + 6;
    d.line(M, L.y - 2, M + CW, L.y - 2, C.rule, 0.3);
  }

  // 7 Scope, method and limitations
  L.heading("Scope, method and limitations");
  const notes = [
    "Read-only static analysis on the local machine. No code was executed and nothing was sent anywhere.",
    ...result.limitations,
    "Findings are leads to validate. For verification, fixes and regression tests, run /saas-security-audit:audit in Claude Code.",
  ];
  for (const n of notes) {
    const lines = wrap(n, "F1", 8.5, CW - 12);
    L.ensure(lines.length * 12 + 4);
    d.text(M, L.y + 9, "–", "F1", 8.5, C.muted);
    lines.forEach((l, i) => d.text(M + 12, L.y + 9 + i * 12, l, "F1", 8.5, C.body));
    L.y += lines.length * 12 + 3;
  }
  const inv = result.inventory;
  L.sub("Inventory");
  for (const [k, val] of [["Dependency manifests", inv.manifests.join(", ") || "None found"], ["Test files", String(inv.test_files)], ["CI files", inv.ci_files.join(", ") || "None found"]] as const) {
    const lines = wrap(val, "F1", 8.5, CW - 130);
    L.ensure(lines.length * 11 + 4);
    d.text(M, L.y + 9, k, "F1", 8.5, C.muted);
    lines.forEach((l, i) => d.text(M + 130, L.y + 9 + i * 11, l, "F1", 8.5, C.ink));
    L.y += lines.length * 11 + 3;
  }
  L.sub("Recommended tools");
  for (const t of inv.recommended_tools) {
    L.ensure(15);
    d.text(M + 6, L.y + 9, t.command, "F3", 7.5, C.ink);
    d.textRight(M + CW - 6, L.y + 9, `${t.installed ? "Installed" : "Not installed"} · ${t.needs_network ? "needs network" : "offline"}`, "F1", 7.5, C.muted);
    L.y += 15;
    d.line(M, L.y - 2.5, M + CW, L.y - 2.5, C.rule, 0.3);
  }

  L.footers(date);
  return d.build({ title: `Security assessment — ${v.project}`, subject: `Static security review of ${result.root}` });
}
