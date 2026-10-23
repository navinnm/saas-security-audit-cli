/**
 * Yes/No prompt from the redesign: a bordered box with a highlighted choice, keyboard
 * hints, and a safe default. Once answered it collapses to one line in the scrollback.
 */
import { emitKeypressEvents } from "node:readline";
import { MARGIN, P, bg, bold, box, c, contentWidth, fg } from "./theme.js";

export interface AskOptions {
  question: string;
  note?: string;
  yes?: string;
  no?: string;
  defaultYes: boolean;
  hint?: string;
  tone?: "info" | "warn";
}

/** Plain-string frame for a prompt, used both here and inside the live scan panel. */
export function promptFrame(o: AskOptions, selectedYes: boolean, width: number): string[] {
  const warn = o.tone === "warn";
  const mark = warn ? bold(c.high("!")) : bold(c.accent("?"));
  const head = `${mark} ${bold(o.question)}${o.note ? "  " + c.muted(o.note) : ""}`;
  const on = (s: string) => bold(bg(warn ? P.high : P.accent, "#0D1117", ` ❯ ${s} `));
  const off = (s: string) => c.muted(`   ${s} `);
  const yes = o.yes ?? "Yes";
  const no = o.no ?? "No";
  const opts = `  ${selectedYes ? on(yes) : off(yes)} ${selectedYes ? off(no) : on(no)}   ${c.dim(o.hint ?? "← → choose · enter confirm · y / n · esc cancel")}`;
  return box([head, opts], Math.min(width, 100), warn ? P.warnBox : P.infoBox);
}

/** One-line record of an answered (or skipped) prompt. */
export function collapsed(question: string, answer: string | null, skippedReason?: string): string {
  if (answer === null) return `${c.dim("–")} ${c.muted(question)} ${c.dim(`skipped${skippedReason ? " · " + skippedReason : ""}`)}`;
  const isYes = /^yes/i.test(answer);
  return `${c.ok("✓")} ${question} ${bold(isYes ? c.accent(answer) : c.muted(answer))}`;
}

/** Ask in an interactive terminal. Resolves true/false, or null when cancelled with esc / ctrl+c. */
export function ask(o: AskOptions): Promise<boolean | null> {
  const stdin = process.stdin;
  const out = process.stdout;
  const width = contentWidth(out.columns);
  let yes = o.defaultYes;
  let lines = 0;
  const draw = () => {
    const frame = promptFrame(o, yes, width).map((l) => MARGIN + " " + l);
    if (lines) out.write(`\x1b[${lines}F\x1b[0J`);
    out.write(frame.join("\n") + "\n");
    lines = frame.length;
  };
  return new Promise((resolveAnswer) => {
    emitKeypressEvents(stdin);
    const wasRaw = stdin.isRaw;
    if (stdin.isTTY) stdin.setRawMode(true);
    stdin.resume();
    out.write("\x1b[?25l");
    draw();
    const finish = (answer: boolean | null) => {
      stdin.off("keypress", onKey);
      if (stdin.isTTY) stdin.setRawMode(wasRaw);
      stdin.pause();
      out.write(`\x1b[${lines}F\x1b[0J\x1b[?25h`);
      const label = answer === null ? null : answer ? (o.yes ?? "Yes") : (o.no ?? "No");
      out.write(MARGIN + " " + collapsed(o.question, label, answer === null ? "cancelled" : undefined) + "\n");
      resolveAnswer(answer);
    };
    const onKey = (str: string | undefined, key: { name?: string; ctrl?: boolean } = {}) => {
      if (key.ctrl && key.name === "c") return finish(null);
      switch (key.name) {
        case "left": case "right": case "tab": case "h": case "l":
          yes = !yes; return draw();
        case "return": case "enter":
          return finish(yes);
        case "escape":
          return finish(null);
        case "y": return finish(true);
        case "n": return finish(false);
        default:
          if (str === "y" || str === "Y") return finish(true);
          if (str === "n" || str === "N") return finish(false);
      }
    };
    stdin.on("keypress", onKey);
  });
}

export const canAsk = () => Boolean(process.stdin.isTTY && process.stdout.isTTY) && !process.env.CI;
export { fg };
