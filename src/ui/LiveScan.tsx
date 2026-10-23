import React, { useEffect, useRef, useState } from "react";
import { Box, Text, useApp, useStdout } from "ink";
import type { Finding, ScanEvents } from "../engine.js";
import { AMBER, BEAM, GROUPS, SEV_INK, SEV_SHORT, groupOf, hex, lerpRgb } from "./theme.js";
import { shownByDefault } from "./summary.js";

type Phase = "discover" | "scan" | "analyze" | "done";

export interface LiveScanProps {
  version: string;
  target: string;
  /** Runs the scan, reporting progress through the given events. */
  run(events: ScanEvents): Promise<void>;
  /** Minimum time the animation stays on screen, so fast scans are still readable. */
  minMs?: number;
  /** Count and show findings in test files / local env files too (otherwise source code only). */
  includeTests?: boolean;
}

const FRAME_MS = 70;
const TRAIL = ["░", "▒", "▓", "█", "▓", "▒", "░"];
const EIGHTHS = ["", "▏", "▎", "▍", "▌", "▋", "▊", "▉"];
const PHASE_LABEL: Record<Phase, string> = { discover: "MAPPING", scan: "SCANNING", analyze: "CORRELATING", done: "COMPLETE" };

function Gradient({ text }: { text: string }) {
  const chars = [...text];
  return (
    <Text bold>
      {chars.map((ch, i) => (
        <Text key={i} color={hex(lerpRgb(chars.length > 1 ? i / (chars.length - 1) : 0))}>{ch}</Text>
      ))}
    </Text>
  );
}

function Beam({ frame, width, active }: { frame: number; width: number; active: boolean }) {
  const span = Math.max(1, 2 * (width - 1));
  const p = frame % span;
  const head = p < width ? p : span - p;
  const cells = Array.from({ length: width }, (_, i) => {
    const d = i - head + 3;
    if (active && d >= 0 && d < TRAIL.length) {
      return <Text key={i} color={d === 3 ? BEAM : hex(lerpRgb(Math.abs(d - 3) / 4))}>{TRAIL[d]}</Text>;
    }
    return <Text key={i} color="gray" dimColor>·</Text>;
  });
  return <Text>{cells}</Text>;
}

function Bar({ fraction, width }: { fraction: number; width: number }) {
  const exact = Math.max(0, Math.min(1, fraction)) * width;
  const full = Math.floor(exact);
  const partial = EIGHTHS[Math.floor((exact - full) * 8)];
  const cells = [];
  for (let i = 0; i < full; i++) cells.push(<Text key={i} color={hex(lerpRgb(i / Math.max(1, width - 1)))}>█</Text>);
  if (partial && full < width) cells.push(<Text key="p" color={hex(lerpRgb(full / Math.max(1, width - 1)))}>{partial}</Text>);
  const rest = width - full - (partial && full < width ? 1 : 0);
  if (rest > 0) cells.push(<Text key="r" color="gray" dimColor>{"─".repeat(rest)}</Text>);
  return <Text>{cells}</Text>;
}

const truncLeft = (s: string, n: number) => (s.length <= n ? s : "…" + s.slice(s.length - n + 1));

export function LiveScan({ version, target, run, minMs = 1400, includeTests = false }: LiveScanProps) {
  const { exit } = useApp();
  const { stdout } = useStdout();
  const cols = Math.max(50, Math.min(stdout?.columns ?? 80, 100));
  const width = Math.max(20, Math.min(46, cols - 30));

  const [frame, setFrame] = useState(0);
  const phase = useRef<Phase>("discover");
  const total = useRef(0);
  const index = useRef(0);
  const current = useRef("");
  const feed = useRef<Finding[]>([]);
  const groupCounts = useRef<number[]>(GROUPS.map(() => 0));
  const start = useRef(Date.now());

  useEffect(() => {
    const timer = setInterval(() => setFrame((f) => f + 1), FRAME_MS);
    let cancelled = false;
    run({
      onPhase: (p) => { if (p !== "done") phase.current = p as Phase; },
      onDiscover: (n) => { total.current = n; },
      onFile: (rel, i) => { current.current = rel; index.current = i + 1; },
      onFinding: (f) => {
        if (!includeTests && !shownByDefault(f)) return;
        const g = groupOf(f.controls[0]);
        if (g >= 0) groupCounts.current[g]++;
        feed.current = [f, ...feed.current].slice(0, 4);
      },
    }).then(async () => {
      phase.current = "analyze";
      const wait = minMs - (Date.now() - start.current);
      if (wait > 0) await new Promise((r) => setTimeout(r, wait));
      if (cancelled) return;
      phase.current = "done";
      index.current = total.current;
      setFrame((f) => f + 1);
      clearInterval(timer);
      setTimeout(() => exit(), FRAME_MS);
    }, (err) => {
      clearInterval(timer);
      exit(err instanceof Error ? err : new Error(String(err)));
    });
    return () => { cancelled = true; clearInterval(timer); };
  }, []);

  const done = phase.current === "done";
  const fraction = total.current ? index.current / total.current : 0;
  const elapsed = ((Date.now() - start.current) / 1000).toFixed(1);
  const blink = Math.floor(frame / 6) % 2 === 0;

  return (
    <Box flexDirection="column" paddingX={1} paddingY={0}>
      <Box>
        <Text color={BEAM}>◢◤ </Text>
        <Gradient text="SAAS SECURITY AUDIT" />
        <Text color="gray">{`  v${version}  ·  read-only · offline scan`}</Text>
      </Box>
      <Text color="gray">{"target  "}<Text color="white">{truncLeft(target, cols - 12)}</Text></Text>
      <Text> </Text>
      <Box>
        <Text color="gray">⟦</Text>
        <Beam frame={frame} width={width} active={!done} />
        <Text color="gray">⟧ </Text>
        <Text color={done ? "green" : blink ? BEAM : "cyan"} bold>{done ? "✔ " : "◉ "}{PHASE_LABEL[phase.current]}</Text>
      </Box>
      <Box>
        <Text>{" "}</Text>
        <Bar fraction={done ? 1 : fraction} width={width} />
        <Text>{" "}</Text>
        <Text bold>{String(Math.round((done ? 1 : fraction) * 100)).padStart(3)}%</Text>
        <Text color="gray">{`  ${index.current}/${total.current} files · ${elapsed}s`}</Text>
      </Box>
      <Text color="gray">{done ? " " : "▸ "}<Text color="white">{done ? "" : truncLeft(current.current, cols - 6)}</Text></Text>
      <Text> </Text>
      {GROUPS.map((g, i) => {
        const n = groupCounts.current[i];
        return (
          <Text key={g.label}>
            <Text color={n ? AMBER : "gray"}>{n ? " ▲ " : " ● "}</Text>
            <Text color={n ? "white" : "gray"}>{g.label.padEnd(28, " ")}</Text>
            <Text color={n ? AMBER : "gray"} bold={n > 0}>{n ? String(n) : "–"}</Text>
          </Text>
        );
      })}
      <Text> </Text>
      <Text color="gray" dimColor>{"─ live findings ".padEnd(Math.min(cols - 4, 60), "─")}</Text>
      {[0, 1, 2, 3].map((i) => {
        const f = feed.current[i];
        if (!f) return <Text key={i} color="gray" dimColor>{i === 0 && !done ? "  waiting for signals…" : " "}</Text>;
        return (
          <Text key={i} wrap="truncate-end">
            <Text color={SEV_INK[f.severity]} bold>{` ${(SEV_SHORT[f.severity] ?? f.severity).padEnd(5)}`}</Text>
            <Text color="gray">{f.id}  </Text>
            <Text color="white">{`${f.file}:${f.line}`}</Text>
            <Text color="gray">{`  ${f.title}`}</Text>
          </Text>
        );
      })}
    </Box>
  );
}
