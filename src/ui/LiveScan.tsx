import React, { useEffect, useRef, useState } from "react";
import { Text, useApp, useInput, useStdin, useStdout } from "ink";
import type { Finding, ScanEvents } from "../engine.js";
import { SEVERITY_RANK } from "../rules.js";
import { shownByDefault } from "../view.js";
import { GROUPS, groupOf, num, termWidth } from "./theme.js";
import { liveFrame, type RunInfo, type StepState } from "./screens.js";
import { promptFrame } from "./prompt.js";

export interface LiveScanProps {
  info: RunInfo;
  report: string | null;
  includeTests: boolean;
  /** Runs scan + report writing; reports progress through `events` and stops when `signal.aborted`. */
  run(events: ScanEvents, signal: { aborted: boolean }): Promise<void>;
  /** Called once if the user stops the scan, with the overall percent reached. */
  onStopped(percent: number): void;
  minMs?: number;
}

const FRAME_MS = 80;
const STEPS = ["Discover", "Classify", "Analyse", "Correlate", "Report"] as const;
const WEIGHTS = [0.04, 0.02, 0.86, 0.05, 0.03];

const fmtTime = (ms: number) => `${(ms / 1000).toFixed(1)}s`;
const fmtEta = (secs: number) => `${Math.floor(secs / 60)}:${String(Math.round(secs % 60)).padStart(2, "0")}`;

export function LiveScan({ info, report, includeTests, run, onStopped, minMs = 900 }: LiveScanProps) {
  const { exit } = useApp();
  const { stdout } = useStdout();
  const { isRawModeSupported } = useStdin();
  const [frame, setFrame] = useState(0);
  const [asking, setAsking] = useState(false);
  const [askYes, setAskYes] = useState(false);
  const [finished, setFinished] = useState(false);

  const signal = useRef({ aborted: false });
  const start = useRef(Date.now());
  const step = useRef(0);
  const stepStart = useRef(Date.now());
  const times = useRef<string[]>([]);
  const totals = useRef({ files: 0, analysable: 0, skipped: 0 });
  const analyse = useRef({ done: 0, startedAt: 0 });
  const current = useRef("");
  const counts = useRef<Record<string, number>>({ Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 });
  const areaTotals = useRef(GROUPS.map((g) => ({ label: g.label, total: 0, crit: 0, high: 0, signals: false })));
  const latest = useRef<Finding[]>([]);

  const advance = (to: number) => {
    while (step.current < to) {
      times.current[step.current] = fmtTime(Date.now() - stepStart.current);
      step.current++;
      stepStart.current = Date.now();
    }
  };

  const overall = () => {
    const done = WEIGHTS.slice(0, step.current).reduce((a, b) => a + b, 0);
    const within = step.current === 2 && totals.current.analysable ? analyse.current.done / totals.current.analysable : 0;
    return Math.min(100, (done + (WEIGHTS[step.current] ?? 0) * within) * 100);
  };

  const stop = () => {
    signal.current.aborted = true;
    onStopped(overall());
    setAsking(false);
  };

  useInput((input, key) => {
    if (finished) return;
    if (key.ctrl && input === "c") {
      if (asking) stop();
      else { setAskYes(false); setAsking(true); }
      return;
    }
    if (!asking) return;
    if (key.leftArrow || key.rightArrow || key.tab) setAskYes((v) => !v);
    else if (key.return) { if (askYes) stop(); else setAsking(false); }
    else if (input === "y" || input === "Y") stop();
    else if (input === "n" || input === "N" || key.escape) setAsking(false);
  }, { isActive: isRawModeSupported });

  useEffect(() => {
    const timer = setInterval(() => setFrame((f) => f + 1), FRAME_MS);
    run({
      onPhase: (p) => {
        if (p === "classify") advance(1);
        else if (p === "scan") { advance(2); analyse.current.startedAt = Date.now(); }
        else if (p === "analyze") advance(3);
        else if (p === "report") advance(4);
      },
      onDiscover: (n) => { totals.current.files = n; },
      onClassify: (a, s) => { totals.current.analysable = a; totals.current.skipped = s; },
      onAnalyse: (rel, done) => { current.current = rel; analyse.current.done = done; },
      onFinding: (f) => {
        if (!includeTests && !shownByDefault(f)) return;
        counts.current[f.severity] = (counts.current[f.severity] ?? 0) + 1;
        const g = groupOf(f.controls[0]);
        if (g >= 0) {
          const a = areaTotals.current[g];
          a.total++;
          if (f.severity === "Critical") a.crit++;
          if (f.severity === "High") a.high++;
        }
        if (SEVERITY_RANK[f.severity] >= SEVERITY_RANK.High) latest.current = [f, ...latest.current].slice(0, 5);
      },
    }, signal.current).then(async () => {
      advance(5);
      const wait = minMs - (Date.now() - start.current);
      if (wait > 0 && !signal.current.aborted) await new Promise((r) => setTimeout(r, wait));
      clearInterval(timer);
      setFinished(true);
      setTimeout(() => exit(), FRAME_MS);
    }, (err) => {
      clearInterval(timer);
      exit(err instanceof Error ? err : new Error(String(err)));
    });
    return () => clearInterval(timer);
  }, []);

  if (finished) return <Text>{""}</Text>;

  const width = termWidth(stdout?.columns);
  const height = Math.max(24, stdout?.rows ?? 40);
  const elapsedAnalyse = analyse.current.startedAt ? (Date.now() - analyse.current.startedAt) / 1000 : 0;
  const rate = elapsedAnalyse > 0.5 ? analyse.current.done / elapsedAnalyse : 0;
  const remaining = totals.current.analysable - analyse.current.done;
  const eta = step.current === 2 && rate > 0 ? fmtEta(remaining / rate) : "";
  const state = (i: number): StepState => (i < step.current ? "done" : i === step.current ? "active" : "pending");
  const details = [
    totals.current.files ? `${num(totals.current.files)} files indexed` : "walking the repository",
    totals.current.analysable ? `${num(totals.current.analysable)} to analyse · ${num(totals.current.skipped)} skipped by type and ignore rules` : "by file type and ignore rules",
    "",
    "dedupe and group by rule",
    report ?? "terminal summary",
  ];

  const text = liveFrame({
    info: { ...info, width },
    height,
    frame,
    steps: STEPS.map((name, i) => ({ name, state: state(i), detail: details[i], time: times.current[i] })),
    analyse: { done: analyse.current.done, total: totals.current.analysable, eta },
    overall: overall(),
    elapsed: (Date.now() - start.current) / 1000,
    stepIndex: Math.min(step.current, STEPS.length - 1),
    current: step.current === 2 ? current.current : "",
    counts: counts.current,
    areaTotals: areaTotals.current,
    latest: latest.current,
    prompt: asking ? promptFrame({
      question: `Stop the scan at ${Math.round(overall())}%?`,
      note: report ? `partial results are saved to ${report}` : "partial results are kept",
      yes: "Yes, stop", no: "No, keep going", defaultYes: false, tone: "warn", hint: "ctrl+c again stops immediately",
    }, askYes, width - 2) : undefined,
  });
  return <Text>{text}</Text>;
}
