// Code-flow analysis (src/flow.ts): planted vibe-code bugs must be found; the safe twin next to each must not.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { scan } from "../dist/engine.js";

async function withRepo(files, fn) {
  const root = mkdtempSync(join(tmpdir(), "saas-audit-flow-"));
  try {
    for (const [rel, text] of Object.entries(files)) {
      mkdirSync(dirname(join(root, rel)), { recursive: true });
      writeFileSync(join(root, rel), text);
    }
    return await fn(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}
const flow = (found) => found.filter((f) => /^SEC04[4-9]$/.test(f.id)).map((f) => `${f.id} ${f.file}:${f.line}`).sort();

const APP = {
  "package.json": JSON.stringify({ dependencies: { next: "15", "@prisma/client": "6", mongoose: "8" } }),
  "lib/db.ts": "export const prisma = new PrismaClient();\n",
  "lib/auth.ts": "export async function auth() { return getServerSession(); }\n",
  // A helper whose name says nothing; it checks the session inside (followed across files).
  "lib/context.ts": "import { getServerSession } from 'next-auth';\nexport async function loadContext() {\n  const s = await getServerSession();\n  if (!s) throw new Error('401');\n  return s;\n}\n",

  // BUG: anyone can list every post.
  "app/api/posts/route.ts": "import { prisma } from '@/lib/db';\nexport async function GET() {\n  const posts = await prisma.post.findMany();\n  return Response.json(posts);\n}\n",
  // BUGS: IDOR on read; IDOR + whole body on update.
  "app/api/posts/[id]/route.ts": [
    "import { prisma } from '@/lib/db';",
    "import { auth } from '@/lib/auth';",
    "export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {",
    "  const session = await auth();",
    "  if (!session) return new Response('no', { status: 401 });",
    "  const { id } = await params;",
    "  const post = await prisma.post.findUnique({ where: { id } });",
    "  return Response.json(post);",
    "}",
    "export async function PATCH(req: Request, { params }) {",
    "  const session = await auth();",
    "  const body = await req.json();",
    "  const post = await prisma.post.update({ where: { id: params.id }, data: body });",
    "  return Response.json(post);",
    "}",
  ].join("\n") + "\n",
  // BUGS: server action with no check; owner and price from the form.
  "app/actions.ts": [
    "'use server';",
    "import { prisma } from '@/lib/db';",
    "export async function deleteInvoice(id: string) {",
    "  await prisma.invoice.delete({ where: { id } });",
    "}",
    "export async function createOrder(formData: FormData) {",
    "  const session = await getServerSession();",
    "  await prisma.order.create({ data: { userId: formData.get('userId'), price: Number(formData.get('price')), item: String(formData.get('item')) } });",
    "}",
  ].join("\n") + "\n",
  // BUGS: SSRF, open redirect, raw SQL.
  "app/api/preview/route.ts": "export async function GET(req: Request) {\n  const user = await currentUser();\n  const url = new URL(req.url).searchParams.get('url');\n  const r = await fetch(url!);\n  return new Response(await r.text());\n}\n",
  "app/api/go/route.ts": "import { NextResponse } from 'next/server';\nexport async function GET(req) {\n  const next = req.nextUrl.searchParams.get('next') ?? '/';\n  return NextResponse.redirect(new URL(next, req.url));\n}\n",
  "app/api/search/route.ts": "import { prisma } from '@/lib/db';\nexport async function GET(req) {\n  const user = await currentUser();\n  const q = req.nextUrl.searchParams.get('q');\n  return Response.json(await prisma.$queryRawUnsafe(`SELECT * FROM t WHERE name = '${q}'`));\n}\n",
  // BUGS (Express): no auth on a model read; IDOR on delete behind auth; shell.
  "server.js": [
    "const { exec } = require('child_process');",
    "app.get('/api/users/:id', async (req, res) => { res.json(await User.findById(req.params.id)); });",
    "app.delete('/api/users/:id', requireAuth, async (req, res) => { await User.findByIdAndDelete(req.params.id); res.end(); });",
    "app.post('/api/convert', requireAuth, (req, res) => { exec(`convert ${req.body.file} out.png`); res.end(); });",
    "",
  ].join("\n"),

  // SAFE twins: none of these may be reported.
  "app/api/me/route.ts": "import { prisma } from '@/lib/db';\nimport { auth } from '@/lib/auth';\nexport async function GET() {\n  const s = await auth();\n  return Response.json(await prisma.user.findUnique({ where: { id: s.user.id } }));\n}\n",
  "app/api/projects/[id]/route.ts": "import { prisma } from '@/lib/db';\nimport { auth } from '@/lib/auth';\nexport async function GET(req, { params }) {\n  const s = await auth();\n  return Response.json(await prisma.project.findFirst({ where: { id: params.id, ownerId: s.user.id } }));\n}\n",
  "app/api/docs/[id]/route.ts": "import { prisma } from '@/lib/db';\nimport { auth } from '@/lib/auth';\nexport async function GET(req, { params }) {\n  const s = await auth();\n  const doc = await prisma.doc.findUnique({ where: { id: params.id } });\n  if (doc.userId !== s.user.id) return new Response('no', { status: 403 });\n  return Response.json(doc);\n}\n",
  "app/api/webhooks/stripe/route.ts": "import { prisma } from '@/lib/db';\nexport async function POST(req) {\n  const event = stripe.webhooks.constructEvent(await req.text(), req.headers.get('stripe-signature'), secret);\n  await prisma.payment.create({ data: { id: event.id } });\n}\n",
  "app/api/contact/route.ts": "import { prisma } from '@/lib/db';\nexport async function POST(req) {\n  if (await rateLimit(req)) return new Response('slow down', { status: 429 });\n  const { email, message } = await req.json();\n  await prisma.message.create({ data: { email, message } });\n}\n",
  "app/api/notes/route.ts": "import { prisma } from '@/lib/db';\nimport { loadContext } from '@/lib/context';\nconst Note = z.object({ title: z.string() });\nexport async function POST(req) {\n  const s = await loadContext();\n  const data = Note.parse(await req.json());\n  await prisma.note.create({ data: { ...data, userId: s.user.id } });\n  const r = await fetch(`${process.env.API}/notes/${data.title}`);\n  return Response.redirect(`/notes/${data.title}`);\n}\n",
  "app/api/feed/route.ts": "import { prisma } from '@/lib/db';\nexport const GET = withAuth(async (req) => Response.json(await prisma.post.findMany()));\n",
  "app/api/cron/route.ts": "import { prisma } from '@/lib/db';\nexport async function GET(req) {\n  if (req.headers.get('authorization') !== `Bearer ${process.env.CRON_SECRET}`) return new Response('no', { status: 401 });\n  await prisma.session.deleteMany({});\n}\n",
  // BUG: a log call that gets the user and the record is not an access check.
  "app/api/files/[id]/route.ts": "import { prisma } from '@/lib/db';\nexport async function GET(req, { params }) {\n  const user = await getCurrentUser();\n  const file = await prisma.file.findUnique({ where: { id: params.id } });\n  await logActivity(file.id, user);\n  return Response.json(file);\n}\n",
  // SAFE: a guard that throws, and a check whose answer decides.
  "app/api/files/[id]/share/route.ts": "import { prisma } from '@/lib/db';\nexport async function POST(req, { params }) {\n  const user = await getCurrentUser();\n  await requireAccess(params.id, user);\n  return Response.json(await prisma.file.update({ where: { id: params.id }, data: { shared: true } }));\n}\n",
  "app/api/files/[id]/meta/route.ts": "import { prisma } from '@/lib/db';\nexport async function GET(req, { params }) {\n  const user = await getCurrentUser();\n  const f = await prisma.file.findUnique({ where: { id: params.id } });\n  const access = await fileForUser(f.folderId, user);\n  if (!access) return new Response('no', { status: 404 });\n  return Response.json(f);\n}\n",
  "lib/regex.ts": "export function f(req) { return /abc/.exec(req.query.x); }\n",
};

test("finds the planted vibe-code bugs and leaves the safe twins alone", async () => {
  await withRepo(APP, async (root) => {
    const got = flow(await scan(root));
    assert.deepEqual(got, [
      "SEC044 app/actions.ts:3",
      "SEC044 app/api/posts/route.ts:2",
      "SEC044 server.js:2",
      "SEC045 app/api/files/[id]/route.ts:4",
      "SEC045 app/api/posts/[id]/route.ts:13",
      "SEC045 app/api/posts/[id]/route.ts:7",
      "SEC045 server.js:3",
      "SEC046 app/api/posts/[id]/route.ts:13",
      "SEC047 app/actions.ts:8",
      "SEC047 app/actions.ts:8",
      "SEC048 app/api/search/route.ts:5",
      "SEC048 server.js:4",
      "SEC049 app/api/go/route.ts:4",
      "SEC049 app/api/preview/route.ts:4",
    ]);
  });
});

test("SAAS_AUDIT_ENGINE=regex turns the flow analysis off; ignore comments suppress it", async () => {
  await withRepo({ "app/api/a/route.ts": "// security-audit: ignore[SEC044] -- public catalogue\nexport async function GET() {\n  return Response.json(await prisma.item.findMany());\n}\n",
    "app/api/b/route.ts": "export async function GET() {\n  return Response.json(await prisma.item.findMany());\n}\n" }, async (root) => {
    assert.deepEqual(flow(await scan(root)), ["SEC044 app/api/b/route.ts:1"]);
    process.env.SAAS_AUDIT_ENGINE = "regex";
    try { assert.deepEqual(flow(await scan(root)), []); } finally { delete process.env.SAAS_AUDIT_ENGINE; }
  });
});
