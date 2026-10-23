// Architecture checks (src/infra.ts): planted deployment bugs must be found, the safe twin of each must not.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { analyzeInfra } from "../dist/infra.js";

const FILES = {
  // BUGS
  "Dockerfile": "FROM node\nENV STRIPE_SECRET_KEY=sk_live_abcdefghijklmnop\nCOPY .env /app/.env\nCMD [\"node\", \"server.js\"]\n",
  "docker-compose.yml": [
    "services:",
    "  db:",
    "    image: postgres:16",
    "    ports:",
    "      - \"5432:5432\"",
    "    environment:",
    "      POSTGRES_PASSWORD: postgres",
    "      POSTGRES_HOST_AUTH_METHOD: trust",
    "  cache:",
    "    image: redis:7",
    "    ports: [\"6379:6379\"]",
    "  agent:",
    "    image: ci/agent:1.2",
    "    privileged: true",
    "    volumes:",
    "      - /var/run/docker.sock:/var/run/docker.sock",
    "",
  ].join("\n"),
  "k8s/deploy.yaml": [
    "apiVersion: apps/v1",
    "kind: Deployment",
    "metadata:",
    "  name: api",
    "spec:",
    "  template:",
    "    spec:",
    "      hostNetwork: true",
    "      containers:",
    "        - name: api",
    "          image: acme/api:latest",
    "          securityContext:",
    "            privileged: true",
    "            runAsUser: 0",
    "          env:",
    "            - name: DATABASE_PASSWORD",
    "              value: s3cr3t-prod-pass",
    "---",
    "apiVersion: v1",
    "kind: Secret",
    "metadata:",
    "  name: creds",
    "stringData:",
    "  token: abcdefghijklmnopqrstuvwx",
    "",
  ].join("\n"),
  ".github/workflows/pr.yml": [
    "on: pull_request_target",
    "permissions: write-all",
    "jobs:",
    "  build:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
    "        with:",
    "          ref: ${{ github.event.pull_request.head.sha }}",
    "      - run: echo \"${{ github.event.pull_request.title }}\"",
    "      - uses: some-org/deploy-action@v2",
    "",
  ].join("\n"),
  "infra/main.tf": [
    'resource "aws_security_group" "db" {',
    "  ingress {",
    "    from_port   = 5432",
    "    to_port     = 5432",
    '    protocol    = "tcp"',
    '    cidr_blocks = ["0.0.0.0/0"]',
    "  }",
    "}",
    'resource "aws_db_instance" "main" {',
    "  publicly_accessible = true",
    "  storage_encrypted   = false",
    '  password            = "SuperSecret123"',
    "}",
    "",
  ].join("\n"),
  "deploy/pg_hba.conf": "local all all peer\nhost all all 0.0.0.0/0 trust\n",
  "deploy/redis.conf": "bind 0.0.0.0\nprotected-mode no\n",
  "deploy/mongod.conf": "net:\n  bindIp: 0.0.0.0\n",

  // SAFE twins
  "safe/Dockerfile": "FROM node:22.11-alpine AS build\nRUN npm ci\nFROM gcr.io/distroless/nodejs22-debian12:nonroot\nCOPY --from=build /app /app\n",
  "safe/app.Dockerfile": "FROM python:3.12-slim\nARG API_KEY\nENV API_KEY=${API_KEY}\nRUN useradd -u 10001 app\nUSER app\n",
  "safe/compose.yaml": "services:\n  db:\n    image: postgres:16\n    ports:\n      - \"127.0.0.1:5432:5432\"\n    environment:\n      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}\n",
  "safe/k8s.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      securityContext:\n        runAsNonRoot: true\n      containers:\n        - name: web\n          image: acme/web:1.4.2\n          env:\n            - name: DB_PASSWORD\n              valueFrom:\n                secretKeyRef: { name: db, key: password }\n",
  ".github/workflows/ci.yml": "on: pull_request\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: some-org/tool@0123456789abcdef0123456789abcdef01234567\n      - run: npm test\n        env:\n          TITLE: ${{ github.event.pull_request.title }}\n",
  "safe/main.tf": 'resource "aws_security_group" "web" {\n  ingress {\n    from_port   = 443\n    to_port     = 443\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\nresource "aws_db_instance" "ok" {\n  publicly_accessible = false\n  password = var.db_password\n}\n',
  "safe/pg_hba.conf": "host all all 127.0.0.1/32 trust\nhostssl all all 10.0.0.0/8 scram-sha-256\n",
  "safe/redis.conf": "bind 0.0.0.0\nrequirepass verylongpassword\n",
};

test("finds the planted deployment bugs and leaves the safe twins alone", () => {
  const root = mkdtempSync(join(tmpdir(), "saas-audit-infra-"));
  try {
    for (const [rel, text] of Object.entries(FILES)) {
      mkdirSync(dirname(join(root, rel)), { recursive: true });
      writeFileSync(join(root, rel), text);
    }
    const hits = analyzeInfra(root, Object.keys(FILES));
    const got = hits.map((h) => `${h.id} ${h.rel}:${h.line}`).sort();
    assert.ok(!hits.some((h) => h.rel.startsWith("safe/") || h.rel.endsWith("ci.yml")), `safe twins reported:\n${hits.filter((h) => h.rel.startsWith("safe/") || h.rel.endsWith("ci.yml")).map((h) => `${h.id} ${h.rel}:${h.line} ${h.title}`).join("\n")}`);
    assert.deepEqual(got, [
      "SEC052 Dockerfile:1", "SEC052 k8s/deploy.yaml:14",
      "SEC053 Dockerfile:2", "SEC053 Dockerfile:3", "SEC053 infra/main.tf:12", "SEC053 k8s/deploy.yaml:17", "SEC053 k8s/deploy.yaml:24",
      "SEC054 .github/workflows/pr.yml:11", "SEC054 Dockerfile:1", "SEC054 k8s/deploy.yaml:11",
      "SEC055 infra/main.tf:10", "SEC055 infra/main.tf:11", "SEC055 infra/main.tf:6",
      "SEC056 deploy/mongod.conf:2", "SEC056 deploy/pg_hba.conf:2", "SEC056 deploy/redis.conf:1",
      "SEC056 docker-compose.yml:11", "SEC056 docker-compose.yml:11", "SEC056 docker-compose.yml:5", "SEC056 docker-compose.yml:7", "SEC056 docker-compose.yml:8",
      "SEC057 .github/workflows/pr.yml:10", "SEC057 .github/workflows/pr.yml:2", "SEC057 .github/workflows/pr.yml:9",
      "SEC058 docker-compose.yml:14", "SEC058 docker-compose.yml:16", "SEC058 k8s/deploy.yaml:13", "SEC058 k8s/deploy.yaml:8",
    ].sort());
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
