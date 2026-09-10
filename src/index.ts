#!/usr/bin/env node
/**
 * domain-security-mcp-server entry point.
 *
 * Built on the **v2 MCP SDK**, so it speaks the 2026-07-28 protocol revision
 * *and* keeps serving 2025-era clients (Claude Desktop, Claude Code, Cursor)
 * from the same factory — the entry point owns the era decision, not the
 * server object.
 *
 * Transports:
 *   - stdio (default) : `serveStdio(factory)`. The opening exchange pins the
 *                       connection's era; one server instance per connection.
 *   - http            : `createMcpHandler(factory)` behind Express, for
 *                       self-hosting (e.g. behind a Coolify/Traefik reverse
 *                       proxy). Stateless by definition — the 2026 revision is
 *                       per request, and the default `legacy: 'stateless'`
 *                       serves 2025 clients through the same endpoint. No
 *                       `Mcp-Session-Id`. Set TRANSPORT=http.
 *
 * No API keys are required for any tool. All logging goes to stderr so it never
 * corrupts the stdio JSON-RPC stream.
 */

import { createMcpHandler } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { toNodeHandler } from "@modelcontextprotocol/node";
import express, { type Request, type Response } from "express";
import { createServer } from "./server.js";
import { SERVER_NAME, SERVER_VERSION } from "./constants.js";

function runStdio(): void {
  serveStdio(() => createServer(), {
    onerror: (error) => console.error(`${SERVER_NAME}: ${error.message}`),
  });
  console.error(`${SERVER_NAME} v${SERVER_VERSION} running on stdio (2026-07-28 + 2025-era clients)`);
}

function originAllowed(req: Request): boolean {
  const allow = (process.env.ALLOWED_ORIGINS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (allow.length === 0) return true; // open (trust the reverse proxy)
  const origin = req.headers.origin;
  return !origin || allow.includes(origin);
}

function runHttp(): void {
  const app = express();
  app.use(express.json({ limit: "1mb" }));

  app.get("/healthz", (_req: Request, res: Response) => {
    res.json({ status: "ok", server: SERVER_NAME, version: SERVER_VERSION });
  });

  // One handler, one factory, both eras. `legacy` defaults to 'stateless',
  // which is exactly the shape the v1 stateless Streamable HTTP deployment had.
  const handler = createMcpHandler(() => createServer());
  const node = toNodeHandler(handler, {
    onerror: (error) => console.error(`${SERVER_NAME}: ${error.message}`),
  });

  app.all("/mcp", (req: Request, res: Response) => {
    if (!originAllowed(req)) {
      res.status(403).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Origin not allowed" },
        id: null,
      });
      return;
    }
    void node(req, res, req.body);
  });

  const port = parseInt(process.env.PORT ?? "3000", 10);
  const host = process.env.HOST ?? "0.0.0.0";
  app.listen(port, host, () => {
    console.error(`${SERVER_NAME} v${SERVER_VERSION} running on http://${host}:${port}/mcp`);
  });
}

const transport = (process.env.TRANSPORT ?? "stdio").toLowerCase();

try {
  if (transport === "http") runHttp();
  else runStdio();
} catch (err) {
  console.error("Fatal error starting server:", err);
  process.exit(1);
}
