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

import { timingSafeEqual } from "node:crypto";
import { createMcpHandler } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import {
  hostHeaderValidation,
  localhostHostValidation,
  localhostOriginValidation,
  originValidation,
  toNodeHandler,
} from "@modelcontextprotocol/node";
import express, { type NextFunction, type Request, type Response } from "express";
import { createServer } from "./server.js";
import { SERVER_NAME, SERVER_VERSION } from "./constants.js";

function runStdio(): void {
  serveStdio(() => createServer(), {
    onerror: (error) => console.error(`${SERVER_NAME}: ${error.message}`),
  });
  console.error(`${SERVER_NAME} v${SERVER_VERSION} running on stdio (2026-07-28 + 2025-era clients)`);
}

/** Comma-separated env list; entries may be full origins or bare hostnames. */
function hostnameList(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((entry) => {
      try {
        return entry.includes("://") ? new URL(entry).hostname : entry;
      } catch {
        return entry;
      }
    });
}

function jsonRpcError(res: Response, status: number, code: number, message: string): void {
  res.status(status).json({ jsonrpc: "2.0", error: { code, message }, id: null });
}

function bearerMatches(header: string | undefined, token: string): boolean {
  const presented = Buffer.from(/^Bearer\s+(.+)$/i.exec(header ?? "")?.[1] ?? "");
  const expected = Buffer.from(token);
  return presented.length === expected.length && timingSafeEqual(presented, expected);
}

/**
 * Streamable HTTP for self-hosting. Safe by default: it binds to loopback and
 * only accepts localhost Host/Origin headers (DNS-rebinding protection). To
 * expose it, set HOST=0.0.0.0 together with ALLOWED_HOSTS (the public hostname
 * a reverse proxy forwards) and, ideally, MCP_AUTH_TOKEN.
 */
function runHttp(): void {
  const port = parseInt(process.env.PORT ?? "3000", 10);
  const host = process.env.HOST || "127.0.0.1";
  const loopback = ["127.0.0.1", "localhost", "::1"].includes(host);
  const allowedHosts = hostnameList(process.env.ALLOWED_HOSTS);
  const allowedOrigins = hostnameList(process.env.ALLOWED_ORIGINS);
  const token = process.env.MCP_AUTH_TOKEN;

  const checkHost = allowedHosts.length
    ? hostHeaderValidation(allowedHosts)
    : loopback
      ? localhostHostValidation()
      : undefined;
  const checkOrigin = allowedOrigins.length
    ? originValidation(allowedOrigins)
    : loopback
      ? localhostOriginValidation()
      : undefined;
  if (!loopback && !checkHost) {
    console.error(`${SERVER_NAME}: listening on ${host} without ALLOWED_HOSTS — any Host header is accepted (no DNS-rebinding protection).`);
  }
  if (!loopback && !token) {
    console.error(`${SERVER_NAME}: listening on ${host} without MCP_AUTH_TOKEN — anyone who can reach the port can use every tool.`);
  }

  const app = express();
  app.disable("x-powered-by");

  app.get("/healthz", (_req: Request, res: Response) => {
    res.json({ status: "ok", server: SERVER_NAME, version: SERVER_VERSION });
  });

  // One handler, one factory, both eras. `legacy` defaults to 'stateless',
  // which is exactly the shape the v1 stateless Streamable HTTP deployment had.
  const handler = createMcpHandler(() => createServer());
  const node = toNodeHandler(handler, {
    onerror: (error) => console.error(`${SERVER_NAME}: ${error.message}`),
  });

  // Host, Origin and token are checked before the body is read or parsed.
  const guard = (req: Request, res: Response, next: NextFunction) => {
    if (checkHost && !checkHost(req, res)) return;
    if (checkOrigin && !checkOrigin(req, res)) return;
    if (token && !bearerMatches(req.headers.authorization, token)) {
      res.setHeader("WWW-Authenticate", 'Bearer realm="mcp"');
      jsonRpcError(res, 401, -32001, "Unauthorized");
      return;
    }
    next();
  };

  app.all("/mcp", guard, express.json({ limit: "1mb" }), (req: Request, res: Response) => {
    void node(req, res, req.body);
  });

  // Body-parser failures answer in JSON-RPC, never with an HTML stack trace.
  app.use((err: Error & { type?: string; status?: number }, _req: Request, res: Response, next: NextFunction) => {
    if (res.headersSent) return next(err);
    if (err.type === "entity.too.large") return jsonRpcError(res, 413, -32600, "Request body too large");
    if (err.type === "entity.parse.failed") return jsonRpcError(res, 400, -32700, "Parse error");
    console.error(`${SERVER_NAME}: ${err.message}`);
    jsonRpcError(res, err.status ?? 500, -32603, "Internal error");
  });

  const httpServer = app.listen(port, host, () => {
    console.error(`${SERVER_NAME} v${SERVER_VERSION} running on http://${host}:${port}/mcp`);
  });

  // `docker stop` sends SIGTERM to PID 1: finish in-flight requests, then exit.
  const shutdown = () => {
    httpServer.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5_000).unref();
  };
  process.once("SIGTERM", shutdown);
  process.once("SIGINT", shutdown);
}

const transport = (process.env.TRANSPORT ?? "stdio").toLowerCase();

try {
  if (transport === "http") runHttp();
  else runStdio();
} catch (err) {
  console.error("Fatal error starting server:", err);
  process.exit(1);
}
