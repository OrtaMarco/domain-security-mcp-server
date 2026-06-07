#!/usr/bin/env node
/**
 * domain-security-mcp-server entry point.
 *
 * Transports:
 *   - stdio (default)  : for Claude Desktop / Claude Code and other local clients.
 *   - http             : stateless Streamable HTTP, for self-hosting (e.g. behind
 *                        a Coolify/Traefik reverse proxy). Set TRANSPORT=http.
 *
 * No API keys are required for any tool. All logging goes to stderr so it never
 * corrupts the stdio JSON-RPC stream.
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express, { type Request, type Response } from "express";
import { createServer } from "./server.js";
import { SERVER_NAME, SERVER_VERSION } from "./constants.js";

async function runStdio(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`${SERVER_NAME} v${SERVER_VERSION} running on stdio`);
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

async function runHttp(): Promise<void> {
  const app = express();
  app.use(express.json({ limit: "1mb" }));

  app.get("/healthz", (_req: Request, res: Response) => {
    res.json({ status: "ok", server: SERVER_NAME, version: SERVER_VERSION });
  });

  app.post("/mcp", async (req: Request, res: Response) => {
    if (!originAllowed(req)) {
      res.status(403).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Origin not allowed" },
        id: null,
      });
      return;
    }

    // Stateless: a fresh server + transport per request avoids cross-request
    // state and request-ID collisions.
    const server = createServer();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });

    res.on("close", () => {
      void transport.close();
      void server.close();
    });

    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      console.error("Error handling MCP request:", err);
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error" },
          id: null,
        });
      }
    }
  });

  // Stateless mode does not support SSE streams or session teardown.
  const methodNotAllowed = (_req: Request, res: Response) => {
    res.status(405).json({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Method not allowed (stateless server)." },
      id: null,
    });
  };
  app.get("/mcp", methodNotAllowed);
  app.delete("/mcp", methodNotAllowed);

  const port = parseInt(process.env.PORT ?? "3000", 10);
  const host = process.env.HOST ?? "0.0.0.0";
  app.listen(port, host, () => {
    console.error(`${SERVER_NAME} v${SERVER_VERSION} running on http://${host}:${port}/mcp`);
  });
}

const transport = (process.env.TRANSPORT ?? "stdio").toLowerCase();
const main = transport === "http" ? runHttp : runStdio;

main().catch((err) => {
  console.error("Fatal error starting server:", err);
  process.exit(1);
});
