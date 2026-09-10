/**
 * Shared response-formatting helpers for MCP tool handlers.
 *
 * Every data-returning tool supports two output formats:
 *   - "markdown" (default): human-readable, summarised.
 *   - "json": complete structured data for programmatic use.
 */

import * as z from "zod/v4";
import type { CallToolResult } from "@modelcontextprotocol/server";
import { CHARACTER_LIMIT } from "./constants.js";

export enum ResponseFormat {
  MARKDOWN = "markdown",
  JSON = "json",
}

/** Reusable Zod field so every tool exposes the same `response_format` option. */
export const responseFormatField = z
  .enum(ResponseFormat)
  .default(ResponseFormat.MARKDOWN)
  .describe(
    "Output format: 'markdown' for a human-readable summary (default) or 'json' for the full structured payload.",
  );

/** Truncate oversized text so a single tool call never floods the context window. */
export function truncate(text: string): string {
  if (text.length <= CHARACTER_LIMIT) return text;
  return (
    text.slice(0, CHARACTER_LIMIT) +
    `\n\n…[truncated ${text.length - CHARACTER_LIMIT} characters — request response_format='json' or a narrower query for the full payload]`
  );
}

/** A successful tool result carrying a single text block. */
export function ok(text: string): CallToolResult {
  return { content: [{ type: "text", text: truncate(text) }] };
}

/** An error tool result. Messages should be actionable (what went wrong + next step). */
export function fail(text: string): CallToolResult {
  return { content: [{ type: "text", text: truncate(text) }], isError: true };
}

/**
 * Render `data` as the tool's text content (pretty JSON or the markdown renderer)
 * AND attach it as `structuredContent` for clients that consume the tool's
 * `outputSchema`. `data` must be a plain object (the SDK validates it against the
 * declared outputSchema).
 */
export function respond(
  data: unknown,
  format: ResponseFormat,
  toMarkdown: () => string,
): CallToolResult {
  const text =
    format === ResponseFormat.JSON ? JSON.stringify(data, null, 2) : toMarkdown();
  return {
    content: [{ type: "text", text: truncate(text) }],
    structuredContent: data as Record<string, unknown>,
  };
}

/** Small helper: render a checklist line with a status glyph. */
export function statusLine(passed: boolean, label: string): string {
  return `${passed ? "✅" : "❌"} ${label}`;
}

/** Map a 0–100 score to a letter grade. */
export function scoreToGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}
