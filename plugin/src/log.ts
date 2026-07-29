// Redacted structured logger.
// Format: [ISO-ts] [level] [name] message {ctx-json}
// Output goes to stderr by default so it doesn't poison the MCP stdio transport.

import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  mkdirSync,
  openSync,
  renameSync,
  statSync,
  writeSync,
} from 'node:fs'
import { dirname } from 'node:path'

import { redactToken } from './config.js'

export type LogLevel = 'debug' | 'info' | 'warn' | 'error'

export interface Logger {
  debug(msg: string, ctx?: Record<string, unknown>): void
  info(msg: string, ctx?: Record<string, unknown>): void
  warn(msg: string, ctx?: Record<string, unknown>): void
  error(msg: string, ctx?: Record<string, unknown>): void
}

export interface CreateLoggerOptions {
  stream?: NodeJS.WritableStream
  // Exact-substring secrets to redact alongside the pattern-based ones
  // (Telegram bot token, Groq key, Bearer/query tokens). Useful for the
  // configured TELEGRAM_WEBHOOK_TOKEN which has no public pattern.
  secrets?: ReadonlyArray<string>
  // Mirror every emitted line into this file as well as the stream. Defaults
  // to the DASHI_LOG_FILE environment variable; unset means stderr only, as
  // before.
  filePath?: string
  // Size at which the file is rolled to `<path>.1`. Kept injectable so a test
  // can prove rotation without writing megabytes.
  rotateBytes?: number
}

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
}

function envLevel(): LogLevel {
  const raw = (process.env.LOG_LEVEL ?? '').toLowerCase()
  if (raw === 'debug' || raw === 'info' || raw === 'warn' || raw === 'error') return raw
  return 'info'
}

function formatLine(
  name: string,
  level: LogLevel,
  msg: string,
  ctx: Record<string, unknown> | undefined,
  secrets: ReadonlyArray<string>,
): string {
  const ts = new Date().toISOString()
  let body = `[${ts}] [${level}] [${name}] ${msg}`
  if (ctx && Object.keys(ctx).length > 0) {
    let serialized: string
    try {
      serialized = JSON.stringify(ctx)
    } catch (err) {
      serialized = `<unserializable:${err instanceof Error ? err.message : String(err)}>`
    }
    body += ` ${redactToken(serialized, secrets)}`
  }
  return redactToken(body, secrets) + '\n'
}

// Stderr is the right default for an MCP stdio server, but it is also the
// reason a misbehaving command cannot be diagnosed after the fact: the host
// captures stderr, and by the time someone asks "why did /status say nothing?"
// there is nothing left to read. Setting DASHI_LOG_FILE keeps a copy on disk.
const ROTATE_BYTES = 5 * 1024 * 1024

function envLogFile(): string | undefined {
  const raw = (process.env.DASHI_LOG_FILE ?? '').trim()
  return raw.length > 0 ? raw : undefined
}

function rotateIfLarge(path: string, limit: number): void {
  try {
    if (statSync(path).size < limit) return
    renameSync(path, `${path}.1`)
  } catch {
    // Missing file is the normal first-write case; anything else must not
    // take the logger down with it.
  }
}

function tightenIfLoose(path: string): void {
  let fd: number | undefined
  try {
    // `mode` on appendFileSync applies only when the file is created, so a log
    // that already exists keeps whatever permissions it had -- including
    // world-readable. Redaction removes tokens, not the conversation.
    //
    // Opened with O_NOFOLLOW and tightened through the descriptor rather than
    // the path: a log path someone can pre-create as a symlink would otherwise
    // have us chmod whatever it points at. Refusing to follow costs one log
    // line; following costs someone else's file.
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW)
    const mode = fstatSync(fd).mode & 0o777
    if ((mode & 0o077) !== 0) fchmodSync(fd, 0o600)
  } catch {
    // Not there yet, or a symlink we decline to follow: the append below
    // creates it with the right mode.
  } finally {
    if (fd !== undefined) closeSync(fd)
  }
}

function appendToFile(path: string, line: string, limit: number): void {
  let fd: number | undefined
  try {
    mkdirSync(dirname(path), { recursive: true })
    // Tighten BEFORE rotating, not after. Rotation renames the current file to
    // `.1`, and a rename carries the old permissions with it -- so tightening
    // afterwards fixes only the empty file about to be created and leaves the
    // whole rotated conversation world-readable.
    tightenIfLoose(path)
    // The rotated copy is checked on its own, because upgrading the code does
    // not rewrite what the old code already left on disk: a `.1` rotated at
    // 0644 before this fix stays 0644 forever otherwise. An old conversation
    // is not less private for predating the fix, and `.1` is where the bulk
    // of it lives.
    tightenIfLoose(`${path}.1`)
    rotateIfLarge(path, limit)
    // The write follows the same rule as the chmod above, and for a sharper
    // reason: refusing to chmod through a symlink while still appending through
    // it protects the target's permissions and hands it the private log anyway.
    // O_NOFOLLOW makes the open fail on a link, O_CREAT|0600 covers the first
    // write, and the fstat check keeps a fifo or device from standing in for a
    // regular file. Losing a log line is the correct outcome here.
    fd = openSync(
      path,
      constants.O_WRONLY |
        constants.O_APPEND |
        constants.O_CREAT |
        constants.O_NOFOLLOW |
        constants.O_NONBLOCK,
      0o600,
    )
    const st = fstatSync(fd)
    if (!st.isFile()) return
    // 0600: lines are redacted, but a log of a private chat is still private.
    if ((st.mode & 0o077) !== 0) fchmodSync(fd, 0o600)
    writeSync(fd, line)
  } catch {
    // never let logging throw
  } finally {
    if (fd !== undefined) closeSync(fd)
  }
}

export function createLogger(name: string, opts: CreateLoggerOptions = {}): Logger {
  const stream: NodeJS.WritableStream = opts.stream ?? process.stderr
  const threshold = LEVEL_ORDER[envLevel()]
  const secrets: ReadonlyArray<string> = opts.secrets ?? []
  const filePath = opts.filePath ?? envLogFile()
  const rotateBytes = opts.rotateBytes ?? ROTATE_BYTES
  const emit = (level: LogLevel, msg: string, ctx?: Record<string, unknown>): void => {
    if (LEVEL_ORDER[level] < threshold) return
    const line = formatLine(name, level, msg, ctx, secrets)
    try {
      stream.write(line)
    } catch {
      // never let logging throw
    }
    // The file sink is written whether or not stderr accepted the line: the
    // case worth diagnosing is precisely the one where the stream is gone.
    if (filePath) appendToFile(filePath, line, rotateBytes)
  }
  return {
    debug: (msg, ctx) => emit('debug', msg, ctx),
    info: (msg, ctx) => emit('info', msg, ctx),
    warn: (msg, ctx) => emit('warn', msg, ctx),
    error: (msg, ctx) => emit('error', msg, ctx),
  }
}
