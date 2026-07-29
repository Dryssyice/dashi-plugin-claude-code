// File sink for the logger.
//
// Motive: /status returned nothing and there was no way to tell why -- stderr
// belongs to the host process, so once the moment passes the evidence is gone.
// These cases pin the three properties that make the sink worth having: it
// records, it does not leak, and it cannot take the server down.

import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { createLogger } from '../src/log.js'

let dir: string

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'dashi-log-'))
})

afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
})

function sink(): NodeJS.WritableStream {
  return { write: () => true } as unknown as NodeJS.WritableStream
}

describe('logger file sink', () => {
  test('writes the line to the configured file', () => {
    const path = join(dir, 'nested', 'plugin.log')
    const log = createLogger('status', { stream: sink(), filePath: path })

    log.info('status command handled', { chatId: '123' })

    const body = readFileSync(path, 'utf8')
    expect(body).toContain('status command handled')
    expect(body).toContain('[info] [status]')
    expect(body).toContain('"chatId":"123"')
  })

  test('redacts configured secrets on the way to disk', () => {
    const path = join(dir, 'plugin.log')
    const log = createLogger('webhook', {
      stream: sink(),
      filePath: path,
      secrets: ['super-secret-value'],
    })

    log.error('auth rejected', { token: 'super-secret-value' })

    const body = readFileSync(path, 'utf8')
    expect(body).not.toContain('super-secret-value')
  })

  test('file is owner-only', () => {
    const path = join(dir, 'plugin.log')
    createLogger('status', { stream: sink(), filePath: path }).info('x')

    expect(statSync(path).mode & 0o777).toBe(0o600)
  })

  test('tightens an existing world-readable log before appending', () => {
    const path = join(dir, 'plugin.log')
    writeFileSync(path, 'from an earlier run\n', { mode: 0o644 })
    chmodSync(path, 0o644)

    createLogger('status', { stream: sink(), filePath: path }).info('second run')

    expect(statSync(path).mode & 0o777).toBe(0o600)
    expect(readFileSync(path, 'utf8')).toContain('from an earlier run')
  })

  test('rotates once the file passes its limit', () => {
    const path = join(dir, 'plugin.log')
    const log = createLogger('status', { stream: sink(), filePath: path, rotateBytes: 200 })

    for (let i = 0; i < 20; i++) log.info(`line ${i} ${'x'.repeat(50)}`)

    expect(readFileSync(`${path}.1`, 'utf8').length).toBeGreaterThan(0)
    expect(statSync(path).size).toBeLessThan(400)
  })

  test('the rotated copy is owner-only too', () => {
    // Tightening only the current file leaves the rotated one carrying whatever
    // permissions it had when it was still current. The old conversation is no
    // less private for having been renamed, and `.1` is where most of it lives.
    const path = join(dir, 'plugin.log')
    writeFileSync(path, `${'x'.repeat(300)}\n`, { mode: 0o644 })
    chmodSync(path, 0o644)

    createLogger('status', { stream: sink(), filePath: path, rotateBytes: 200 }).info('rolls over')

    expect(statSync(`${path}.1`).mode & 0o777).toBe(0o600)
    expect(statSync(path).mode & 0o777).toBe(0o600)
  })

  test('tightens a rotated copy the older version left loose', () => {
    // The upgrade state, which the case above cannot reach: `.1` was rotated by
    // the vulnerable version and is already on disk at 0644, while the current
    // file is fine and nowhere near the rotation threshold. Nothing in the new
    // ordering would ever look at it.
    const path = join(dir, 'plugin.log')
    writeFileSync(path, 'current\n', { mode: 0o600 })
    chmodSync(path, 0o600)
    writeFileSync(`${path}.1`, 'left behind by an older version\n', { mode: 0o644 })
    chmodSync(`${path}.1`, 0o644)

    createLogger('status', { stream: sink(), filePath: path }).info('one emit')

    expect(statSync(`${path}.1`).mode & 0o777).toBe(0o600)
    expect(statSync(path).mode & 0o777).toBe(0o600)
  })

  test('writes nothing through a symlink', () => {
    // A log path an attacker can pre-create as a symlink must not turn the
    // logger into a chmod primitive on someone else's file -- and refusing the
    // chmod while still appending is worse than either failure alone: the
    // target keeps its permissions AND receives the private log. Both the mode
    // and the contents have to be untouched.
    const victim = join(dir, 'victim.txt')
    writeFileSync(victim, 'not ours\n', { mode: 0o644 })
    chmodSync(victim, 0o644)
    const path = join(dir, 'plugin.log')
    symlinkSync(victim, path)

    createLogger('status', { stream: sink(), filePath: path }).info('PRIVATE_CHAT_MARKER')

    expect(statSync(victim).mode & 0o777).toBe(0o644)
    expect(readFileSync(victim, 'utf8')).toBe('not ours\n')
  })

  test('an unwritable path does not throw', () => {
    const path = join(dir, 'locked', 'plugin.log')
    writeFileSync(join(dir, 'locked'), 'not a directory')

    const log = createLogger('status', { stream: sink(), filePath: path })

    expect(() => log.error('still alive')).not.toThrow()
  })

  test('stays silent when no file is configured', () => {
    const log = createLogger('status', { stream: sink() })

    expect(() => log.info('no sink')).not.toThrow()
  })

  test('read-only directory does not throw', () => {
    const locked = join(dir, 'ro')
    const path = join(locked, 'plugin.log')
    createLogger('status', { stream: sink(), filePath: path }).info('creates dir')
    chmodSync(locked, 0o500)

    const log = createLogger('status', { stream: sink(), filePath: join(locked, 'other.log') })

    expect(() => log.warn('cannot write')).not.toThrow()
    chmodSync(locked, 0o700)
  })
})
