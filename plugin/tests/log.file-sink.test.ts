// File sink for the logger.
//
// Motive: /status returned nothing and there was no way to tell why -- stderr
// belongs to the host process, so once the moment passes the evidence is gone.
// These cases pin the three properties that make the sink worth having: it
// records, it does not leak, and it cannot take the server down.

import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
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
