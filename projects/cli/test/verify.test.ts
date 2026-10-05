import { describe, expect, it } from 'vitest'
import { VerificationResult } from '@d13co/dnssec-oracle-sdk'
import { formatVerification } from '../src/commands'

const passing: VerificationResult = {
  ok: true,
  checks: [
    { name: 'program', status: 'pass', message: 'approval and clear programs match APP_SPEC (puya 5.10.1), approval sha256 0123456789abcdef…' },
    { name: 'actions', status: 'pass', message: 'no UpdateApplication or DeleteApplication action in the ARC-56 spec (16 methods, bare create NoOp)' },
    { name: 'anchors', status: 'pass', message: 'tag 20326 Valid (IANA), tag 38696 Valid (IANA)' },
    { name: 'admin', status: 'pass', message: 'renounced (zero address)' },
    { name: 'rootKeys', status: 'pass', message: 'rootEpoch 1, rollInception none, anchors 2 Valid' },
  ],
}

describe('formatVerification', () => {
  it('prints one aligned line per check and a verdict', () => {
    const lines = formatVerification(passing)
    expect(lines).toEqual([
      '✔ program   approval and clear programs match APP_SPEC (puya 5.10.1), approval sha256 0123456789abcdef…',
      '✔ actions   no UpdateApplication or DeleteApplication action in the ARC-56 spec (16 methods, bare create NoOp)',
      '✔ anchors   tag 20326 Valid (IANA), tag 38696 Valid (IANA)',
      '✔ admin     renounced (zero address)',
      '✔ rootKeys  rootEpoch 1, rollInception none, anchors 2 Valid',
      'verified',
    ])
  })

  it('names the warnings in the verdict without failing it', () => {
    const warned: VerificationResult = {
      ...passing,
      checks: passing.checks.map((c) =>
        c.name === 'anchors' ? { ...c, status: 'warn', message: 'IANA file not checked: offline; tag 20326 Valid (IANA)' } : c,
      ),
    }
    const lines = formatVerification(warned)
    expect(lines[2]).toBe('! anchors   IANA file not checked: offline; tag 20326 Valid (IANA)')
    expect(lines.at(-1)).toBe('verified, with warnings: anchors')
  })

  it('lists the failed checks in the verdict: the exit code follows `ok`', () => {
    const failed: VerificationResult = {
      ok: false,
      checks: passing.checks.map((c) =>
        c.name === 'program'
          ? { ...c, status: 'fail', message: 'on-chain programs differ from APP_SPEC: approval 00… vs 01…' }
          : c.name === 'rootKeys'
            ? { ...c, status: 'warn', message: 'abc… AddPend since 2026-01-01T00:00:00.000Z with its hold-down over: no watcher ran updateAnchor; rootEpoch 1' }
            : c,
      ),
    }
    const lines = formatVerification(failed)
    expect(lines[0]).toBe('✖ program   on-chain programs differ from APP_SPEC: approval 00… vs 01…')
    expect(lines.at(-1)).toBe('NOT VERIFIED: program failed; warnings: rootKeys')
  })
})
