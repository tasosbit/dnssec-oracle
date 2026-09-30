const assert = require('node:assert/strict')
const { spawnSync } = require('node:child_process')
const path = require('node:path')
const { test } = require('node:test')
const sdk = require('../dist/cjs/index.js')

test('malformed uncompressed names and RRSIGs reject without hanging', () => {
  // Isolate the adversarial calls: a regression must fail instead of freezing the runner.
  const child = spawnSync(process.execPath, ['-e', `
    const assert = require('node:assert/strict');
    const sdk = require(${JSON.stringify(path.resolve(__dirname, '../dist/cjs/index.js'))});
    const overlong = Uint8Array.from([...Array(4).fill([63, ...Array(63).fill(97)]).flat(), 0]);
    for (const bad of [new Uint8Array(), new Uint8Array([1, 97]), new Uint8Array([64, 0]), overlong]) {
      for (const name of ['nameFromWire', 'lowercaseName', 'labelCount', 'ancestors']) {
        assert.throws(() => sdk[name](bad), name);
      }
      assert.throws(() => sdk.nameLength(bad, 0));
    }
    assert.throws(() => sdk.parseRrsig(new Uint8Array(18)));
    assert.throws(() => sdk.rdataOf(new Uint8Array([0, 0, 48, 0, 1, 0, 0, 0, 1, 0, 4, 1])));
    assert.throws(() => sdk.parseDnskey(new Uint8Array(3)));
    assert.throws(() => sdk.parseDs(new Uint8Array(3)));
    assert.throws(() => sdk.txtStrings(new Uint8Array([2, 97])));
  `], { timeout: 3000, encoding: 'utf8' })
  assert.ifError(child.error)
  assert.equal(child.status, 0, child.stderr)
})

const response = (answer) => sdk.concat(
  sdk.u16(1), sdk.u16(0x8000), sdk.u16(0), sdk.u16(1), sdk.u16(0), sdk.u16(0), answer,
)

test('response parsing rejects truncated headers, labels, pointers and RDATA', () => {
  const badAnswers = [
    new Uint8Array([1, 97]),
    new Uint8Array([0xc0]),
    new Uint8Array([0xc0, 255]),
    new Uint8Array([0x40, 0]),
    new Uint8Array([0]), // no RR header
    sdk.concat(new Uint8Array([0]), sdk.u16(16), sdk.u16(1), sdk.u32(1), sdk.u16(4), new Uint8Array([1])),
  ]
  for (const answer of badAnswers) assert.throws(() => sdk.parseResponse(response(answer)))
  assert.throws(() => sdk.parseResponse(new Uint8Array(11)))
  assert.throws(() => sdk.parseResponse(response(new Uint8Array([0xc0, 12]))), /loop/)
})

test('legitimate compressed owners are expanded and lowercased', () => {
  const owner = sdk.nameToWire('example.com')
  owner[1] = 69 // E
  const header = sdk.concat(sdk.u16(1), sdk.u16(0x8000), sdk.u16(1), sdk.u16(1), sdk.u16(0), sdk.u16(0))
  const question = sdk.concat(owner, sdk.u16(16), sdk.u16(1))
  const rdata = sdk.txtRdata('hello')
  const answer = sdk.concat(new Uint8Array([0xc0, 12]), sdk.u16(16), sdk.u16(1), sdk.u32(3600), sdk.u16(rdata.length), rdata)
  const parsed = sdk.parseResponse(sdk.concat(header, question, answer))
  assert.equal(sdk.nameFromWire(parsed.answers[0].owner), 'example.com.')
  assert.deepEqual(parsed.answers[0].rdata, rdata)
})

test('recorded DNSSEC chains still build and verify', async () => {
  const fixture = require('../../dnssec-oracle/tests/fixtures/2026-09-28.json')
  for (const name of fixture.names) {
    const steps = await sdk.buildTxtChain(name, sdk.capturedResolver(fixture.responses), {
      anchors: sdk.ROOT_ANCHORS, now: fixture.capturedAt,
    })
    assert.equal(steps[0].kind, 'root')
    assert.equal(steps.at(-1).kind, 'txt')
  }
})
