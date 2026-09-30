import { connect } from 'node:net'
import { concat, lowercaseName, readU16, readU32, requireBytes, RR, RRType, u16 } from './wire.js'

/** Answers a query with a raw DNS response message. */
export type Resolver = (name: Uint8Array, type: number) => Promise<Uint8Array>

/** A DNS query with EDNS0 and the DO bit set, so RRSIGs come back. */
export function buildQuery(name: Uint8Array, type: number, { recursion = true } = {}): Uint8Array {
  const id = Math.floor(Math.random() * 0x10000)
  const header = concat(u16(id), u16(recursion ? 0x0100 : 0), u16(1), u16(0), u16(0), u16(1))
  // OPT: root owner, type 41, UDP size 4096, extended rcode/version 0, DO bit
  const opt = concat(new Uint8Array([0]), u16(RRType.OPT), u16(4096), new Uint8Array([0, 0]), u16(0x8000), u16(0))
  return concat(header, name, u16(type), u16(1), opt)
}

/** Read a possibly compressed name at `at`: `[lowercase wire name, offset after it]`. */
function readName(msg: Uint8Array, at: number): [Uint8Array, number] {
  const parts: Uint8Array[] = []
  let end = -1
  let nameBytes = 1 // terminating zero
  for (let hops = 0; ; hops++) {
    if (hops > 128) throw new Error('DNS name compression loop')
    requireBytes(msg, at, 1)
    const length = msg[at]
    if (length >= 0xc0) {
      requireBytes(msg, at, 2)
      if (end < 0) end = at + 2
      at = ((length & 0x3f) << 8) | msg[at + 1]
    } else if (length === 0) {
      parts.push(new Uint8Array([0]))
      return [lowercaseName(concat(...parts)), end < 0 ? at + 1 : end]
    } else {
      if (length >= 0x40) throw new Error('extended label in a DNS name')
      requireBytes(msg, at + 1, length)
      nameBytes += length + 1
      if (nameBytes > 255) throw new Error('DNS name over 255 bytes')
      parts.push(msg.slice(at, at + 1 + length))
      at += 1 + length
    }
  }
}

/** The answer section of a response, RDATA raw (none of the types we read compress it). */
export function parseResponse(msg: Uint8Array): { rcode: number; answers: RR[] } {
  requireBytes(msg, 0, 12)
  const rcode = msg[3] & 0x0f
  const questions = readU16(msg, 4)
  const answerCount = readU16(msg, 6)
  let at = 12
  for (let i = 0; i < questions; i++) {
    at = readName(msg, at)[1]
    requireBytes(msg, at, 4)
    at += 4
  }
  const answers: RR[] = []
  for (let i = 0; i < answerCount; i++) {
    const [owner, next] = readName(msg, at)
    requireBytes(msg, next, 10)
    const length = readU16(msg, next + 8)
    requireBytes(msg, next + 10, length)
    answers.push({
      owner,
      type: readU16(msg, next),
      class: readU16(msg, next + 2),
      ttl: readU32(msg, next + 4),
      rdata: msg.slice(next + 10, next + 10 + length),
    })
    at = next + 10 + length
  }
  return { rcode, answers }
}

/** DNS over TCP, which sidesteps truncation of large DNSKEY responses. */
export function tcpResolver(server = '1.1.1.1', { port = 53, recursion = true, timeoutMs = 10_000 } = {}): Resolver {
  return (name, type) =>
    new Promise((resolve, reject) => {
      const query = buildQuery(name, type, { recursion })
      const socket = connect({ host: server, port })
      let buffer = new Uint8Array(0)
      socket.setTimeout(timeoutMs, () => socket.destroy(new Error(`DNS timeout from ${server}`)))
      socket.on('connect', () => socket.write(concat(u16(query.length), query)))
      socket.on('data', (chunk) => {
        buffer = concat(buffer, chunk)
        if (buffer.length >= 2 && buffer.length >= 2 + readU16(buffer, 0)) {
          socket.end()
          resolve(buffer.slice(2, 2 + readU16(buffer, 0)))
        }
      })
      socket.on('error', reject)
    })
}

/** Resolve through recorded responses: `captured["<name wire hex> <type>"]` is a message's hex. */
export function capturedResolver(captured: Record<string, string>): Resolver {
  return async (name, type) => {
    const hex = captured[captureKey(name, type)]
    if (!hex) throw new Error(`no captured response for ${captureKey(name, type)}`)
    return new Uint8Array(Buffer.from(hex, 'hex'))
  }
}

export const captureKey = (name: Uint8Array, type: number) => `${Buffer.from(name).toString('hex')} ${type}`

/** Wraps a resolver and records every response, for fixtures. */
export function recordingResolver(inner: Resolver, into: Record<string, string>): Resolver {
  return async (name, type) => {
    const msg = await inner(name, type)
    into[captureKey(name, type)] = Buffer.from(msg).toString('hex')
    return msg
  }
}
