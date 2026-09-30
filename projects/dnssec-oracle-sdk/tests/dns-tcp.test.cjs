const assert = require('node:assert/strict')
const { createServer } = require('node:net')
const { test } = require('node:test')
const { tcpResolver, concat, u16 } = require('../dist/cjs/index.js')

async function withServer(t, handler) {
  const sockets = new Set()
  const server = createServer((socket) => {
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))
    socket.once('data', () => handler(socket))
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  t.after(() => {
    for (const socket of sockets) socket.destroy()
    return new Promise((resolve) => server.close(resolve))
  })
  return tcpResolver('127.0.0.1', { port: server.address().port, timeoutMs: 100 })
}

for (const [label, bytes] of [
  ['no frame', new Uint8Array()],
  ['partial prefix', new Uint8Array([0])],
  ['partial body', new Uint8Array([0, 12, 1, 2])],
]) {
  test(`early EOF rejects with ${label}`, { timeout: 1000 }, async (t) => {
    const resolver = await withServer(t, (socket) => socket.end(bytes))
    await assert.rejects(resolver(new Uint8Array([0]), 48), /Incomplete|closed/)
  })
}

test('fragmented response completes without waiting for peer EOF', { timeout: 1000 }, async (t) => {
  const message = new Uint8Array(12)
  message[2] = 0x80
  const frame = concat(u16(message.length), message)
  const resolver = await withServer(t, (socket) => {
    socket.write(frame.slice(0, 1))
    setTimeout(() => socket.write(frame.slice(1, 5)), 10)
    setTimeout(() => socket.write(frame.slice(5)), 20)
  })
  assert.deepEqual(await resolver(new Uint8Array([0]), 48), message)
})

test('silent and trickling peers are bounded by a total deadline', { timeout: 1000 }, async (t) => {
  for (const trickle of [false, true]) {
    const resolver = await withServer(t, (socket) => {
      if (trickle) {
        socket.write(new Uint8Array([255, 255]))
        const timer = setInterval(() => socket.write(new Uint8Array([0])), 20)
        socket.once('close', () => clearInterval(timer))
      }
    })
    await assert.rejects(resolver(new Uint8Array([0]), 48), /DNS timeout/)
  }
})
