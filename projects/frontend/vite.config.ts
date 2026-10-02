import { fileURLToPath } from 'node:url'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

const shim = (file: string) => fileURLToPath(new URL(`./src/shims/${file}`, import.meta.url))

// The SDK imports node:crypto (hashing, signature checks) and node:net (DNS over TCP, unused
// here: the browser resolves over DoH). The shims stand in for both.
export default defineConfig({
  plugins: [react()],
  resolve: { alias: { 'node:crypto': shim('crypto.ts'), 'node:net': shim('net.ts') } },
  test: { environment: 'node' },
})
