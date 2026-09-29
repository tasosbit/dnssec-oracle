import { puyaTsTransformer } from '@algorandfoundation/algorand-typescript-testing/vitest-transformer'
import typescript from '@rollup/plugin-typescript'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  esbuild: {},
  test: {
    setupFiles: ['vitest.setup.ts'],
    // RSA-2048 proofs simulate twice (probe, then send) with ~135 op-up inner calls
    testTimeout: 120_000,
    hookTimeout: 60_000,
    // one LocalNet: e2e files run one at a time
    fileParallelism: false,
    // puya-ts-utils ships contract source: it runs through the emulator transform like ours
    server: { deps: { inline: [/puya-ts-utils/] } },
  },
  plugins: [
    typescript({
      tsconfig: './tsconfig.test.json',
      include: ['**/*.ts', /puya-ts-utils\/src\/.*\.ts$/],
      // `*.algo.spec.ts` files run against the AVM emulator; plain `*.spec.ts` are left alone
      transformers: {
        before: [puyaTsTransformer],
      },
    }),
  ],
})
