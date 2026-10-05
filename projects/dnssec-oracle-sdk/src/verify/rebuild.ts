import { execFile } from 'node:child_process'
import { access, mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { promisify } from 'node:util'
import { RebuildOutput, TARGET_AVM_VERSION } from '../verify.js'

const run = promisify(execFile)

const exists = (path: string) =>
  access(path).then(
    () => true,
    () => false,
  )

/** Walk up from `from` looking for `relative`; the first hit, or undefined. */
async function findUp(from: string, relative: string): Promise<string | undefined> {
  for (let dir = resolve(from); ; dir = dirname(dir)) {
    const candidate = join(dir, relative)
    if (await exists(candidate)) return candidate
    if (dirname(dir) === dir) return undefined
  }
}

/** The shipped sources next to this module: `dist/{cjs,esm}/verify` or `src/verify` → `contract/`. */
async function shippedSources(): Promise<string | undefined> {
  // __dirname exists in the CommonJS build and under tsx; the ESM build falls through to cwd
  if (typeof __dirname !== 'string') return undefined
  for (const root of [resolve(__dirname, '..', '..'), resolve(__dirname, '..', '..', '..')]) {
    if (await exists(join(root, 'contract', 'dnssec_oracle'))) return join(root, 'contract')
  }
  return undefined
}

/**
 * Compile the contract sources shipped with the SDK (`contract/`, copied from
 * `projects/dnssec-oracle/smart_contracts` at build time) with `puya-ts`, and return the
 * DnssecOracle bytecode. Nothing is installed: when the sources or the compiler cannot be
 * found the result says so and the caller reports `skip`.
 */
export async function rebuildContract({ contractDir, puyaTs }: { contractDir?: string; puyaTs?: string } = {}): Promise<RebuildOutput> {
  const sources =
    contractDir ??
    (await shippedSources()) ??
    (await findUp(process.cwd(), join('node_modules', '@d13co', 'dnssec-oracle-sdk', 'contract'))) ??
    (await findUp(process.cwd(), join('contract', 'dnssec_oracle')).then((p) => p && dirname(p)))
  if (!sources || !(await exists(join(sources, 'dnssec_oracle', 'contract.algo.ts')))) {
    return { skipped: 'contract sources not found: pass rebuild.contractDir (the SDK package ships them under contract/)' }
  }
  // the monorepo keeps puya-ts in the contract project, a sibling of the SDK
  const sibling = resolve(sources, '..', '..', 'dnssec-oracle', 'node_modules', '.bin', 'puya-ts')
  const compiler =
    puyaTs ??
    (await findUp(sources, join('node_modules', '.bin', 'puya-ts'))) ??
    (await findUp(process.cwd(), join('node_modules', '.bin', 'puya-ts'))) ??
    ((await exists(sibling)) ? sibling : 'puya-ts')
  const out = await mkdtemp(join(tmpdir(), 'dnssec-oracle-rebuild-'))
  try {
    const args = [
      sources,
      '--target-avm-version',
      String(TARGET_AVM_VERSION),
      '--out-dir',
      out,
      '--output-arc56',
      '--no-output-teal',
      '--no-output-arc32',
      '--no-output-source-map',
      '--log-level',
      'error',
    ]
    try {
      await run(compiler, args, { cwd: sources, maxBuffer: 64 * 1024 * 1024, timeout: 10 * 60 * 1000 })
    } catch (e) {
      const err = e as NodeJS.ErrnoException & { stderr?: string }
      if (err.code === 'ENOENT') {
        return { skipped: `puya-ts not found (${compiler}): install @algorandfoundation/puya-ts or pass rebuild.puyaTs` }
      }
      return { skipped: `puya-ts failed: ${(err.stderr || err.message || '').trim().split('\n').slice(-3).join(' ')}` }
    }
    const spec = JSON.parse(await readFile(join(out, 'dnssec_oracle', 'DnssecOracle.arc56.json'), 'utf8')) as {
      byteCode?: { approval: string; clear: string }
      compilerInfo?: { compiler: string; compilerVersion: { major: number; minor: number; patch: number } }
    }
    if (!spec.byteCode) return { skipped: 'puya-ts produced no bytecode' }
    const v = spec.compilerInfo?.compilerVersion
    return {
      approval: new Uint8Array(Buffer.from(spec.byteCode.approval, 'base64')),
      clear: new Uint8Array(Buffer.from(spec.byteCode.clear, 'base64')),
      compilerVersion: v ? `${spec.compilerInfo?.compiler ?? 'puya'} ${v.major}.${v.minor}.${v.patch}` : 'unknown',
    }
  } finally {
    await rm(out, { recursive: true, force: true })
  }
}
