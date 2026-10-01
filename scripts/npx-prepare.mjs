// Makes `npx github:tasosbit/dnssec-oracle` work: npm runs `prepare` on git
// installs, and this bundles the CLI (with the SDK and all deps) into bin/.
// pnpm also runs root `prepare` on every workspace install; skip it there.
import { execSync } from 'node:child_process'

if (process.env.npm_config_user_agent?.startsWith('pnpm')) process.exit(0)

const pnpm = (args) => execSync(`npx -y pnpm@10 ${args}`, { stdio: 'inherit' })
pnpm('install --frozen-lockfile')
pnpm('--dir projects/dnssec-oracle-sdk run build')
pnpm('--dir projects/cli run bundle')
