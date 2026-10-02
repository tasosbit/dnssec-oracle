export function connect(): never {
  throw new Error('DNS over TCP is unavailable in the browser: use a DoH resolver')
}
