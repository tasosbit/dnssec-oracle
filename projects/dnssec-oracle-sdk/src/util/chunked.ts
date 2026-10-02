import { toHex } from '../prover/wire.js'
import { chunk } from './chunk.js'

/**
 * Concurrency-limited map preserving input order (small local stand-in for p-map,
 * which is ESM-only and would break the dual CJS+ESM build).
 */
export async function mapConcurrent<T, R>(items: T[], mapper: (item: T) => Promise<R>, concurrency: number): Promise<R[]> {
  const results: R[] = new Array(items.length)
  let next = 0
  const workers = Array.from({ length: Math.max(1, Math.min(concurrency, items.length)) }, async () => {
    while (next < items.length) {
      const i = next++
      results[i] = await mapper(items[i])
    }
  })
  await Promise.all(workers)
  return results
}

/**
 * Decorator that automatically chunks an array argument and flattens the results in order.
 * Concurrency is read from `this.concurrency` when present (default 2).
 * @param chunkSize - The maximum size of each chunk
 * @param chunkArgIndex - The index of the argument to chunk
 */
export function chunked(chunkSize: number, chunkArgIndex = 0) {
  return function (_target: object, _propertyKey: string, descriptor: PropertyDescriptor): PropertyDescriptor {
    const originalMethod = descriptor.value

    descriptor.value = async function (...args: unknown[]) {
      const arr = args[chunkArgIndex] as unknown[]
      if (arr.length <= chunkSize) {
        return originalMethod.apply(this, args)
      }
      const self = this as { concurrency?: number }
      const concurrency = typeof self.concurrency === 'number' ? self.concurrency : 2

      const chunks = chunk(arr, chunkSize)
      const results = await mapConcurrent(
        chunks,
        async (chunkedItems) => {
          const applyArgs = [...args.slice(0, chunkArgIndex), chunkedItems, ...args.slice(chunkArgIndex + 1)]
          return originalMethod.apply(this, applyArgs)
        },
        concurrency,
      )
      return results.flat()
    }

    return descriptor
  }
}

/**
 * Decorator that passes each distinct item of an array argument once and expands the
 * results back to every input position. Items are keyed by value: strings as they are,
 * byte arrays by hex. Stack it above @chunked to dedupe across chunks too.
 * @param argIndex - The index of the argument to dedupe
 */
export function deduped(argIndex = 0) {
  return function (_target: object, _propertyKey: string, descriptor: PropertyDescriptor): PropertyDescriptor {
    const originalMethod = descriptor.value

    descriptor.value = async function (...args: unknown[]) {
      const arr = args[argIndex] as (string | Uint8Array)[]
      const index = new Map<string, number>()
      const unique: (string | Uint8Array)[] = []
      const positions = arr.map((item) => {
        const key = typeof item === 'string' ? item : toHex(item)
        let i = index.get(key)
        if (i === undefined) {
          i = unique.push(item) - 1
          index.set(key, i)
        }
        return i
      })
      if (unique.length === arr.length) return originalMethod.apply(this, args)
      const applyArgs = [...args.slice(0, argIndex), unique, ...args.slice(argIndex + 1)]
      const results: unknown[] = await originalMethod.apply(this, applyArgs)
      return positions.map((i) => results[i])
    }

    return descriptor
  }
}
