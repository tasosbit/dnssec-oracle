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
