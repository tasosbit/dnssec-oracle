export function chunk<T>(array: T[], size: number): T[][] {
  if (size <= 0) throw new RangeError('chunk size must be a positive integer')
  const chunkedArr: T[][] = []
  let index = 0
  while (index < array.length) {
    chunkedArr.push(array.slice(index, size + index))
    index += size
  }
  return chunkedArr
}
