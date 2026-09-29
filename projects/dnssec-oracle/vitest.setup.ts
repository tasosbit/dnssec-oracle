import { addEqualityTesters } from '@algorandfoundation/algorand-typescript-testing'
import { beforeAll, expect } from 'vitest'

beforeAll(() => {
  addEqualityTesters({ expect })
})
