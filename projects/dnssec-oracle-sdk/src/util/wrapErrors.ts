import { ErrorTransformer } from '@algorandfoundation/algokit-utils/types/composer'
import { ErrorMessages } from '../generated/errors.js'

/**
 * Map of error codes to human-readable error messages
 */
export const errorMap = ErrorMessages

export const errorTransformer: ErrorTransformer = async (ogError) => {
  const [errCode] = /ERR:[^" ]+/.exec(ogError.message) ?? []
  if (errCode) {
    const humanMessage = errorMap[errCode] ?? 'Unknown error'
    const message = `${errCode.replace('ERR:', 'Error ')}: ${humanMessage}`

    ogError.stack = `${message}\n    ${ogError.message}\n${ogError.stack}`
    ogError.message = message
    Object.assign(ogError, { code: errCode, description: humanMessage })
    return ogError
  }
  return ogError
}

export async function wrapErrorsInternal<T>(promiseOrGenerator: Promise<T> | (() => Promise<T>)): Promise<T> {
  try {
    if (typeof promiseOrGenerator === 'function') {
      return await promiseOrGenerator()
    } else {
      return await promiseOrGenerator
    }
  } catch (e) {
    throw await errorTransformer(e as Error)
  }
}

/**
 * Decorator that wraps the return value of an async method with error transformation.
 */
export function wrapErrors() {
  return function (_target: object, _propertyKey: string, descriptor: PropertyDescriptor): PropertyDescriptor {
    const originalMethod = descriptor.value

    descriptor.value = async function (...args: unknown[]) {
      return wrapErrorsInternal(() => originalMethod.apply(this, args))
    }

    return descriptor
  }
}
