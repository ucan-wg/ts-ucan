const CHARS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


export const generateNonce = (len = 6): string => {
  let nonce = ""
  for (let i = 0; i < len; i++) {
    nonce += CHARS[ Math.floor(Math.random() * CHARS.length) ]
  }
  return nonce
}

export function hasProp<K extends PropertyKey>(data: unknown, prop: K): data is Record<K, unknown> {
  return typeof data === "object" && data != null && prop in data
}

export function isRecord(data: unknown): data is Record<PropertyKey, unknown> {
  return typeof data === "object" && data != null
}

export function isIterable<T>(obj: unknown): obj is Iterable<T> {
  return typeof obj === "object" && obj != null && Symbol.iterator in obj
}

export function isAsyncIterable<T>(obj: unknown): obj is AsyncIterable<T> {
  return typeof obj === "object" && obj != null && Symbol.asyncIterator in obj
}


export function all<T>(it: Iterable<T>): T[]
export function all<T>(it: AsyncIterable<T>): Promise<T[]>
export function all<T>(it: Iterable<T> | AsyncIterable<T>): T[] | Promise<T[]> {
  if (isIterable(it)) {
    const arr = []
    for (const elem of it) {
      arr.push(elem)
    }
    return arr
  } else if (isAsyncIterable(it)) {
    return (async () => {
      const arr = []
      for await (const elem of it) {
        arr.push(elem)
      }
      return arr
    })()
  } else {
    throw new TypeError(`Expected either Iterable or AsyncIterable, but got ${it}`)
  }
}

export function first<T>(it: Iterable<T>): T | undefined
export function first<T>(it: AsyncIterable<T>): Promise<T | undefined>
export function first<T>(it: Iterable<T> | AsyncIterable<T>): T | undefined | Promise<T | undefined> {
  if (isIterable(it)) {
    for (const elem of it) {
      return elem
    }
    return undefined
  } else if (isAsyncIterable(it)) {
    return (async () => {
      for await (const elem of it) {
        return elem
      }
      return undefined
    })()
  } else {
    throw new TypeError(`Expected either Iterable or AsyncIterable, but got ${it}`)
  }
}

