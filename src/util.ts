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
