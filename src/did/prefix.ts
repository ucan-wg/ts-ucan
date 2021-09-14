import * as uint8arrays from 'uint8arrays'
import { KeyType } from "../types"


export const EDWARDS_DID_PREFIX = new Uint8Array([ 0xed, 0x01 ])
export const BLS_DID_PREFIX = new Uint8Array([ 0xea, 0x01 ])
export const RSA_DID_PREFIX = new Uint8Array([ 0x00, 0xf5, 0x02 ])
export const BASE58_DID_PREFIX = "did:key:z"

/**
 * Magic bytes.
 */
export function magicBytes(keyType: KeyType): Uint8Array | null {
  switch (keyType) {
    case KeyType.Edwards: return EDWARDS_DID_PREFIX
    case KeyType.RSA: return RSA_DID_PREFIX
    default: return null
  }
}

/**
 * Parse magic bytes on prefixed key-bytes
 * to determine cryptosystem & the unprefixed key-bytes.
 */
export const parseMagicBytes = (prefixedKey: Uint8Array): {
  keyBytes: Uint8Array
  type: KeyType
} => {
  // RSA
  if (hasPrefix(prefixedKey, RSA_DID_PREFIX)) {
    return {
      keyBytes: prefixedKey.slice(RSA_DID_PREFIX.byteLength),
      type: KeyType.RSA
    }

  // EDWARDS
  } else if (hasPrefix(prefixedKey, EDWARDS_DID_PREFIX)) {
    return {
      keyBytes: prefixedKey.slice(EDWARDS_DID_PREFIX.byteLength),
      type: KeyType.Edwards
    }
  }

  throw new Error("Unsupported key algorithm. Try using RSA.")
}

/**
 * Determines if a Uint8Array has a given indeterminate length-prefix.
 */
export const hasPrefix = (prefixedKey: Uint8Array, prefix: Uint8Array): boolean => {
  return uint8arrays.equals(prefix, prefixedKey.slice(0, prefix.byteLength))
}

export const toKeyType = (str: string): KeyType => {
  switch(str) {
    case "rsa": return KeyType.RSA
    case "ed25519": return KeyType.Edwards
  }
  throw new Error(`Key Type ${str} not supported`)
}
