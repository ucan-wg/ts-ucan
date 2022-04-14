import * as uint8arrays from "uint8arrays"
import { KeyType } from "../types.js"

// Each prefix is varint-encoded. So e.g. 0x1205 gets varint-encoded to 0x8524
// The varint encoding is described here: https://github.com/multiformats/unsigned-varint
// These varints are encoded big-endian in 7-bit pieces.
// So 0x1205 is split up into 0x12 and 0x05
// Because there's another byte to be read, the MSB of 0x05 is set: 0x85
// The next 7 bits encode as 0x24 (instead of 0x12) => 0x8524

/** https://github.com/multiformats/multicodec/blob/e9ecf587558964715054a0afcc01f7ace220952c/table.csv#L94 */
export const EDWARDS_DID_PREFIX = new Uint8Array([ 0xed, 0x01 ])
/** https://github.com/multiformats/multicodec/blob/e9ecf587558964715054a0afcc01f7ace220952c/table.csv#L91 */
export const BLS_DID_PREFIX = new Uint8Array([ 0xea, 0x01 ])
/** https://github.com/multiformats/multicodec/blob/e9ecf587558964715054a0afcc01f7ace220952c/table.csv#L141 */
export const P256_DID_PREFIX = new Uint8Array([ 0x80, 0x24 ])
/** https://github.com/multiformats/multicodec/blob/e9ecf587558964715054a0afcc01f7ace220952c/table.csv#L142 */
export const P384_DID_PREFIX = new Uint8Array([ 0x81, 0x24 ])
/** https://github.com/multiformats/multicodec/blob/e9ecf587558964715054a0afcc01f7ace220952c/table.csv#L143 */
export const P521_DID_PREFIX = new Uint8Array([ 0x82, 0x24 ])
/** https://github.com/multiformats/multicodec/blob/e9ecf587558964715054a0afcc01f7ace220952c/table.csv#L146 */
export const RSA_DID_PREFIX = new Uint8Array([ 0x85, 0x24 ])
/** Old RSA DID prefix, used pre-standardisation */
export const RSA_DID_PREFIX_OLD = new Uint8Array([ 0x00, 0xf5, 0x02 ])

export const BASE58_DID_PREFIX = "did:key:z" // z is the multibase prefix for base58btc byte encoding

/**
 * Magic bytes.
 */
export function magicBytes(keyType: KeyType): Uint8Array | null {
  switch (keyType) {
    case "ed25519":
      return EDWARDS_DID_PREFIX
    case "p256":
      return P256_DID_PREFIX
    case "p384":
      return P384_DID_PREFIX
    case "p521":
      return P521_DID_PREFIX
    case "rsa":
      return RSA_DID_PREFIX
    case "bls12-381":
      return BLS_DID_PREFIX
    default:
      return null
  }
}

/**
 * Parse magic bytes on prefixed key-bytes
 * to determine cryptosystem & the unprefixed key-bytes.
 */
export const parseMagicBytes = (
  prefixedKey: Uint8Array
): {
  keyBytes: Uint8Array
  type: KeyType
} => {
  // RSA
  if (hasPrefix(prefixedKey, RSA_DID_PREFIX)) {
    return {
      keyBytes: prefixedKey.slice(RSA_DID_PREFIX.byteLength),
      type: "rsa",
    }

    // RSA OLD
  } else if (hasPrefix(prefixedKey, RSA_DID_PREFIX_OLD)) {
    return {
      keyBytes: prefixedKey.slice(RSA_DID_PREFIX_OLD.byteLength),
      type: "rsa",
    }

    // EC P-256
  } else if (hasPrefix(prefixedKey, P256_DID_PREFIX)) {
    return {
      keyBytes: prefixedKey.slice(P256_DID_PREFIX.byteLength),
      type: "p256",
    }

    // EC P-384
  } else if (hasPrefix(prefixedKey, P384_DID_PREFIX)) {
    return {
      keyBytes: prefixedKey.slice(P384_DID_PREFIX.byteLength),
      type: "p384",
    }

    // EC P-521
  } else if (hasPrefix(prefixedKey, P521_DID_PREFIX)) {
    return {
      keyBytes: prefixedKey.slice(P521_DID_PREFIX.byteLength),
      type: "p521",
    }

    // EDWARDS
  } else if (hasPrefix(prefixedKey, EDWARDS_DID_PREFIX)) {
    return {
      keyBytes: prefixedKey.slice(EDWARDS_DID_PREFIX.byteLength),
      type: "ed25519",
    }

    // BLS
  } else if (hasPrefix(prefixedKey, BLS_DID_PREFIX)) {
    return {
      keyBytes: prefixedKey.slice(BLS_DID_PREFIX.byteLength),
      type: "bls12-381",
    }
  }

  throw new Error("Unsupported key algorithm. Try using RSA.")
}

/**
 * Determines if a Uint8Array has a given indeterminate length-prefix.
 */
export const hasPrefix = (
  prefixedKey: Uint8Array,
  prefix: Uint8Array
): boolean => {
  return uint8arrays.equals(prefix, prefixedKey.subarray(0, prefix.byteLength))
}
