import * as uint8arrays from "uint8arrays"

import { BASE58_DID_PREFIX, magicBytes, parseMagicBytes } from "./prefix"
import { KeyType, Encodings } from "../types"

/**
 * Convert a public key in bytes to a DID (did:key).
 */
export function publicKeyBytesToDid(
  publicKeyBytes: Uint8Array,
  type: KeyType,
): string {
  // Prefix public-write key
  const prefix = magicBytes(type)
  if (prefix === null) {
    throw new Error(`Key type '${type}' not supported`)
  }

  const prefixedBytes = uint8arrays.concat([prefix, publicKeyBytes])

  // Encode prefixed
  return BASE58_DID_PREFIX + uint8arrays.toString(prefixedBytes, "base58btc")
}

/**
 * Convert a base64 public key to a DID (did:key).
 */
export function publicKeyToDid(
  publicKey: string,
  type: KeyType,
  encoding: Encodings = 'base64'
): string {
  const pubKeyBytes = uint8arrays.fromString(publicKey, encoding)
  return publicKeyBytesToDid(pubKeyBytes, type)
}


/**
 * Convert a DID (did:key) to the public key in bytes
 */
export function didToPublicKeyBytes(did: string): {
  publicKey: Uint8Array
  type: KeyType
} {
  if (!did.startsWith(BASE58_DID_PREFIX)) {
    throw new Error("Please use a base58-encoded DID formatted `did:key:z...`")
  }

  const didWithoutPrefix = did.slice(BASE58_DID_PREFIX.length)
  const magicBytes = uint8arrays.fromString(didWithoutPrefix, "base58btc")
  const { keyBytes, type } = parseMagicBytes(magicBytes)

  return {
    publicKey: keyBytes,
    type
  }
}

/**
 * Convert a DID (did:key) to a base64 public key.
 */
export function didToPublicKey(did: string, encoding: Encodings = 'base64'): {
  publicKey: string
  type: KeyType
} {
  const { publicKey, type } = didToPublicKeyBytes(did)
  return {
    publicKey: uint8arrays.toString(publicKey, encoding),
    type
  }
}
