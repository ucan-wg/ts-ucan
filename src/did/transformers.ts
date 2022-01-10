import * as uint8arrays from "uint8arrays"

import * as rsa from "../crypto/rsa"
import { BASE58_DID_PREFIX, RSA_DID_PREFIX_OLD, magicBytes, parseMagicBytes, hasPrefix } from "./prefix"
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

  if (type === "rsa") {
    // See also the comment in didToPublicKeyBytes
    // In this library, we're assuming a single byte encoding for all types of keys.
    // For RSA that is "SubjectPublicKeyInfo", because that's what the WebCrypto API understands.
    // But DIDs assume that all public keys are encoded as "RSAPublicKey".
    publicKeyBytes = rsa.convertSubjectPublicKeyInfoToRSAPublicKey(publicKeyBytes)
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
  encoding: Encodings = "base64pad"
): string {
  const pubKeyBytes = uint8arrays.fromString(publicKey, encoding)
  return publicKeyBytesToDid(pubKeyBytes, type)
}


/**
 * Convert a DID (did:key) to the public key into bytes in SubjectPublicKeyInfo (spki) format.
 * 
 * For consumption e.g. in the WebCrypto API.
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
  let { keyBytes, type } = parseMagicBytes(magicBytes)

  if (type === "rsa" && !hasPrefix(magicBytes, RSA_DID_PREFIX_OLD)) {
    // DID RSA keys are ASN.1 DER encoded "RSAPublicKeys" (PKCS #1).
    // But the WebCrypto API mostly works with "SubjectPublicKeyInfo" (SPKI),
    // which wraps RSAPublicKey with some metadata.
    // In an unofficial RSA multiformat we were using, we used SPKI,
    // so we have to be careful not to transform *every* RSA DID to SPKI, but
    // only newer DIDs.
    keyBytes = rsa.convertRSAPublicKeyToSubjectPublicKeyInfo(keyBytes)
  }

  return {
    publicKey: keyBytes,
    type
  }
}

/**
 * Convert a DID (did:key) to a base64 public key.
 */
export function didToPublicKey(did: string, encoding: Encodings = "base64pad"): {
  publicKey: string
  type: KeyType
} {
  const { publicKey, type } = didToPublicKeyBytes(did)
  return {
    publicKey: uint8arrays.toString(publicKey, encoding),
    type
  }
}

function bytesStartWith(bytes: Uint8Array, prefix: Uint8Array): boolean {
  return uint8arrays.equals(prefix, bytes.subarray(0, prefix.length))
}
