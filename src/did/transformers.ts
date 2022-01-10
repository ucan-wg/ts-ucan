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

  // if (type === "rsa") {
  //   if (bytesStartWith(publicKeyBytes, SPKI_HEADER)) {
  //     publicKeyBytes = publicKeyBytes.slice(SPKI_HEADER.length)
  //   }
  // }

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

  // if (type === "rsa" && !bytesStartWith(keyBytes, SPKI_HEADER)) {
  //   // Generally never expect the SPKI_HEADER to already be in the DID.
  //   // As per the multicodec specification, that shouldn't be the case -
  //   // it should always only be an ASN.1 DER RSAPublicKey encoded bytestring.
  //   // But in previous versions we've used an unofficial encoding that
  //   // uses SubjectPublicKeyInfo directly.
  //   keyBytes = uint8arrays.concat([SPKI_HEADER, keyBytes])
  // }
        
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
