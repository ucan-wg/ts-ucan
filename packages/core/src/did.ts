import * as uint8arrays from "uint8arrays"

import * as plugins from "./plugins.js"
// import * as compression from "./pubkey-compress.js"
// import * as rsa from "../crypto/rsa.js"
// import { BASE58_DID_PREFIX, RSA_DID_PREFIX_OLD, magicBytes, parseMagicBytes, hasPrefix } from "./prefix.js"
import { Encodings } from "./types.js"


// DID → PUBLIC KEY


/**
 * Convert a DID (did:key) to a base64 public key.
 */
export function didToPublicKey(did: string, encoding: Encodings = "base64pad"): {
  publicKey: string
  jwtAlg: string
} {
  const { publicKey, jwtAlg } = didToPublicKeyBytes(did)
  return {
    publicKey: uint8arrays.toString(publicKey, encoding),
    jwtAlg
  }
}

/**
 * Convert a DID (did:key) to the public key into bytes in SubjectPublicKeyInfo (spki) format.
 *
 * For consumption e.g. in the WebCrypto API.
 */
export function didToPublicKeyBytes(did: string): {
  publicKey: Uint8Array
  jwtAlg: string
} {
  return plugins.didToPublicKeyBytes(did)
}



// PUBLIC KEY → DID


/**
 * Convert a base64 public key to a DID (did:key).
 */
export function publicKeyToDid(
  publicKey: string,
  jwtAlg: string,
  encoding: Encodings = "base64pad"
): string {
  const pubKeyBytes = uint8arrays.fromString(publicKey, encoding)
  return publicKeyBytesToDid(pubKeyBytes, jwtAlg)
}

/**
 * Convert a public key in bytes to a DID (did:key).
 */
export function publicKeyBytesToDid(
  publicKeyBytes: Uint8Array,
  jwtAlg: string,
): string {
  return plugins.publicKeyBytesToDid(publicKeyBytes, jwtAlg)
}