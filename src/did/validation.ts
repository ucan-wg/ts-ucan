import * as ed25519 from "@stablelib/ed25519"
import * as uint8arrays from "uint8arrays"

import * as rsa from "../crypto/rsa.js"
import * as ecdsa from "../crypto/ecdsa.js"

import { didToPublicKeyBytes } from "./transformers.js"


/**
 * Verify the signature of some data (Uint8Array), given a DID.
 */
export async function verifySignature(data: Uint8Array, signature: Uint8Array, did: string): Promise<boolean> {
  try {
    const { type, publicKey } = didToPublicKeyBytes(did)

    switch (type) {

      case "ed25519":
        return ed25519.verify(publicKey, data, signature)

      case "rsa":
        return await rsa.verify(data, signature, publicKey)

      case "p256":
        return await ecdsa.verify(data, signature, publicKey, "P-256")

      case "p384":
        return await ecdsa.verify(data, signature, publicKey, "P-384")

      case "p521":
        return await ecdsa.verify(data, signature, publicKey, "P-521")

      default: return false
    }

  } catch (_) {
    return false

  }
}

/**
 * Verify the signature of some data (string encoded as utf8), given a DID.
 */
export async function verifySignatureUtf8(data: string, signature: string, did: string): Promise<boolean> {
  const dataBytes = uint8arrays.fromString(data, "utf8")
  const sigBytes = uint8arrays.fromString(signature, "base64url")
  return await verifySignature(dataBytes, sigBytes, did)
}
