import * as uint8arrays from "uint8arrays"
import nacl from "tweetnacl"

import * as rsa from "../crypto/rsa"
import { didToPublicKeyBytes } from "./transformers"


/**
 * Verify the signature of some data (Uint8Array), given a DID.
 */
export async function verifySignature(data: Uint8Array, signature: Uint8Array, did: string): Promise<boolean> {
  try {
    const { type, publicKey } = didToPublicKeyBytes(did)

    switch (type) {

      case "ed25519":
        return nacl.sign.detached.verify(data, signature, publicKey)

      case "rsa":
        return await rsa.verify(data, signature, publicKey)

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
