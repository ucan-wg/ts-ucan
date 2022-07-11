import { DidKeyPlugin } from "@ucans/core"
import * as crypto from "./crypto.js"
import { P256_DID_PREFIX } from "../prefixes.js"

export const p256Plugin: DidKeyPlugin = {
  prefix: P256_DID_PREFIX,
  jwtAlg: "ES256",
  verifySignature: async (did: string, data: Uint8Array, sig: Uint8Array) => {
    const publicKey = crypto.didToPublicKey(did)
    return crypto.verify(publicKey, data, sig)
  }
}