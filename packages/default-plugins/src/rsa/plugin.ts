import { DidKeyPlugin } from "@ucans/core"
import * as crypto from "./crypto.js"
import { RSA_DID_PREFIX, RSA_DID_PREFIX_OLD } from "../prefixes.js"

export const rsaPlugin: DidKeyPlugin = {
  prefix: RSA_DID_PREFIX,
  jwtAlg: "RS256",
  verifySignature: async (did: string, data: Uint8Array, sig: Uint8Array) => {
    const publicKey = crypto.didToPublicKey(did)
    return crypto.verify(publicKey, data, sig)
  }
}

export const rsaOldPlugin: DidKeyPlugin = {
  prefix: RSA_DID_PREFIX_OLD,
  jwtAlg: "RS256",
  verifySignature: async (did: string, data: Uint8Array, sig: Uint8Array) => {
    const publicKey = crypto.oldDidToPublicKey(did)
    return crypto.verify(publicKey, data, sig)
  }
}

