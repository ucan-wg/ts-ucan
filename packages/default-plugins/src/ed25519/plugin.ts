import { DidKeyPlugin } from "@ucans/core"
import * as ed25519 from "@stablelib/ed25519"
import * as crypto from "./crypto.js"

import { EDWARDS_DID_PREFIX } from "../prefixes.js"

export const ed25519Plugin: DidKeyPlugin = {
  prefix: EDWARDS_DID_PREFIX,
  jwtAlg: "EdDSA",
  verifySignature: async (did: string, data: Uint8Array, sig: Uint8Array) => {
    const publicKey = crypto.didToPublicKey(did)
    return ed25519.verify(publicKey, data, sig)
  }
}