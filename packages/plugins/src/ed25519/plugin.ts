import { DidKeyPlugin } from '@ucans/core'
import * as ed25519 from "@stablelib/ed25519"
import * as crypto from "./crypto.js"

import { EDWARDS_DID_PREFIX } from "../prefixes.js"

export const ed25519Plugin: DidKeyPlugin = {
  prefix: EDWARDS_DID_PREFIX,
  jwtAlg: 'EdDSA',
  didToPublicKey: crypto.didToPublickey,
  publicKeyToDid: crypto.publicKeyToDid,
  verifySignature: async (publicKey: Uint8Array, data: Uint8Array, sig: Uint8Array) => {
    return ed25519.verify(publicKey, data, sig)
  }
}