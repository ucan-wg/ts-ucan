import { DidKeyPlugin } from '@ucans/core'
import * as crypto from "./crypto.js"
import { P256_DID_PREFIX } from "../prefixes.js"

export const p256Plugin: DidKeyPlugin = {
  prefix: P256_DID_PREFIX,
  jwtAlg: 'ES256',
  didToPublicKey: crypto.didToPublicKey,
  publicKeyToDid: crypto.publicKeyToDid,
  checkSignature: crypto.verify,
}