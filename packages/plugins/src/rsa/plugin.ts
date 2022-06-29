import { DidKeyPlugin } from '@ucans/core'
import * as crypto from "./crypto.js"
import { RSA_DID_PREFIX, RSA_DID_PREFIX_OLD } from "../prefixes.js"

export const rsaPlugin: DidKeyPlugin = {
  prefix: RSA_DID_PREFIX,
  jwtAlg: 'RS256',
  didToPublicKey: crypto.didToPublicKey,
  publicKeyToDid: crypto.publicKeyToDid,
  checkSignature: crypto.verify,
}

export const rsaOldPlugin: DidKeyPlugin = {
  prefix: RSA_DID_PREFIX_OLD,
  jwtAlg: 'RS256',
  didToPublicKey: crypto.oldDidToPublicKey,
  publicKeyToDid: crypto.publicKeyToOldDid,
  checkSignature: crypto.verify,
}

