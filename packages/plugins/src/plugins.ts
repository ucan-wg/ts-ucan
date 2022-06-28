import { DidKeyPlugin, Plugins } from '@ucans/core'
import { EDWARDS_DID_PREFIX, keyBytesFromDid, P256_DID_PREFIX, RSA_DID_PREFIX, RSA_DID_PREFIX_OLD } from './did'
import * as ed25519 from "@stablelib/ed25519"
import * as rsaCrypto from "./crypto/rsa.js"
import * as ecdsaCrypto from "./crypto/rsa.js"
import { decompressNistP256Pubkey } from "./did/pubkey-compress"

export const edwards: DidKeyPlugin = {
  prefix: EDWARDS_DID_PREFIX,
  jwtAlg: 'EdDSA',
  checkSignature: async (did, data, sig): Promise<boolean> => {
    const keyBytes = keyBytesFromDid(did, EDWARDS_DID_PREFIX)
    return ed25519.verify(keyBytes, data, sig)
  }
}

export const rsa: DidKeyPlugin = {
  prefix: RSA_DID_PREFIX,
  jwtAlg: 'RS256',
  checkSignature: async (did, data, sig): Promise<boolean> => {
    const keyBytes = keyBytesFromDid(did, RSA_DID_PREFIX)
    const spkiBytes = rsaCrypto.convertRSAPublicKeyToSubjectPublicKeyInfo(keyBytes)
    const isValid = await rsaCrypto.verify(data, sig, spkiBytes)
    return isValid
  }
}

export const rsaOld: DidKeyPlugin = {
  prefix: RSA_DID_PREFIX_OLD,
  jwtAlg: 'RS256',
  checkSignature: async (did, data, sig): Promise<boolean> => {
    const keyBytes = keyBytesFromDid(did, RSA_DID_PREFIX_OLD)
    const isValid = await rsaCrypto.verify(data, sig, keyBytes)
    return isValid
  }
}

export const p256: DidKeyPlugin = {
  prefix: P256_DID_PREFIX,
  jwtAlg: 'ES256',
  checkSignature: async (did, data, sig): Promise<boolean> => {
    const keyBytes = keyBytesFromDid(did, P256_DID_PREFIX)
    const decompressedKey = decompressNistP256Pubkey(keyBytes)
    const isValid = await ecdsaCrypto.verify(data, sig, decompressedKey)
    return isValid
  }
}

export const defaults: Plugins = {
  keys: [edwards, p256, rsa, rsaOld],
  methods: [],
}