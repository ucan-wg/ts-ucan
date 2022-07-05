import * as uint8arrays from "uint8arrays"

export type DidKeyPlugin = {
  prefix: Uint8Array
  jwtAlg: string
  verifySignature: (did: string, data: Uint8Array, sig: Uint8Array) => Promise<boolean>
}

export type DidMethodPlugin = {
  checkJwtAlg: (did: string, jwtAlg: string) => boolean
  verifySignature: (did: string, data: Uint8Array, sig: Uint8Array) => Promise<boolean>
}

export class Plugins {

  constructor(
    public keys: DidKeyPlugin[],
    public methods: Record<string, DidMethodPlugin>
  ) {}

  verifyIssuerAlg(did: string, jwtAlg: string): boolean {
    const didMethod = parseDidMethod(did)
    if(didMethod === "key") {
      const bytes = parsePrefixedBytes(did)
      for (const keyPlugin of this.keys) {
        if(hasPrefix(bytes, keyPlugin.prefix)) {
          return jwtAlg === keyPlugin.jwtAlg
        }
      }
    } else {
      const maybePlugin = this.methods[didMethod]
      if(maybePlugin) {
        return maybePlugin.checkJwtAlg(did, jwtAlg)
      }
    }
    throw new Error(`DID method not supported by plugins: ${did}`)
  }

  async verifySignature(did: string, data: Uint8Array, sig: Uint8Array): Promise<boolean> {
    const didMethod = parseDidMethod(did)
    if(didMethod === "key") {
      const bytes = parsePrefixedBytes(did)
      for (const keyPlugin of this.keys) {
        if(hasPrefix(bytes, keyPlugin.prefix)) {
          return keyPlugin.verifySignature(did, data, sig)
        }
      }
    } else {
      const maybePlugin = this.methods[didMethod]
      if (maybePlugin) {
        return maybePlugin.verifySignature(did, data, sig)
      }
    }
    throw new Error(`DID method not supported by plugins: ${did}`)
  }
}

export default Plugins

const hasPrefix = (
  prefixedKey: Uint8Array,
  prefix: Uint8Array
): boolean => {
  return uint8arrays.equals(prefix, prefixedKey.subarray(0, prefix.byteLength))
}

const BASE58_DID_PREFIX = "did:key:z"

// @TODO would be better to follow the actual varint spec here (instead of guess & check):
// https://github.com/multiformats/unsigned-varint 
const parsePrefixedBytes = (did: string): Uint8Array => {
  if(!did.startsWith(BASE58_DID_PREFIX)) {
    throw new Error(`Not a valid base58 formatted did:key: ${did}`)
  } 
  return uint8arrays.fromString(
    did.slice(BASE58_DID_PREFIX.length),
    "base58btc"
  )
}

const parseDidMethod = (did: string) => {
  const parts = did.split(":")
  if(parts[0] !== "did") {
    throw new Error(`Not a DID: ${did}`)
  }
  if(parts[1].length < 1) {
    throw new Error(`No DID method included: ${did}`)
  }
  return parts[1]
}