import * as uint8arrays from 'uint8arrays'

export type DidKeyPlugin = {
  prefix: Uint8Array
  jwtAlg: string
  checkSignature: (did: string, data: Uint8Array, sig: Uint8Array) => Promise<boolean>
}

export type DidMethodPlugin = {
  method: string
  checkJwtAlg: (did: string, jwtAlg: string) => boolean
  checkSignature: (did: string, data: Uint8Array, sig: Uint8Array) => Promise<boolean>
}

export type Plugins = {
  keys: DidKeyPlugin[]
  methods: DidMethodPlugin[]
}

let plugins: Plugins | null = null

export const checkIssuer = (did: string, jwtAlg: string): boolean => {
  if(plugins === null) {
    throw new Error("No plugins loaded")
  }
  const didMethod = parseDidMethod(did)
  if(didMethod === 'key') {
    const bytes = parsePrefixedBytes(did)
    for (const keyPlugin of plugins.keys) {
      if(hasPrefix(bytes, keyPlugin.prefix)) {
        return jwtAlg === keyPlugin.jwtAlg
      }
    }
  } else {
    for (const didPlugin of plugins.methods) {
      if(didMethod === didPlugin.method) {
        return didPlugin.checkJwtAlg(did, jwtAlg)
      }
    }
  }
  throw new Error(`DID method not supported by plugins: ${did}`)
}

export const checkSignature = async (did: string, data: Uint8Array, sig: Uint8Array): Promise<boolean> => {
  if(plugins === null) {
    throw new Error("No plugins loaded")
  }
  const didMethod = parseDidMethod(did)
  if(didMethod === 'key') {
    const bytes = parsePrefixedBytes(did)
    for (const keyPlugin of plugins.keys) {
      if(hasPrefix(bytes, keyPlugin.prefix)) {
        return keyPlugin.checkSignature(did, data, sig)
      }
    }
  } else {
    for (const didPlugin of plugins.methods) {
      if(didMethod === didPlugin.method) {
        return didPlugin.checkSignature(did, data, sig)
      }
    }
  }
  throw new Error(`DID method not supported by plugins: ${did}`)
}

export const loadPlugins = (toLoad: Plugins): void => {
  plugins = toLoad
}

export const hasPrefix = (
  prefixedKey: Uint8Array,
  prefix: Uint8Array
): boolean => {
  return uint8arrays.equals(prefix, prefixedKey.subarray(0, prefix.byteLength))
}

// @TODO would be better to follow the actual varint spec here:
// https://github.com/multiformats/unsigned-varint 
const parsePrefixedBytes = (did: string): Uint8Array => {
  if(!did.startsWith("did:key:z")) {
    throw new Error(`Not a valid base58 formatted did:key: ${did}`)
  } 
  return uint8arrays.fromString(
    did.replace("did:key:z", ""),
    "base58btc"
  )
}

const parseDidMethod = (did: string) => {
  const parts = did.split(':')
  if(parts[0] !== 'did') {
    throw new Error(`Not a DID: ${did}`)
  }
  if(parts[1].length < 1) {
    throw new Error(`No DID method included: ${did}`)
  }
  return parts[1]
}