import bigInt from "big-integer"
import * as uint8arrays from "uint8arrays"
import { webcrypto } from "one-webcrypto"
import { AvailableCryptoKeyPair, PrivateKeyJwk } from "../types.js"
import { didFromKeyBytes, keyBytesFromDid } from "../util.js"
import { P256_DID_PREFIX } from "../prefixes.js"

export const ALG = "ECDSA"
export const DEFAULT_CURVE = "P-256"
export const DEFAULT_HASH_ALG = "SHA-256"

export const generateKeypair = async (): Promise<AvailableCryptoKeyPair> => {
  return await webcrypto.subtle.generateKey(
    {
      name: ALG,
      namedCurve: DEFAULT_CURVE,
    },
    false,
    [ "sign", "verify" ]
  )
}

export const importKeypairJwk = async (
  privKeyJwk: PrivateKeyJwk,
  exportable = false
): Promise<AvailableCryptoKeyPair> => {
  const privateKey = await webcrypto.subtle.importKey(
    "jwk",
    privKeyJwk,
    {
      name: ALG,
      namedCurve: DEFAULT_CURVE,
    },
    exportable,
    ["sign" ]
  )
  const { kty, crv, x, y} = privKeyJwk
  const pubKeyJwk = { kty, crv, x, y}
  const publicKey = await webcrypto.subtle.importKey(
    "jwk",
    pubKeyJwk,
    {
      name: ALG,
      namedCurve: DEFAULT_CURVE,
    },
    true,
    [ "verify" ]
  )
  return { privateKey, publicKey }
}

export const exportKey = async (key: CryptoKey): Promise<Uint8Array> => {
  const buf = await webcrypto.subtle.exportKey("raw", key)
  return new Uint8Array(buf)
}

export const importKey = async (
  key: Uint8Array
): Promise<CryptoKey> => {
  return await webcrypto.subtle.importKey(
    "raw",
    key,
    { name: ALG, namedCurve: DEFAULT_CURVE },
    true,
    [ "verify" ]
  )
}

export const sign = async (
  msg: Uint8Array,
  privateKey: CryptoKey
): Promise<Uint8Array> => {
  const buf = await webcrypto.subtle.sign(
    { name: ALG, hash: { name: DEFAULT_HASH_ALG } },
    privateKey,
    msg
  )
  return new Uint8Array(buf)
}

export const verify = async (
  pubKey: Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array
): Promise<boolean> => {
  return await webcrypto.subtle.verify(
    { name: ALG, hash: { name: DEFAULT_HASH_ALG } },
    await importKey(pubKey),
    sig,
    msg
  )
}


export const didToPublicKey = (did: string): Uint8Array => {
  // The multiformats space (used by did:key) specifies that NIST P-256
  // keys should be encoded as the 33-byte compressed public key,
  // instead of the 65-byte raw public key
  const keyBytes = keyBytesFromDid(did, P256_DID_PREFIX)
  return decompressP256Pubkey(keyBytes)
}

export const publicKeyToDid = (publicKey: Uint8Array): string => {
  const compressed = compressP256Pubkey(publicKey)
  return didFromKeyBytes(compressed, P256_DID_PREFIX)
}



// PUBLIC KEY COMPRESSION
// -------------------------

// Compression & Decompression algos from:
// https://stackoverflow.com/questions/48521840/biginteger-to-a-uint8array-of-bytes

// Public key compression for NIST P-256
export const compressP256Pubkey = (pubkeyBytes: Uint8Array): Uint8Array => {
  if (pubkeyBytes.length !== 65) {
    throw new Error("Expected 65 byte pubkey")
  } else if (pubkeyBytes[0] !== 0x04) {
    throw new Error("Expected first byte to be 0x04")
  }
  // first byte is a prefix
  const x = pubkeyBytes.slice(1, 33)
  const y = pubkeyBytes.slice(33, 65)
  const out = new Uint8Array(x.length + 1)

  out[0] = 2 + (y[y.length - 1] & 1)
  out.set(x, 1)

  return out
}

// Public key decompression for NIST P-256
export const decompressP256Pubkey = (compressed: Uint8Array): Uint8Array => {
  if (compressed.length !== 33) {
    throw new Error("Expected 33 byte compress pubkey")
  } else if (compressed[0] !== 0x02 && compressed[0] !== 0x03) {
    throw new Error("Expected first byte to be 0x02 or 0x03")
  }
  // Consts for P256 curve
  const two = bigInt(2)
  // 115792089210356248762697446949407573530086143415290314195533631308867097853951
  const prime = two
    .pow(256)
    .subtract(two.pow(224))
    .add(two.pow(192))
    .add(two.pow(96))
    .subtract(1)
  const b = bigInt(
    "41058363725152142129326129780047268409114441015993725554835256314039467401291",
  )

  // Pre-computed value, or literal
  const pIdent = prime.add(1).divide(4) // 28948022302589062190674361737351893382521535853822578548883407827216774463488

  // This value must be 2 or 3. 4 indicates an uncompressed key, and anything else is invalid.
  const signY = bigInt(compressed[0] - 2)
  const x = compressed.slice(1)
  const xBig = bigInt(uint8arrays.toString(x, "base10"))

  // y^2 = x^3 - 3x + b
  const maybeY = xBig
    .pow(3)
    .subtract(xBig.multiply(3))
    .add(b)
    .modPow(pIdent, prime)

  let yBig
  // If the parity matches, we found our root, otherwise it's the other root
  if (maybeY.mod(2).equals(signY)) {
    yBig = maybeY
  } else {
    // y = prime - y
    yBig = prime.subtract(maybeY)
  }
  const y = uint8arrays.fromString(yBig.toString(10), "base10")

  // left-pad for smaller than 32 byte y
  const offset = 32 - y.length
  const yPadded = new Uint8Array(32)
  yPadded.set(y, offset)

  // concat coords & prepend P-256 prefix
  const publicKey = uint8arrays.concat([[0x04], x, yPadded])
  return publicKey
}
