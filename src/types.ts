import { SupportedEncodings } from "uint8arrays/util/bases.js"
import { Capability, isCapability, isEncodedCapability } from "./capability/index.js"
import * as util from "./util.js"


// 💎


export type Ucan<Prf = string> = {
  header: UcanHeader
  payload: UcanPayload<Prf>
  signature: string
}



// CHUNKS


export interface UcanParts<Prf = string> {
  header: UcanHeader
  payload: UcanPayload<Prf>
}

export type UcanHeader = {
  alg: string
  typ: string
  ucv: string
}

export type UcanPayload<Prf = string> = {
  iss: string
  aud: string
  exp: number
  nbf?: number
  nnc?: string
  att: Array<Capability>
  fct?: Array<Fact>
  prf: Array<Prf>
}



// FRAGMENTS


export type Fact = Record<string, unknown>



// CRYPTOGRAPHY


/** Unlike tslib's CryptoKeyPair, this requires the `privateKey` and `publicKey` fields */
export interface AvailableCryptoKeyPair {
  privateKey: CryptoKey
  publicKey: CryptoKey
}

export interface Didable {
  publicKeyStr: (format?: Encodings) => string
  did: () => string
}

export interface ExportableKey {
  export: (format?: Encodings) => Promise<string>
}

export interface Keypair {
  publicKey: Uint8Array
  keyType: KeyType
  sign: (msg: Uint8Array) => Promise<Uint8Array>
}

export type KeyType =
  | "rsa"
  | "p256"
  | "p384"
  | "p521"
  | "ed25519"
  | "bls12-381"

// https://developer.mozilla.org/en-US/docs/Web/API/EcKeyGenParams
export type NamedCurve = "P-256" | "P-384" | "P-521"



// MISC


export type Encodings = SupportedEncodings



// TYPE CHECKS


export function isAvailableCryptoKeyPair(keypair: CryptoKeyPair): keypair is AvailableCryptoKeyPair {
  return keypair.publicKey != null && keypair.privateKey != null
}

export function isKeypair(obj: unknown): obj is Keypair {
  return util.isRecord(obj)
    && util.hasProp(obj, "publicKey") && obj.publicKey instanceof Uint8Array
    && util.hasProp(obj, "keyType") && typeof obj.keyType === "string"
    && util.hasProp(obj, "sign") && typeof obj.sign === "function"
}

export function isUcanHeader(obj: unknown): obj is UcanHeader {
  return util.isRecord(obj)
    && util.hasProp(obj, "alg") && typeof obj.alg === "string"
    && util.hasProp(obj, "typ") && typeof obj.typ === "string"
    && util.hasProp(obj, "ucv") && typeof obj.ucv === "string"
}

export function isUcanPayload(obj: unknown): obj is UcanPayload {
  return util.isRecord(obj)
    && util.hasProp(obj, "iss") && typeof obj.iss === "string"
    && util.hasProp(obj, "aud") && typeof obj.aud === "string"
    && util.hasProp(obj, "exp") && typeof obj.exp === "number"
    && (!util.hasProp(obj, "nbf") || typeof obj.nbf === "number")
    && (!util.hasProp(obj, "nnc") || typeof obj.nnc === "string")
    && util.hasProp(obj, "att") && Array.isArray(obj.att) && obj.att.every(a => isCapability(a) || isEncodedCapability(a))
    && (!util.hasProp(obj, "fct") || Array.isArray(obj.fct) && obj.fct.every(util.isRecord))
    && util.hasProp(obj, "prf") && Array.isArray(obj.prf) && obj.prf.every(str => typeof str === "string")
}
