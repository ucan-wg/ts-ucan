import { SupportedEncodings } from "uint8arrays/util/bases"
import * as util from "./util"

export type Encodings = SupportedEncodings

export interface Keypair {
  publicKey: Uint8Array
  keyType: KeyType
  sign: (msg: Uint8Array) => Promise<Uint8Array>
}

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

export type KeyType = "rsa" | "ed25519" | "bls12-381"

export type Fact = Record<string, unknown>

export type Capability = {
  [rsc: string]: unknown
  cap: string
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

export type Ucan<Prf = string> = {
  header: UcanHeader
  payload: UcanPayload<Prf>
  signature: string
}


// Type checks

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
    && util.hasProp(obj, "att") && Array.isArray(obj.att) && obj.att.every(isCapability)
    && (!util.hasProp(obj, "fct") || Array.isArray(obj.fct) && obj.fct.every(util.isRecord))
    && util.hasProp(obj, "prf") && Array.isArray(obj.prf) && obj.prf.every(str => typeof str === "string")
}

export function isCapability(obj: unknown): obj is Capability {
  return util.isRecord(obj) && util.hasProp(obj, "cap") && typeof obj.cap === "string"
}

export function isAvailableCryptoKeyPair(keypair: CryptoKeyPair): keypair is AvailableCryptoKeyPair {
  return keypair.publicKey != null && keypair.privateKey != null
}
