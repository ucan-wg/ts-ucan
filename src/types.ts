import { SupportedEncodings } from "uint8arrays/util/bases"

export type Encodings = SupportedEncodings

export interface Keypair {
  publicKey: Uint8Array
  keyType: KeyType
  publicKeyStr: (format?: SupportedEncodings) => string
  did: () => string
  sign: (msg: Uint8Array) => Promise<Uint8Array>
}

export enum KeyType {
  RSA = "rsa",
  Edwards = "ed25519",
  BLS = 'bls12-381'
}

export type Fact = Record<string, string>

export type Resource =
  "*" | Record<string, string>

export type Potency = string |  Record<string, unknown> | undefined | null

export type UcanHeader = {
  alg: string
  typ: string
  uav: string
}

export type UcanPayload = {
  aud: string
  exp: number
  fct: Array<Fact>
  iss: string
  nbf: number
  prf: string | null
  ptc: Potency
  rsc: Resource
}

export type Ucan = {
  header: UcanHeader
  payload: UcanPayload
  signature: string | null
}
