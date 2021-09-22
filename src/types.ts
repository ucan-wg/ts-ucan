import { SupportedEncodings } from "uint8arrays/util/bases"

export type Encodings = SupportedEncodings

export interface Keypair {
  publicKey: Uint8Array
  keyType: KeyType
  publicKeyStr: (format?: SupportedEncodings) => string
  did: () => string
  sign: (msg: Uint8Array) => Promise<Uint8Array>
  export: () => Promise<Uint8Array>
}

export enum KeyType {
  RSA = "rsa",
  Edwards = "ed25519",
  BLS = 'bls12-381'
}

export type Fact = Record<string, string>

export type Capability = {
  [rsc: string]: string
  cap: string
}

export type UcanHeader = {
  alg: string
  typ: string
  ucv: string
}

export type UcanPayload = {
  aud: string
  exp: number
  fct: Array<Fact>
  iss: string
  nbf: number
  prf: string | null
  att: Array<Capability>
  nnc?: string
}

export type Ucan = {
  header: UcanHeader
  payload: UcanPayload
  signature: string | null
}
