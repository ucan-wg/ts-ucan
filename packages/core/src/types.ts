import * as semver from "./semver.js"
import { SemVer } from "./semver.js"
import { SupportedEncodings } from "uint8arrays/util/bases.js" // @IMPORT
import { Capability, isCapability, isEncodedCapability } from "./capability/index.js"
import * as util from "./util.js"
import { DelegationChain, DelegationSemantics } from "./attenuation.js"


// 💎


export type Ucan<Prf = string> = {
  header: UcanHeader
  payload: UcanPayload<Prf>
  // We need to keep the encoded version around to preserve the signature
  signedData: string
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
  ucv: SemVer
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

export interface Didable {
  did: () => string
}

export interface ExportableKey {
  export: (format?: Encodings) => Promise<string>
}

export interface Keypair {
  jwtAlg: string
  sign: (msg: Uint8Array) => Promise<Uint8Array>
}

export interface DidableKey extends Didable, Keypair {}

// MISC


export type Encodings = SupportedEncodings


// STORE


export interface IndexByAudience {
  [ audienceDID: string ]: Array<{
    processedUcan: Ucan
    capabilities: DelegationChain[]
  }>
}

export interface StoreI {
  add(ucan: Ucan): Promise<void> 
  getByAudience(audience: string): Ucan[] 
  findByAudience(audience: string, predicate: (ucan: Ucan) => boolean): Ucan | null 
  findWithCapability(
    audience: string,
    requiredCapability: Capability,
    requiredIssuer: string,
  ): Iterable<DelegationChain>   
}

// BUILDER

export interface BuildableState {
  issuer: DidableKey
  audience: string
  expiration: number
}


export interface DefaultableState {
  capabilities: Capability[]
  facts: Fact[]
  proofs: Ucan[]
  addNonce: boolean
  notBefore?: number
}

// the state neccessary for being able to lookup fitting capabilities in the UCAN store
export interface CapabilityLookupCapableState {
  issuer: Keypair
  expiration: number
}

export interface BuilderI<State extends Partial<BuildableState>> {
  issuedBy(issuer: DidableKey): BuilderI<State & { issuer: DidableKey }>
  toAudience(audience: string): BuilderI<State & { audience: string }>
  withLifetimeInSeconds(seconds: number): BuilderI<State & { expiration: number }>
  withExpiration(expiration: number): BuilderI<State & { expiration: number }>
  withNotBefore(notBeforeTimestamp: number): BuilderI<State>
  withFact(fact: Fact): BuilderI<State>
  withFact(fact: Fact, ...facts: Fact[]): BuilderI<State>
  withFact(fact: Fact, ...facts: Fact[]): BuilderI<State>
  withNonce(): BuilderI<State>
  claimCapability(capability: Capability): BuilderI<State>
  claimCapability(capability: Capability, ...capabilities: Capability[]): BuilderI<State>
  claimCapability(capability: Capability, ...capabilities: Capability[]): BuilderI<State>
  delegateCapability(requiredCapability: Capability, store: StoreI): State extends CapabilityLookupCapableState ? BuilderI<State> : never
  delegateCapability(requiredCapability: Capability, proof: DelegationChain, semantics: DelegationSemantics): State extends CapabilityLookupCapableState ? BuilderI<State> : never
  delegateCapability(requiredCapability: Capability, storeOrProof: StoreI | DelegationChain, semantics?: DelegationSemantics): BuilderI<State>
  buildPayload(): State extends BuildableState ? UcanPayload : never
  buildPayload(): UcanPayload
  build(): Promise<State extends BuildableState ? Ucan : never>
  build(): Promise<Ucan>
}


// TYPE CHECKS


export function isKeypair(obj: unknown): obj is Keypair {
  return util.isRecord(obj)
    && util.hasProp(obj, "jwtAlg") && typeof obj.jwtAlg === "string"
    && util.hasProp(obj, "sign") && typeof obj.sign === "function"
}

export function isUcanHeader(obj: unknown): obj is UcanHeader {
  return util.isRecord(obj)
    && util.hasProp(obj, "alg") && typeof obj.alg === "string"
    && util.hasProp(obj, "typ") && typeof obj.typ === "string"
    && util.hasProp(obj, "ucv") && semver.isSemVer(obj.ucv)
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