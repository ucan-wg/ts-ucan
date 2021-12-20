import * as token from "./token"
import * as util from "./util"
import { Keypair, isKeypair, Capability, Fact, UcanParts } from "./types"
import { publicKeyBytesToDid } from "./did/transformers"
import { Chained } from "./chained"
import { CapabilityInfo, CapabilitySemantics } from "./attenuation"
import { Store } from "./store"


export class Builder {

  private issuer: Keypair
  private audience: string
  private expiration: number
  private notBefore: number | undefined

  private capabilities: Capability[]
  private facts: Fact[]
  private proofs: Chained[]

  constructor(options: BuilderOptionsLifetime)
  constructor(options: BuilderOptionsExpiration)
  constructor(options: unknown) {
    if (!isBuilderOptions(options)) {
      throw new Error("UCAN Builder: Constructor needs to be passed an issuer keypair, audience string and either lifetimeInSeconds or an expiration timestamp.")
    }
    this.issuer = options.issuer
    this.audience = options.audience
    this.notBefore = options.notBefore
    if (isBuilderOptionsExpiration(options)) {
      this.expiration = options.expiration
    } else if (isBuilderOptionsLifetime(options)) {
      this.expiration = Date.now() + options.lifetimeInSeconds * 1000
    } else {
      throw new Error("UCAN Builder: Constructor needs to be passed either a 'lifetimeInSeconds' or 'expiration' number.")
    }

    this.capabilities = []
    this.facts = []
    this.proofs = []
  }

  withCapability<A>(semantics: CapabilitySemantics<A>, requiredCapability: Capability, store: Store): Builder
  withCapability<A>(semantics: CapabilitySemantics<A>, requiredCapability: Capability, proof: Chained): Builder
  withCapability<A>(semantics: CapabilitySemantics<A>, requiredCapability: Capability, storeOrProof: Store | Chained): Builder {
    function isProof(proof: Store | Chained): proof is Chained {
      // @ts-ignore
      const encodedFnc = proof.encoded
      return typeof encodedFnc === "function"
    }

    const parsedRequirement = semantics.tryParsing(requiredCapability)
    if (parsedRequirement == null) {
      throw new Error(`Can't add capability to UCAN: Semantics can't parse given capability: ${JSON.stringify(requiredCapability)}`)
    }
    const hasInfoRequirements = (info: CapabilityInfo) => {
      if (info.expiresAt < this.expiration) return false
      if (info.notBefore == null || this.notBefore == null) return true
      return info.notBefore <= this.notBefore
    }
    if (isProof(storeOrProof)) {
      this.capabilities.push(requiredCapability)
      if (this.proofs.find(proof => proof.encoded() === storeOrProof.encoded()) == null) {
        this.proofs.push(storeOrProof)
      }
    } else {
      const result = storeOrProof.findWithCapability(this.audience, semantics, parsedRequirement, hasInfoRequirements)
      if (result.success) {
        this.capabilities.push(requiredCapability)
        if (this.proofs.find(proof => proof.encoded() === result.ucan.encoded()) == null) {
          this.proofs.push(result.ucan)
        }
      } else {
        throw new Error(`Can't add capability to UCAN: ${result.reason}`)
      }
    }
    return this
  }

  buildParts(options?: BuildOptions): UcanParts {
    const addNonce = options?.addNonce ?? false
    return token.buildParts({
      keyType: this.issuer.keyType,
      issuer: publicKeyBytesToDid(this.issuer.publicKey, this.issuer.keyType),
      audience: this.audience,

      expiration: this.expiration,
      notBefore: this.notBefore,
      addNonce,

      capabilities: this.capabilities,
      facts: this.facts,
      proofs: this.proofs.map(proof => proof.encoded()),
    })
  }

  async build(options?: BuildOptions): Promise<Chained> {
    const parts = this.buildParts(options)
    const signed = await token.sign(parts.header, parts.payload, this.issuer)
    const encoded = token.encode(signed)
    return new Chained(encoded, { ...signed, payload: { ...signed.payload, prf: this.proofs }})
  }

}

export interface BuilderOptions {
  issuer: Keypair
  audience: string
  notBefore?: number
}

export interface BuilderOptionsLifetime extends BuilderOptions {
  lifetimeInSeconds: number
}

export interface BuilderOptionsExpiration extends BuilderOptions {
  expiration: number
}

export interface BuildOptions {
  addNonce?: boolean
}

function isBuilderOptions(obj: unknown): obj is BuilderOptions {
  return util.isRecord(obj)
    && util.hasProp(obj, "issuer") && isKeypair(obj.issuer)
    && util.hasProp(obj, "audience") && typeof obj.audience === "string"
    && (!util.hasProp(obj, "notBefore") || typeof obj.notBefore === "number")
}

function isBuilderOptionsLifetime(obj: unknown): obj is BuilderOptionsLifetime {
  return isBuilderOptions(obj)
    && util.hasProp(obj, "lifetimeInSeconds") && typeof obj.lifetimeInSeconds === "number"
}

function isBuilderOptionsExpiration(obj: unknown): obj is BuilderOptionsExpiration {
  return isBuilderOptions(obj)
    && util.hasProp(obj, "expiration") && typeof obj.expiration === "number"
}
