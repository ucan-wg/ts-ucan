import * as token from "./token"
import * as util from "./util"
import { Keypair, isKeypair, Capability, Fact, UcanParts } from "./types"
import { publicKeyBytesToDid } from "./did/transformers"
import { Chained } from "./chained"
import { CapabilityInfo, CapabilitySemantics } from "./attenuation"
import { Store } from "./store"


export interface BuildableState {
  issuer: Keypair
  audience: string
  expiration: number
}

function isBuildableState(obj: unknown): obj is BuildableState {
  return util.isRecord(obj)
    && util.hasProp(obj, "issuer") && isKeypair(obj.issuer)
    && util.hasProp(obj, "audience") && typeof obj.audience === "string"
    && util.hasProp(obj, "expiration") && typeof obj.expiration === "number"
}

interface DefaultableState {
  capabilities: Capability[]
  facts: Fact[]
  proofs: Chained[]
  addNonce: boolean
  notBefore?: number
}

// the state neccessary for being able to lookup fitting capabilities in the UCAN store
export interface CapabilityLookupCapableState {
  issuer: Keypair
  expiration: number
}

function isCapabilityLookupCapableState(obj: unknown): obj is CapabilityLookupCapableState {
  return util.isRecord(obj)
    && util.hasProp(obj, "issuer") && isKeypair(obj.issuer)
    && util.hasProp(obj, "expiration") && typeof obj.expiration === "number"
}

export class Builder<State extends Partial<BuildableState>> {

  private state: State // portion of the state that's required to be set before building
  private defaultable: DefaultableState // portion of the state that has sensible defaults

  private constructor(state: State, defaultable: DefaultableState) {
    this.state = state
    this.defaultable = defaultable
  }

  static create(): Builder<{}> {
    return new Builder({}, { capabilities: [], facts: [], proofs: [], addNonce: false })
  }

  issuedBy(issuer: Keypair): Builder<State & { issuer: Keypair }> {
    return new Builder({ ...this.state, issuer }, this.defaultable)
  }

  toAudience(audience: string): Builder<State & { audience: string }> {
    return new Builder({ ...this.state, audience }, this.defaultable)
  }

  withLifetimeInSeconds(seconds: number): Builder<State & { expiration: number }> {
    return this.withExpiraton(Date.now() + seconds * 1000)
  }

  withExpiraton(expiration: number): Builder<State & { expiration: number }> {
    if (this.defaultable.notBefore != null && expiration < this.defaultable.notBefore) {
      throw new Error(`Can't set expiration to ${expiration} which is before 'notBefore': ${this.defaultable.notBefore}`)
    }
    return new Builder({ ...this.state, expiration }, this.defaultable)
  }

  withNotBefore(notBeforeTimestamp: number): Builder<State> {
    if (util.hasProp(this.state, "expiration") && typeof this.state.expiration === "number" && this.state.expiration < notBeforeTimestamp) {
      throw new Error(`Can't set 'notBefore' to ${notBeforeTimestamp} which is after expiration: ${this.state.expiration}`)
    }
    return new Builder(this.state, { ...this.defaultable, notBefore: notBeforeTimestamp })
  }

  withFact(fact: Fact): Builder<State>
  withFact(fact: Fact, ...facts: Fact[]): Builder<State>
  withFact(fact: Fact, ...facts: Fact[]): Builder<State> {
    return new Builder(this.state, {
      ...this.defaultable,
      facts: [...this.defaultable.facts, fact, ...facts]
    })
  }

  withNonce(): Builder<State> {
    return new Builder(this.state, { ...this.defaultable, addNonce: true })
  }

  /**
   * Claim capabilities 'by parenthood'.
   */
  claimCapability(capability: Capability): Builder<State>
  claimCapability(capability: Capability, ...capabilities: Capability[]): Builder<State>
  claimCapability(capability: Capability, ...capabilities: Capability[]): Builder<State> {
    return new Builder(this.state, {
      ...this.defaultable,
      capabilities: [...this.defaultable.capabilities, capability, ...capabilities]
    })
  }

  delegateCapability<A>(semantics: CapabilitySemantics<A>, requiredCapability: Capability, store: Store): State extends CapabilityLookupCapableState ? Builder<State> : never
  delegateCapability<A>(semantics: CapabilitySemantics<A>, requiredCapability: Capability, proof: Chained): State extends CapabilityLookupCapableState ? Builder<State> : never
  delegateCapability<A>(semantics: CapabilitySemantics<A>, requiredCapability: Capability, storeOrProof: Store | Chained): Builder<State> {
    if (!isCapabilityLookupCapableState(this.state)) {
      throw new Error(`Can't delegate capabilities without having these paramenters set in the builder: issuer and expiration.`)
    }

    function isProof(proof: Store | Chained): proof is Chained {
      // @ts-ignore
      const encodedFnc = proof.encoded
      return typeof encodedFnc === "function"
    }

    const parsedRequirement = semantics.tryParsing(requiredCapability)
    if (parsedRequirement == null) {
      throw new Error(`Can't add capability to UCAN: Semantics can't parse given capability: ${JSON.stringify(requiredCapability)}`)
    }

    const expiration = this.state.expiration
    const hasInfoRequirements = (info: CapabilityInfo) => {
      if (info.expiresAt < expiration) return false
      if (info.notBefore == null || this.defaultable.notBefore == null) return true
      return info.notBefore <= this.defaultable.notBefore
    }

    if (isProof(storeOrProof)) {
      return new Builder(this.state, {
        ...this.defaultable,
        capabilities: [...this.defaultable.capabilities, requiredCapability],
        proofs: this.defaultable.proofs.find(proof => proof.encoded() === storeOrProof.encoded()) == null
          ? [...this.defaultable.proofs, storeOrProof]
          : this.defaultable.proofs
      })
    } else {
      const issuer = publicKeyBytesToDid(this.state.issuer.publicKey, this.state.issuer.keyType)
      // we look up a proof that has our issuer as an audience
      const result = storeOrProof.findWithCapability(issuer, semantics, parsedRequirement, hasInfoRequirements)
      if (result.success) {
        return new Builder(this.state, {
          ...this.defaultable,
          capabilities: [...this.defaultable.capabilities, requiredCapability],
          proofs: this.defaultable.proofs.find(proof => proof.encoded() === result.ucan.encoded()) == null
            ? [...this.defaultable.proofs, result.ucan]
            : this.defaultable.proofs
        })
      } else {
        throw new Error(`Can't add capability to UCAN: ${result.reason}`)
      }
    }
  }

  buildParts(): State extends BuildableState ? UcanParts : never
  buildParts(): UcanParts {
    if (!isBuildableState(this.state)) {
      throw new Error(`Builder is missing one of the required properties before it can be built: issuer, audience and/or expiration.`)
    }
    return token.buildParts({
      keyType: this.state.issuer.keyType,
      issuer: publicKeyBytesToDid(this.state.issuer.publicKey, this.state.issuer.keyType),
      audience: this.state.audience,

      expiration: this.state.expiration,
      notBefore: this.defaultable.notBefore,
      addNonce: this.defaultable.addNonce,

      capabilities: this.defaultable.capabilities,
      facts: this.defaultable.facts,
      proofs: this.defaultable.proofs.map(proof => proof.encoded()),
    })
  }

  async build(): Promise<State extends BuildableState ? Chained : never>
  async build(): Promise<Chained> {
    if (!isBuildableState(this.state)) {
      throw new Error(`Builder is missing one of the required properties before it can be built: issuer, audience and/or expiration.`)
    }
    const parts = this.buildParts()
    const signed = await token.sign(parts.header, parts.payload, this.state.issuer)
    const encoded = token.encode(signed)
    return new Chained(encoded, { ...signed, payload: { ...signed.payload, prf: this.defaultable.proofs } })
  }

}
