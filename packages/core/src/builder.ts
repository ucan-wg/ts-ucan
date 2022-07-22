import * as token from "./token.js"
import * as util from "./util.js"
import Plugins from "./plugins.js"

import { Fact, UcanPayload, isKeypair, Ucan, DidableKey, StoreI, BuilderI, BuildableState, CapabilityLookupCapableState, DefaultableState } from "./types.js"
import { Capability, isCapability } from "./capability/index.js"
import { capabilityCanBeDelegated, DelegationSemantics, DelegationChain } from "./attenuation.js"



function isBuildableState(obj: unknown): obj is BuildableState {
  return util.isRecord(obj)
    && util.hasProp(obj, "issuer") && isKeypair(obj.issuer)
    && util.hasProp(obj, "audience") && typeof obj.audience === "string"
    && util.hasProp(obj, "expiration") && typeof obj.expiration === "number"
}

function isCapabilityLookupCapableState(obj: unknown): obj is CapabilityLookupCapableState {
  return util.isRecord(obj)
    && util.hasProp(obj, "issuer") && isKeypair(obj.issuer)
    && util.hasProp(obj, "expiration") && typeof obj.expiration === "number"
}

// type BuilderConstructor = new <State extends Partial<BuildableState>>(state: State, defaultable: DefaultableState) => BuilderI<State>
type BuilderConstructor = { 
  new <State extends Partial<BuildableState>>(state: State, defaultable: DefaultableState): BuilderI<State> 
  create(): BuilderI<Record<string, never>> 
}

/**
 * A builder API for UCANs.
 *
 * Supports grabbing UCANs from a UCAN `Store` for proofs (see `delegateCapability`).
 *
 * Example usage:
 *
 * ```ts
 * const ucan = await Builder.create()
 *   .issuedBy(aliceKeypair)
 *   .toAudience(bobDID)
 *   .withLifetimeInSeconds(30)
 *   .claimCapability({ email: "my@email.com", cap: "SEND" })
 *   .delegateCapability(emailSemantics, { email: "my-friends@email.com", cap: "SEND" }, proof)
 *   .build()
 * ```
 */
const mkBuilderClass = (plugins: Plugins): BuilderConstructor => {

  return class Builder<State extends Partial<BuildableState>> implements BuilderI<State> {

    private state: State // portion of the state that's required to be set before building
    private defaultable: DefaultableState // portion of the state that has sensible defaults

    constructor(state: State, defaultable: DefaultableState) {
      this.state = state
      this.defaultable = defaultable
    }

    /**
     * Create an empty builder.
     * Before finalising the builder, you need to at least call
     * - `issuedBy`
     * - `toAudience` and
     * - `withLifetimeInSeconds` or `withExpiration`.
     * To finalise the builder, call its `build` or `buildPayload` method.
     */
    static create(): Builder<Record<string, never>> {
        return new Builder({}, { capabilities: [], facts: [], proofs: [], addNonce: false })
    }

    /**
     * @param issuer The issuer as a DID string ("did:key:...").
     *
     * The UCAN must be signed with the private key of the issuer to be valid.
     */
    issuedBy(issuer: DidableKey): Builder<State & { issuer: DidableKey }> {
      if (!isKeypair(issuer)) {
        throw new TypeError(`Expected a Keypair, but got ${issuer}`)
      }
      return new Builder({ ...this.state, issuer }, this.defaultable)
    }

    /**
     * @param audience The audience as a DID string ("did:key:...").
     *
     * This is the identity this UCAN transfers rights to.
     * It could e.g. be the DID of a service you're posting this UCAN as a JWT to,
     * or it could be the DID of something that'll use this UCAN as a proof to
     * continue the UCAN chain as an issuer.
     */
    toAudience(audience: string): Builder<State & { audience: string }> {
      if (typeof audience !== "string") {
        throw new TypeError(`Expected audience DID as string, but got ${audience}`)
      }
      return new Builder({ ...this.state, audience }, this.defaultable)
    }

    /**
     * @param seconds The number of seconds from the calltime of this function
     *   to set the expiry timestamp to.
     */
    withLifetimeInSeconds(seconds: number): Builder<State & { expiration: number }> {
      if (typeof seconds !== "number") {
        throw new TypeError(`Expected seconds as number, but got ${seconds}`)
      }
      if (!isFinite(seconds) || seconds <= 0) {
        throw new TypeError(`Expected seconds to be a positive number, but got ${seconds}`)
      }
      return this.withExpiration(Math.floor(Date.now() / 1000) + seconds)
    }

    /**
     * @param expiration The UTCTime timestamp (in seconds) for when the UCAN should expire.
     */
    withExpiration(expiration: number): Builder<State & { expiration: number }> {
      if (typeof expiration !== "number" || !isFinite(expiration)) {
        throw new TypeError(`Expected expiration as number, but got ${expiration}`)
      }
      if (this.defaultable.notBefore != null && expiration < this.defaultable.notBefore) {
        throw new Error(`Can't set expiration to ${expiration} which is before 'notBefore': ${this.defaultable.notBefore}`)
      }
      return new Builder({ ...this.state, expiration }, this.defaultable)
    }

    /**
     * @param notBeforeTimestamp The UTCTime timestamp (in seconds) of when the UCAN becomes active.
     */
    withNotBefore(notBeforeTimestamp: number): Builder<State> {
      if (typeof notBeforeTimestamp !== "number" || !isFinite(notBeforeTimestamp)) {
        throw new TypeError(`Expected notBeforeTimestamp as number, but got ${notBeforeTimestamp}`)
      }
      if (util.hasProp(this.state, "expiration") && typeof this.state.expiration === "number" && this.state.expiration < notBeforeTimestamp) {
        throw new Error(`Can't set 'notBefore' to ${notBeforeTimestamp} which is after expiration: ${this.state.expiration}`)
      }
      return new Builder(this.state, { ...this.defaultable, notBefore: notBeforeTimestamp })
    }

    /**
     * @param fact Any fact or proof of knowledge in this UCAN as a record.
     * @param facts Arbitrary more facts or proofs of knowledge.
     */
    withFact(fact: Fact): Builder<State>
    withFact(fact: Fact, ...facts: Fact[]): Builder<State>
    withFact(fact: Fact, ...facts: Fact[]): Builder<State> {
      if (!util.isRecord(fact) || facts.some(fct => !util.isRecord(fct))) {
        throw new TypeError(`Expected fact(s) to be a record, but got ${fact}`)
      }
      return new Builder(this.state, {
        ...this.defaultable,
        facts: [ ...this.defaultable.facts, fact, ...facts ]
      })
    }

    /**
     * Will ensure that the built UCAN includes a number used once.
     */
    withNonce(): Builder<State> {
      return new Builder(this.state, { ...this.defaultable, addNonce: true })
    }

    /**
     * Claim capabilities 'by parenthood'.
     */
    claimCapability(capability: Capability): Builder<State>
    claimCapability(capability: Capability, ...capabilities: Capability[]): Builder<State>
    claimCapability(capability: Capability, ...capabilities: Capability[]): Builder<State> {
      if (!isCapability(capability)) {
        throw new TypeError(`Expected capability, but got ${JSON.stringify(capability, null, " ")}`)
      }
      return new Builder(this.state, {
        ...this.defaultable,
        capabilities: [ ...this.defaultable.capabilities, capability, ...capabilities ]
      })
    }

    /**
     * Delegate capabilities from a given proof to the audience of the UCAN you're building.
     *
     * @param semantics The rules for which delegations of capabilities are allowed.
     * @param requiredCapability The capability you want to delegate.
     *
     * Then, one of
     * @param proof The proof chain that grants the issuer of this UCAN at least the capabilities you want to delegate, or
     * @param store The UCAN store in which to try to find a UCAN granting you enough capabilities to delegate given capabilities.
     *
     * @throws If given store can't provide a UCAN for delegating given capability
     * @throws If given proof can't be used to delegate given capability
     * @throws If the builder hasn't set an issuer and expiration yet
     */
    delegateCapability(requiredCapability: Capability, store: StoreI): State extends CapabilityLookupCapableState ? Builder<State> : never
    delegateCapability(requiredCapability: Capability, proof: DelegationChain, semantics: DelegationSemantics): State extends CapabilityLookupCapableState ? Builder<State> : never
    delegateCapability(requiredCapability: Capability, storeOrProof: StoreI | DelegationChain, semantics?: DelegationSemantics): Builder<State> {
      if (!isCapability(requiredCapability)) {
        throw new TypeError(`Expected 'requiredCapability' as a second argument, but got ${requiredCapability}`)
      }
      if (!isCapabilityLookupCapableState(this.state)) {
        throw new Error(`Can't delegate capabilities without having these paramenters set in the builder: issuer and expiration.`)
      }

      function isProof(proof: StoreI | DelegationChain): proof is DelegationChain {
        return util.hasProp(proof, "capability") || util.hasProp(proof, "ownershipDID")
      }

      if (isProof(storeOrProof)) {
        if (semantics == null) {
          throw new TypeError(`Expected 'semantics' as third argument if a 'proof' DelegationChain was passed as second.`)
        }
        const proof: DelegationChain = storeOrProof
        const ucan = proof.ucan
        if (!capabilityCanBeDelegated(semantics, requiredCapability, proof)) {
          throw new Error(`Can't add capability to UCAN: Given proof doesn't give required rights to delegate.`)
        }
        return new Builder(this.state, {
          ...this.defaultable,
          capabilities: [ ...this.defaultable.capabilities, requiredCapability ],
          proofs: this.defaultable.proofs.find(p => token.encode(p) === token.encode(ucan)) == null
            ? [ ...this.defaultable.proofs, ucan ]
            : this.defaultable.proofs
        })
      } else {
        const store: StoreI = storeOrProof
        const issuer = this.state.issuer.did()
        // we look up a proof that has our issuer as an audience
        const result = util.first(store.findWithCapability(issuer, requiredCapability, issuer))
        if (result != null) {
          const ucan = result.ucan
          const ucanEncoded = token.encode(ucan)
          return new Builder(this.state, {
            ...this.defaultable,
            capabilities: [ ...this.defaultable.capabilities, requiredCapability ],
            proofs: this.defaultable.proofs.find(proof => token.encode(proof) === ucanEncoded) == null
              ? [ ...this.defaultable.proofs, ucan ]
              : this.defaultable.proofs
          })
        } else {
          throw new Error(`Couldn't add capability to UCAN. Couldn't find anything providing this capability in given store.`)
        }
      }
    }

    /**
     * Build the UCAN body. This can be used if you want to sign the UCAN yourself afterwards.
     */
    buildPayload(): State extends BuildableState ? UcanPayload : never
    buildPayload(): UcanPayload {
      if (!isBuildableState(this.state)) {
        throw new Error(`Builder is missing one of the required properties before it can be built: issuer, audience and expiration.`)
      }
      return token.buildPayload({
        issuer: this.state.issuer.did(),
        audience: this.state.audience,

        expiration: this.state.expiration,
        notBefore: this.defaultable.notBefore,
        addNonce: this.defaultable.addNonce,

        capabilities: this.defaultable.capabilities,
        facts: this.defaultable.facts,
        proofs: this.defaultable.proofs.map(proof => token.encode(proof)),
      })
    }

    /**
     * Finalize: Build and sign the UCAN.
     *
     * @throws If the builder hasn't yet been set an issuer, audience and expiration.
     */
    async build(): Promise<State extends BuildableState ? Ucan : never>
    async build(): Promise<Ucan> {
      if (!isBuildableState(this.state)) {
        throw new Error(`Builder is missing one of the required properties before it can be built: issuer, audience and expiration.`)
      }
      const payload = this.buildPayload()
      return await token.signWithKeypair(plugins)(payload, this.state.issuer)
    }

  }

}

export default mkBuilderClass