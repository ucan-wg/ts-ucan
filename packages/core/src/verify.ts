import * as token from "./token.js"
import Plugins from "./plugins.js"
import { capabilityCanBeDelegated, DelegationSemantics, DelegationChain, delegationChains, equalCanDelegate, rootIssuer } from "./attenuation.js"
import { Capability, isCapability } from "./capability/index.js"
import { Fact, Ucan } from "./types.js"


export type Result<Ok, Err = Error>
  = { ok: true; value: Ok }
  | { ok: false; error: Err }

const ok: <T, E>(k: T) => Result<T, E> = k => ({ ok: true, value: k })
const err: <T, E>(e: E) => Result<T, E> = e => ({ ok: false, error: e })


export interface VerifyOptions {
  /**
   * the DID of the callee of this function. The expected audience of the outermost level of the UCAN.
   * NOTE: This DID should not be hardcoded in production calls to this function.
   */
  audience: string
  /**
   * a non-empty list of capabilities required for this UCAN invocation. The root issuer and capability
   * should be derived from something like your HTTP request parameters. They identify the resource
   * that's access-controlled.
   */
  requiredCapabilities: { capability: Capability; rootIssuer: string }[]
   /**
   * an optional record of functions that specify what the rules for delegating capabilities are.
   * If not provided, the default semantics will be `equalCanDelegate`.
   */
  semantics?: DelegationSemantics
  /**
   * an async predicate on UCANs to figure out whether they've been revoked or not.
   * Usually that means checking whether the hash of the UCAN is in a list of revoked UCANs.
   * If not provided, it will assume no UCAN to be revoked.
   */
   isRevoked?: (ucan: Ucan) => Promise<boolean>
  /**
   * an optional function that's given the list of facts in the root UCAN and returns a boolean indicating
   * whether the facts include everything you expect for the UCAN invocation to check.
   * By default this will ignore all facts in the UCAN and just return true.
   */
  checkFacts?: (facts: Fact[]) => boolean
}


/**
 * Verify a UCAN for an invocation.
 *
 * @param ucan a UCAN to verify for invocation in JWT format. (starts with 'eyJ...' and has two '.' in it)
 *
 * @param options required and optional verification options see {@link VerifyOptions}
 *
 * @throws TypeError if the passed arguments don't match what is expected
 */
export const verify = (plugins: Plugins) => 
  async (ucan: string, options: VerifyOptions): Promise<Result<Verification[], Error[]>> => {
  const { audience, requiredCapabilities } = options
  const semantics = options.semantics ?? equalCanDelegate
  const isRevoked = options.isRevoked ?? (async () => false)
  const checkFacts = options.checkFacts ?? (() => true)
  // type-check arguments
  if (typeof ucan !== "string") {
    throw new TypeError(`Expected an encoded UCAN string as first argument, but got ${ucan}`)
  }
  if (typeof audience !== "string" || !audience.startsWith("did:")) {
    throw new TypeError(`Expected a DID string as second argument, but got ${audience}`)
  }
  if (typeof isRevoked !== "function") {
    throw new TypeError(`Expected a function returning a promise as third argument, but got ${isRevoked}`)
  }
  if (!Array.isArray(requiredCapabilities)) {
    throw new TypeError(`Expected an array as fourth argument, but got ${requiredCapabilities}`)
  }
  if (requiredCapabilities.length < 1) {
    throw new TypeError(`Expected a non-empty list of required capabilities as 4th argument.`)
  }
  if (requiredCapabilities.some(req => !isCapability(req.capability) || typeof req.rootIssuer !== "string" || !req.rootIssuer.startsWith("did:"))) {
    throw new TypeError(`Expected an array of records of capabilities and rootIssuers as DID strings as 4th argument, but got ${requiredCapabilities}`)
  }
  if (typeof semantics.canDelegateResource !== "function" || typeof semantics.canDelegateAbility !== "function") {
    throw new TypeError(`Expected a record with two functions 'canDelegateResource' and 'canDelegateAbility' as 5th argument, but got ${semantics}`)
  }
  if (typeof checkFacts !== "function") {
    throw new TypeError(`Expected a function as 6th argument, but got ${checkFacts}`)
  }

  try {
    // Verify the UCAN
    const decoded = await token.validate(plugins)(ucan)

    // Check that it's addressed to us
    if (decoded.payload.aud !== audience) {
      return err([ new Error(`Invalid UCAN: Expected audience to be ${audience}, but it's ${decoded.payload.aud}`) ])
    }

    const errors: Error[] = []
    const remaining = new Set(requiredCapabilities)
    const proven: Verification[] = []

    // Check that all required capabilities are verified
    loop: for await (const delegationChain of delegationChains(plugins)(semantics, decoded, isRevoked)) {
      if (delegationChain instanceof Error) {
        errors.push(delegationChain)
        continue
      }

      // Try to look for capabilities from given delegation chain
      for (const expected of remaining) {
        if (
          capabilityCanBeDelegated(semantics, expected.capability, delegationChain)
          && rootIssuer(delegationChain) === expected.rootIssuer
        ) {
          remaining.delete(expected)
          proven.push({
            ...expected,
            proof: delegationChain
          })
        }
      }

      // If we've already verified all, we don't need to keep looking
      if (remaining.size === 0) {
        break loop
      }
    }

    return remaining.size > 0 ? err(errors) : ok(proven)

  } catch (e) {
    return err([ e instanceof Error ? e : new Error(`Unknown error during UCAN verification: ${e}`) ])
  }
}

export interface Verification {
  capability: Capability
  rootIssuer: string
  proof: DelegationChain
}
