// https://whitepaper.fission.codes/access-control/ucan/jwt-authentication#attenuation
import { Capability, Ucan } from "./types"
import { Chained } from "./chained"
import * as util from "./util"


export interface CapabilitySemantics<A> {
  parse(cap: Capability): A | null
  toCapability(parsedCap: A): Capability
  /**
   * This figures out whether a given `childCap` can be delegated from `parentCap`.
   * There are three possible results with three return types respectively:
   * - `A`: The delegation is possible and results in the rights returned.
   * - `null`: The capabilities from `parentCap` and `childCap` are unrelated and can't be compared nor delegated.
   * - `CapabilityEscalation<A>`: It's clear that `childCap` is meant to be delegated from `parentCap`, but there's a rights escalation.
   */
  tryDelegating<T extends A>(parentCap: T, childCap: T): T | null | CapabilityEscalation<A>
  // TODO builders
}


export interface CapabilityInfo {
  originator: string // DID
  expiresAt: number
  notBefore?: number
}


export interface CapabilityEscalation<A> {
  escalation: string // reason
  capability: A // the capability that escalated rights
}

function isCapabilityEscalation<A>(obj: unknown): obj is CapabilityEscalation<A> {
  return util.isRecord(obj)
    && util.hasProp(obj, "escalation") && typeof obj.escalation === "string"
    && util.hasProp(obj, "capability")
}


export type CapabilityResult<A>
  = A & CapabilityInfo
  | CapabilityEscalation<A>


export function capabilities<A>(
  ucan: Chained,
  capability: CapabilitySemantics<A>,
): Iterable<CapabilityResult<A>> {

  function* findParsingCaps(ucan: Ucan<never>): Iterable<A & CapabilityInfo> {
    const capInfo = parseCapabilityInfo(ucan)
    for (const cap of ucan.payload.att) {
      const parsedCap = capability.parse(cap)
      if (parsedCap != null) yield { ...parsedCap, ...capInfo }
    }
  }

  const delegate = (ucan: Ucan<never>, capabilitiesInProofs: () => Iterable<() => Iterable<CapabilityResult<A>>>) => {
    return function* () {
      for (const parsedChildCap of findParsingCaps(ucan)) {
        let isCoveredByProof = false
        for (const capabilitiesInProof of capabilitiesInProofs()) {
          for (const parsedParentCap of capabilitiesInProof()) {
            // pass through capability escalations from parents
            if (isCapabilityEscalation(parsedParentCap)) {
              yield parsedParentCap
            } else {
              // try figuring out whether we can delegate the capabilities from this to the parent
              const delegated = capability.tryDelegating(parsedParentCap, parsedChildCap)
              // if the capabilities *are* related, then this will be non-null
              // otherwise we just continue looking
              if (delegated != null) {
                // we infer that the capability was meant to be delegated
                isCoveredByProof = true
                // it's still possible that that delegation was invalid, i.e. an escalation, though
                if (isCapabilityEscalation(delegated)) {
                  yield delegated // which is an escalation
                } else {
                  yield delegateCapabilityInfo({ ...parsedChildCap, ...delegated }, parsedParentCap)
                }
              }
            }
          }
        }
        // If a capability can't be considered to be delegated by any of its proofs
        // (or if there are no proofs),
        // then we root its origin in the UCAN we're looking at.
        if (!isCoveredByProof) {
          yield parsedChildCap
        }
      }
    }
  }

  return ucan.reduce(delegate)()
}

function delegateCapabilityInfo<A extends CapabilityInfo>(childCap: A, parentCap: A): A {
  let notBefore = {}
  if (childCap.notBefore != null && parentCap.notBefore != null) {
    notBefore = { notBefore: Math.max(childCap.notBefore, parentCap.notBefore) }
  } else if (parentCap.notBefore != null) {
    notBefore = { notBefore: parentCap.notBefore }
  } else {
    notBefore = { notBefore: childCap.notBefore }
  }
  return {
    ...childCap,
    originator: parentCap.originator,
    expiresAt: Math.min(childCap.expiresAt, parentCap.expiresAt),
    ...notBefore,
  }
}

function parseCapabilityInfo(ucan: Ucan<never>): CapabilityInfo {
  return {
    originator: ucan.payload.iss,
    expiresAt: ucan.payload.exp,
    ...(ucan.payload.nbf != null ? { notBefore: ucan.payload.nbf } : {}),
  }
}
