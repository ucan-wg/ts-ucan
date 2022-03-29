// https://github.com/ucan-wg/spec/blob/dd4ac83f893cef109f5a26b07970b2484f23aabf/README.md#325-attenuation-scope
import { Capability } from "./capability"
import { Chained } from "./chained"
import { Ucan } from "./types"
import * as util from "./util"


// TYPES


export interface CapabilitySemantics<A> {
  /**
   * Try to parse a capability into a representation used for
   * delegation & returning in the `capabilities` call.
   *
   * If the capability doesn't seem to match the format expected
   * for the capabilities with the semantics currently defined,
   * return `null`.
   */
  tryParsing(cap: Capability): A | null

  /**
   * This figures out whether a given `childCap` can be delegated from `parentCap`.
   * There are three possible results with three return types respectively:
   * - `A`: The delegation is possible and results in the rights returned.
   * - `null`: The capabilities from `parentCap` and `childCap` are unrelated and can't be compared nor delegated.
   * - `CapabilityEscalation<A>`: It's clear that `childCap` is meant to be delegated from `parentCap`, but there's a rights escalation.
   */
  tryDelegating(parentCap: A, childCap: A): A | null | CapabilityEscalation<A>
}

export type CapabilityResult<A>
  = CapabilityWithInfo<A>
  | CapabilityEscalation<A>

export interface CapabilityInfo {
  originator: string // DID
  expiresAt: number
  notBefore?: number
}

export interface CapabilityWithInfo<A> {
  info: CapabilityInfo
  capability: A
}

export interface CapabilityEscalation<A> {
  escalation: string // reason
  capability: A // the capability that escalated rights
}



// TYPE CHECKING


export function isCapabilityEscalation<A>(obj: unknown): obj is CapabilityEscalation<A> {
  return util.isRecord(obj)
    && util.hasProp(obj, "escalation") && typeof obj.escalation === "string"
    && util.hasProp(obj, "capability")
}



// PARSING


function parseCapabilityInfo(ucan: Ucan<never>): CapabilityInfo {
  return {
    originator: ucan.payload.iss,
    expiresAt: ucan.payload.exp,
    ...(ucan.payload.nbf != null ? { notBefore: ucan.payload.nbf } : {}),
  }
}



// FUNCTIONS


export function canDelegate<A>(semantics: CapabilitySemantics<A>, capability: A, ucan: Chained): boolean {
  for (const cap of capabilities(ucan, semantics)) {
    if (isCapabilityEscalation(cap)) {
      continue
    }

    const delegated = semantics.tryDelegating(cap.capability, capability)

    if (isCapabilityEscalation(delegated)) {
      continue
    }

    if (delegated != null) {
      return true
    }
  }

  return false
}

export function capabilities<A>(
  ucan: Chained,
  capability: CapabilitySemantics<A>,
): Iterable<CapabilityResult<A>> {

  function* findParsingCaps(ucan: Ucan<never>): Iterable<CapabilityWithInfo<A>> {
    const capInfo = parseCapabilityInfo(ucan)
    for (const cap of ucan.payload.att) {
      const parsedCap = capability.tryParsing(cap)
      if (parsedCap != null) yield { info: capInfo, capability: parsedCap }
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
              const delegated = capability.tryDelegating(parsedParentCap.capability, parsedChildCap.capability)
              // if the capabilities *are* related, then this will be non-null
              // otherwise we just continue looking
              if (delegated != null) {
                // we infer that the capability was meant to be delegated
                isCoveredByProof = true
                // it's still possible that that delegation was invalid, i.e. an escalation, though
                if (isCapabilityEscalation(delegated)) {
                  yield delegated // which is an escalation
                } else {
                  yield {
                    info: delegateCapabilityInfo(parsedChildCap.info, parsedParentCap.info),
                    capability: delegated
                  }
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

function delegateCapabilityInfo(childInfo: CapabilityInfo, parentInfo: CapabilityInfo): CapabilityInfo {
  let notBefore = {}
  if (childInfo.notBefore != null && parentInfo.notBefore != null) {
    notBefore = { notBefore: Math.max(childInfo.notBefore, parentInfo.notBefore) }
  } else if (parentInfo.notBefore != null) {
    notBefore = { notBefore: parentInfo.notBefore }
  } else {
    notBefore = { notBefore: childInfo.notBefore }
  }
  return {
    originator: parentInfo.originator,
    expiresAt: Math.min(childInfo.expiresAt, parentInfo.expiresAt),
    ...notBefore,
  }
}

export function hasCapability<Cap>(
  semantics: CapabilitySemantics<Cap>,
  capability: CapabilityWithInfo<Cap>,
  ucan: Chained
): CapabilityWithInfo<Cap> | false {
  for (const cap of capabilities(ucan, semantics)) {
    if (isCapabilityEscalation(cap)) {
      continue
    }

    const delegatedCapability = semantics.tryDelegating(cap.capability, capability.capability)

    if (isCapabilityEscalation(delegatedCapability)) {
      continue
    }

    if (delegatedCapability != null) {
      return {
        info: delegateCapabilityInfo(capability.info, cap.info),
        capability: delegatedCapability,
      }
    }
  }

  return false
}
