// https://whitepaper.fission.codes/access-control/ucan/jwt-authentication#attenuation
import { Capability, Ucan } from "./types"
import { Chained } from "./chained"


export interface CapabilitySemantics<A> {
  parse(cap: Capability): A | null
  toCapability(parsedCap: A): Capability
  tryDelegating(parentCap: A, childCap: A): A | null
  // TODO builders
}

export interface CapabilityInfo {
  originator: string // DID
  expiresAt: number
  notBefore?: number
}

export function capabilities<A>(
  ucan: Chained,
  capability: CapabilitySemantics<A>,
): Iterable<A & CapabilityInfo> {

  function* findParsingCaps(ucan: Ucan<never>): Iterable<A & CapabilityInfo> {
    const capInfo = parseCapabilityInfo(ucan)
    for (const cap of ucan.payload.att) {
      const parsedCap = capability.parse(cap)
      if (parsedCap != null) yield { ...parsedCap, ...capInfo }
    }
  }

  const delegate = (ucan: Ucan<never>, delegatedInParent: () => Iterable<() => Iterable<A & CapabilityInfo>>) => {
    return function* () {
      for (const parsedChildCap of findParsingCaps(ucan)) {
        let isCoveredByProof = false
        for (const parent of delegatedInParent()) {
          for (const parsedParentCap of parent()) {
            isCoveredByProof = true
            const delegated = capability.tryDelegating(parsedParentCap, parsedChildCap)
            if (delegated != null) {
              yield delegateCapabilityInfo({ ...parsedChildCap, ...delegated }, parsedParentCap)
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
