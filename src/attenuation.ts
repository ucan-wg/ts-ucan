// https://whitepaper.fission.codes/access-control/ucan/jwt-authentication#attenuation
import { Capability, Ucan } from "./types"
import { Chained } from "./chained"

export interface CapabilityChecker {

}

export interface CapabilityInfo {
  originator: string // DID
  expiresAt: number
  // notBefore?: number
}

export interface EmailCapability {
  email: string
  potency: "SEND"
}

function parseEmailCapability(cap: Capability): EmailCapability | null {
  if (typeof cap.email === "string" && cap.cap === "SEND") {
    return {
      email: cap.email,
      potency: cap.cap,
    }
  }
  return null
}

function delegateEmailCap(childCap: EmailCapability, parentCap: EmailCapability): EmailCapability | null {
  // potency is always "SEND" anyway, so doesn't need to be checked
  return childCap.email === parentCap.email ? childCap : null
}

export function emailCapabilities(ucan: Chained) {
  return capabilities(ucan, parseEmailCapability, delegateEmailCap)
}

export function* capabilities<A>(
  ucan: Chained,
  parseCap: (cap: Capability) => A | null,
  delegateCap: (childCap: A, parentCap: A) => A | null
): Iterable<A> {

  function* findParsingCaps(ucan: Ucan<never>): Iterable<A & CapabilityInfo> {
    const capInfo = parseCapabilityInfo(ucan)
    for (const cap of ucan.payload.att) {
      const parsedCap = parseCap(cap)
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
            const delegated = delegateCap(parsedChildCap, parsedParentCap)
            if (delegated != null) {
              yield delegateCapabilityInfo({ ...parsedChildCap, ...delegated }, parsedParentCap)
            }
          }
        }
        if (!isCoveredByProof) {
          yield parsedChildCap
        }
      }
    }
  }

  yield* ucan.reduce(delegate)()
}

function delegateCapabilityInfo<A extends CapabilityInfo>(childCap: A, parentCap: A): A {
  return {
    ...childCap,
    originator: parentCap.originator,
    expiresAt: Math.min(childCap.expiresAt, parentCap.expiresAt),
  }
}

function parseCapabilityInfo(ucan: Ucan<never>): CapabilityInfo {
  return {
    originator: ucan.payload.iss,
    expiresAt: ucan.payload.exp,
  }
}
