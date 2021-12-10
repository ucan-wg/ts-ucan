// https://whitepaper.fission.codes/access-control/ucan/jwt-authentication#attenuation
import * as util from "./util"
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


export function* emailCapabilities(ucan: Chained): Iterable<EmailCapability> {
  const parseCap = (cap: Capability): EmailCapability | null => {
    if (typeof cap.email === "string" && cap.cap === "SEND") {
      return {
        email: cap.email,
        potency: cap.cap,
      }
    }
    return null
  }

  const parseCapabilityInfo = (ucan: Ucan<never>): CapabilityInfo => ({
    originator: ucan.payload.iss,
    expiresAt: ucan.payload.exp,
  })

  function* findParsingCaps(ucan: Ucan<never>): Iterable<EmailCapability & CapabilityInfo> {
    const capInfo = parseCapabilityInfo(ucan)
    for (const cap of ucan.payload.att) {
      const parsedCap = parseCap(cap)
      if (parsedCap != null) yield { ...parsedCap, ...capInfo }
    }
  }

  const delegateEmailCap = (childCap: EmailCapability, parentCap: EmailCapability): EmailCapability | null => {
    // potency is always "SEND" anyway, so doesn't need to be checked
    return childCap.email === parentCap.email ? childCap : null
  }

  const delegateInfo = <A extends CapabilityInfo>(childCap: A, parentCap: A): A => {
    return {
      ...childCap,
      originator: parentCap.originator,
      expiresAt: Math.min(childCap.expiresAt, parentCap.expiresAt),
    }
  }

  const delegate = (ucan: Ucan<never>, delegatedInParent: () => Iterable<() => Iterable<EmailCapability & CapabilityInfo>>) => {
    return function* () {
      for (const parsedChildCap of findParsingCaps(ucan)) {
        let isCoveredByProof = false
        for (const parent of delegatedInParent()) {
          for (const parsedParentCap of parent()) {
            isCoveredByProof = true
            const delegated = delegateEmailCap(parsedChildCap, parsedParentCap)
            if (delegated != null) {
              yield delegateInfo({ ...parsedChildCap, ...delegated }, parsedParentCap)
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
