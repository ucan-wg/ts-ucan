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

export interface EmailCapability extends CapabilityInfo {
  email: string
  potency: "SEND"
}

function isEmailCap(obj: Capability): obj is { email: string; cap: "SEND" } {
  return util.isRecord(obj)
    && util.hasProp(obj, "email") && typeof obj.email === "string"
    && util.hasProp(obj, "cap") && obj.cap === "SEND"
}

export function* emailCapabilities(ucan: Chained): Iterable<EmailCapability> {
  const parseCap = (cap: Capability, ucan: Ucan<never>) => {
    if (isEmailCap(cap)) {
      return {
        originator: ucan.payload.iss,
        expiresAt: ucan.payload.exp,
        email: cap.email,
        potency: cap.cap,
      } as EmailCapability
    }
    return null
  }

  const findParsedCaps = function* (ucan: Ucan<never>) {
    for (const cap of ucan.payload.att) {
      const emailCap = parseCap(cap, ucan)
      if (emailCap != null) yield emailCap as EmailCapability
    }
  }

  const isCapabilityLessThan = (childCap: EmailCapability, parentCap: EmailCapability) => {
    return childCap.email === parentCap.email // potency is always "SEND" anyway, so doesn't need to be checked
  }

  const delegate = (ucan: Ucan<never>, delegatedInParent: () => Iterable<() => Iterable<EmailCapability>>) => {
    return function* () {
      for (const parsedChildCap of findParsedCaps(ucan)) {
        let isCoveredByProof = false
        for (const parent of delegatedInParent()) {
          for (const parsedParentCap of parent()) {
            isCoveredByProof = true
            if (isCapabilityLessThan(parsedChildCap, parsedParentCap)) {
              yield ({
                ...parsedChildCap,
                originator: parsedParentCap.originator,
                expiresAt: Math.min(parsedParentCap.expiresAt, parsedChildCap.expiresAt),
              })
            } else {
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
