// https://whitepaper.fission.codes/access-control/ucan/jwt-authentication#attenuation
import * as util from "./util"
import { Capability, Ucan } from "./types"
import { Chained } from "./chained"

export interface CapabilityChecker {

}

export interface EmailCapability {
  originator: string // DID
  expiresAt: number
  // notBefore?: number
  email: string
  potency: "SEND"
}

interface CapabilityInfo {
  originator: string // DID
  expiresAt: number
}

export function emailCapabilities(chain: Chained): EmailCapability[] {
  return chain.attenuation().flatMap(bareCap => {
    if (!isEmailCapability(bareCap)) {
      return []
    }

    const matchesEmailCapability = (cap: Capability, ucan: Ucan<never>) => {
      if (isEmailCapability(cap) && cap.email === bareCap.email) {
        return {
          originator: ucan.payload.iss,
          expiresAt: ucan.payload.exp
        }
      }
      return null
    }

    const matchAttenutation = (proof: Ucan<never>) => proof.payload.att.reduce(
      (acc: CapabilityInfo | null, cap: Capability) =>
        acc != null ? acc : matchesEmailCapability(cap, proof),
      null
    )

    const delegate = (ucan: Ucan<never>, delegatedInParent: Iterable<CapabilityInfo | null>) => {
      const child: CapabilityInfo | null = matchAttenutation(ucan)
      if (child == null) return null
      for (const parent of delegatedInParent) {
        if (parent != null) {
          return {
            originator: parent.originator,
            expiresAt: Math.min(parent.expiresAt, child.expiresAt),
          }
        }
      }
      return child
    }

    const info = chain.reduce(delegate)
    return info == null ? [] : [{
      originator: info.originator,
      expiresAt: info.expiresAt,
      email: bareCap.email,
      potency: bareCap.cap,
    }]
  })
}


function isEmailCapability(obj: Capability): obj is { email: string; cap: "SEND" } {
  return util.isRecord(obj)
    && util.hasProp(obj, "email") && typeof obj.email === "string"
    && util.hasProp(obj, "cap") && obj.cap === "SEND"
}
