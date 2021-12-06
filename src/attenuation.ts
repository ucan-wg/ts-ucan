// https://whitepaper.fission.codes/access-control/ucan/jwt-authentication#attenuation
import * as util from "./util"
import { Capability, Ucan } from "./types"
import { Chained } from "./chain"

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

    const matcher = (cap: Capability, ucan: Ucan<never>) => {
      if (isEmailCapability(cap) && cap.email === bareCap.email) {
        return {
          originator: ucan.payload.iss,
          expiresAt: ucan.payload.exp
        }
      }
    }

    const combine = (parent: CapabilityInfo, child: CapabilityInfo) => ({
      originator: parent.originator,
      expiresAt: Math.min(parent.expiresAt, child.expiresAt),
    } as CapabilityInfo)

    // TODO instead of that ??, move that fallback logic into findChain
    const info = findChain(chain, matcher, combine) ?? matcher(bareCap, chain.payload())

    return [{
      originator: info.originator,
      expiresAt: info.expiresAt,
      email: bareCap.email,
      potency: bareCap.cap,
    }]
  })
}

/** @returns the ucan closest to a leaf that has a matching capability in its attenuations */
function findChain<A>(
  chain: Chained,
  capabilityMatcher: (cap: Capability, chain: Ucan<never>) => A | null,
  combine: (parent: A, child: A) => A
): A | null {
  for (const proof of chain.proofs()) {
    for (const cap of proof.attenuation()) {
      const result = capabilityMatcher(cap, proof.payload())
      if (result != null) {
        const parentResult = findChain(proof, capabilityMatcher, combine)
        if (parentResult != null) {
          return combine(parentResult, result)
        } else {
          return result
        }
      }
    }
  }
  return null
}

function isEmailCapability(obj: Capability): obj is { email: string; cap: "SEND" } {
  return util.isRecord(obj)
    && util.hasProp(obj, "email") && typeof obj.email === "string"
    && util.hasProp(obj, "cap") && obj.cap === "SEND"
}
