// https://whitepaper.fission.codes/access-control/ucan/jwt-authentication#attenuation
import * as util from "./util"
import { Capability } from "./types"
import { Chained } from "./chain"

export interface CapabilityChecker {

}

export interface EmailCapability {
  originator: string
  // expiresAt: number
  // notBefore?: number
  email: string
  potency: "SEND"
}

export function emailCapabilities(chain: Chained): EmailCapability[] {
  return chain.attenuation().flatMap(bareCap => {
    if (!isEmailCapability(bareCap)) {
      return []
    }

    // find the originator of of said capability
    const origin = findOrigin(chain, cap => isEmailCapability(cap) && cap.email === bareCap.email) ?? chain
    const originator = origin.issuer()
    return [{
      originator,
      email: bareCap.email,
      potency: bareCap.cap,
    }]
  })
}

/** @returns the ucan closest to a leaf that has a matching capability in its attenuations */
function findOrigin(chain: Chained, capabilityMatcher: (cap: Capability) => boolean): Chained | null {
  for (const proof of chain.proofs()) {
    for (const cap of proof.attenuation()) {
      if (capabilityMatcher(cap)) {
        return findOrigin(proof, capabilityMatcher) ?? proof
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
