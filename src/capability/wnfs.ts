import { Capability } from "../types"
import { capabilities, CapabilityEscalation, CapabilitySemantics } from "../attenuation"
import { Chained } from "../chained"


export const wnfsCapLevels = {
  "SUPER_USER": 0,
  "OVERWRITE": -1,
  "SOFT_DELETE": -2,
  "REVISE": -3,
  "CREATE": -4,
}

export type WnfsCap = keyof typeof wnfsCapLevels

export function isWnfsCap(obj: unknown): obj is WnfsCap {
  return typeof obj === "string" && Object.keys(wnfsCapLevels).includes(obj)
}

export interface WnfsPublicCapability {
  user: string // e.g. matheus23.fission.name
  publicPath: string[]
  cap: WnfsCap
}

export const wnfsPublicSemantics: CapabilitySemantics<WnfsPublicCapability> = {

  parse(cap: Capability): WnfsPublicCapability | null {
    if (typeof cap.wnfs === "string" && isWnfsCap(cap.cap)) {
      // remove trailing slash
      const trimmed = cap.wnfs.endsWith("/") ? cap.wnfs.slice(0, -1) : cap.wnfs
      const split = trimmed.split("/")
      const user = split[0]
      const publicPath = split.slice(2) // drop first two: matheus23.fission.name/public/keep/this
      if (user == null || split[1] !== "public") return null
      return {
        user,
        publicPath,
        cap: cap.cap,
      }
    }
    return null
  },

  toCapability(parsed: WnfsPublicCapability): Capability {
    return {
      wnfs: `${parsed.user}/public/${parsed.publicPath.join("/")}`,
      cap: parsed.cap,
    }
  },

  tryDelegating<T extends WnfsPublicCapability>(parentCap: T, childCap: T): T | null | CapabilityEscalation<WnfsPublicCapability> {
    // need to delegate the same user's file system
    if (childCap.user !== parentCap.user) return null

    // must not escalate capability level
    if (wnfsCapLevels[childCap.cap] > wnfsCapLevels[parentCap.cap]) {
      return escalation("Capability level escalation", childCap)
    }

    // parentCap path must be a prefix of childCap path
    if (childCap.publicPath.length < parentCap.publicPath.length) {
      return escalation("WNFS Public path access escalation", childCap)
    }

    for (let i = 0; i < parentCap.publicPath.length; i++) {
      if (childCap.publicPath[i] !== parentCap.publicPath[i]) {
        return escalation("WNFS Public path access escalation", childCap)
      }
    }

    return childCap
  },

}

function escalation<T extends WnfsPublicCapability>(reason: string, cap: T): CapabilityEscalation<WnfsPublicCapability> {
  return {
    escalation: reason,
    capability: { user: cap.user, publicPath: cap.publicPath, cap: cap.cap }
  }
}

export function wnfsPublicCapabilities(ucan: Chained) {
  return capabilities(ucan, wnfsPublicSemantics)
}
