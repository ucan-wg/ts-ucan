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



/////////////////////////////
// Public WNFS Capabilities
/////////////////////////////


export interface WnfsPublicCapability {
  user: string // e.g. matheus23.fission.name
  publicPath: string[]
  cap: WnfsCap
}

export const wnfsPublicSemantics: CapabilitySemantics<WnfsPublicCapability> = {

  /**
   * Example valid public wnfs capability:
   * ```js
   * {
   *   wnfs: "boris.fission.name/public/path/to/dir/or/file",
   *   cap: "OVERWRITE"
   * }
   * ```
   */
  tryParsing(cap: Capability): WnfsPublicCapability | null {
    if (typeof cap.wnfs !== "string" || !isWnfsCap(cap.cap)) return null

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
  },

  tryDelegating(parentCap: WnfsPublicCapability, childCap: WnfsPublicCapability): WnfsPublicCapability | null | CapabilityEscalation<WnfsPublicCapability> {
    // need to delegate the same user's file system
    if (childCap.user !== parentCap.user) return null

    // must not escalate capability level
    if (wnfsCapLevels[childCap.cap] > wnfsCapLevels[parentCap.cap]) {
      return {
        escalation: "Capability level escalation",
        capability: childCap,
      }
    }

    // parentCap path must be a prefix of childCap path
    if (childCap.publicPath.length < parentCap.publicPath.length) {
      return {
        escalation: "WNFS Public path access escalation",
        capability: childCap,
      }
    }

    for (let i = 0; i < parentCap.publicPath.length; i++) {
      if (childCap.publicPath[i] !== parentCap.publicPath[i]) {
        return {
          escalation: "WNFS Public path access escalation",
          capability: childCap,
        }
      }
    }

    return childCap
  },

}

export function wnfsPublicCapabilities(ucan: Chained) {
  return capabilities(ucan, wnfsPublicSemantics)
}



/////////////////////////////
// Private WNFS Capabilities
/////////////////////////////


export interface WnfsPrivateCapability {
  user: string
  requiredINumbers: Set<string>
  cap: WnfsCap
}

const wnfsPrivateSemantics: CapabilitySemantics<WnfsPrivateCapability> = {

  /**
   * Example valid private wnfs capability:
   * 
   * ```js
   * {
   *   wnfs: "boris.fission.name/private/fccXmZ8HYmpwxkvPSjwW9A",
   *   cap: "OVERWRITE"
   * }
   * ```
   */
  tryParsing(cap: Capability): WnfsPrivateCapability | null {
    if (typeof cap.wnfs !== "string" || !isWnfsCap(cap.cap)) return null

    // split up "boris.fission.name/private/fccXmZ8HYmpwxkvPSjwW9A" into "<user>/private/<inumberBase64url>"
    const split = cap.wnfs.split("/")
    const user = split[0]
    const inumberBase64url = split[2]
    
    if (user == null || split[1] !== "private" || inumberBase64url == null) return null

    return {
      user,
      requiredINumbers: new Set([inumberBase64url]),
      cap: cap.cap,
    }
  },

  tryDelegating<T extends WnfsPrivateCapability>(parentCap: T, childCap: T): T | null | CapabilityEscalation<WnfsPrivateCapability> {
    // If the users don't match, these capabilities are unrelated.
    if (childCap.user !== parentCap.user) return null

    // This escalation *could* be wrong, but we shouldn't assume they're unrelated either.
    if (wnfsCapLevels[childCap.cap] > wnfsCapLevels[parentCap.cap]) {
      return {
        escalation: "Capability level escalation",
        capability: childCap,
      }
    }

    return {
      ...childCap,
      requiredINumbers: new Set([...childCap.requiredINumbers.values(), ...parentCap.requiredINumbers.values()]),
    }
  },

}

export function wnfsPrivateCapabilities(ucan: Chained) {
  return capabilities(ucan, wnfsPrivateSemantics)
}
