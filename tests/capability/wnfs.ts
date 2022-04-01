import { Ability, isAbility } from "../../src/capability/ability"
import { Capability } from "../../src/capability"
import { CapabilityEscalation, CapabilitySemantics, capabilities } from "../../src/attenuation"
import { Chained } from "../../src/chained"
import { SUPERUSER } from "../../src/capability/super-user"


export const WNFS_ABILITY_LEVELS = {
  "SUPER_USER": 0,
  "OVERWRITE": -1,
  "SOFT_DELETE": -2,
  "REVISE": -3,
  "CREATE": -4,
}

export const WNFS_ABILITIES: string[] = Object.keys(WNFS_ABILITY_LEVELS)

export type WnfsAbility = keyof typeof WNFS_ABILITY_LEVELS

export function isWnfsCap(cap: Capability): boolean {
  return cap.with.scheme === "wnfs" && isWnfsAbility(cap.can)
}

export function isWnfsAbility(ability: unknown): ability is WnfsAbility {
  if (!isAbility(ability)) return false
  if (ability === SUPERUSER) return true
  const abilitySegment = ability.segments[ 0 ]
  const isWnfsAbilitySegment = !!abilitySegment && WNFS_ABILITIES.includes(abilitySegment)
  return isWnfsAbilitySegment && ability.namespace.toLowerCase() === "wnfs"
}

export function wnfsAbilityFromAbility(ability: Ability): WnfsAbility | null {
  if (ability === SUPERUSER) return "SUPER_USER"
  if (isWnfsAbility(ability)) return ability.segments[ 0 ] as WnfsAbility
  return null
}

export function wnfsCapability(path: string, ability: WnfsAbility): Capability {
  return {
    with: { scheme: "wnfs", hierPart: path },
    can: { namespace: "wnfs", segments: [ ability ] }
  }
}



//////////////////////////////
// Public WNFS Capabilities //
//////////////////////////////


export interface WnfsPublicCapability {
  user: string // e.g. matheus23.fission.name
  publicPath: string[]
  ability: WnfsAbility
}

export const wnfsPublicSemantics: CapabilitySemantics<WnfsPublicCapability> = {

  /**
   * Example valid public wnfs capability:
   * ```js
   * {
   *   with: { scheme: "wnfs", hierPart: "//boris.fission.name/public/path/to/dir/or/file" },
   *   can: { namespace: "wnfs", segments: [ "OVERWRITE" ] }
   * }
   * ```
   */
  tryParsing(cap: Capability): WnfsPublicCapability | null {
    if (!isWnfsCap(cap)) return null

    // remove trailing slash
    const path = cap.with.hierPart.replace(/^\/\//, "")
    const trimmed = path.endsWith("/") ? path.slice(0, -1) : path
    const split = trimmed.split("/")
    const user = split[ 0 ]
    const publicPath = split.slice(2) // drop first two: matheus23.fission.name/public/keep/this
    if (user == null || split[ 1 ] !== "public") return null

    const ability = wnfsAbilityFromAbility(cap.can)
    if (!ability) return null

    return {
      user,
      publicPath,
      ability
    }
  },

  tryDelegating(parentCap: WnfsPublicCapability, childCap: WnfsPublicCapability): WnfsPublicCapability | null | CapabilityEscalation<WnfsPublicCapability> {
    // need to delegate the same user's file system
    if (childCap.user !== parentCap.user) return null

    // must not escalate capability level
    if (WNFS_ABILITY_LEVELS[ childCap.ability ] > WNFS_ABILITY_LEVELS[ parentCap.ability ]) {
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
      if (childCap.publicPath[ i ] !== parentCap.publicPath[ i ]) {
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



///////////////////////////////
// Private WNFS Capabilities //
///////////////////////////////


export interface WnfsPrivateCapability {
  user: string
  requiredINumbers: Set<string>
  ability: WnfsAbility
}

const wnfsPrivateSemantics: CapabilitySemantics<WnfsPrivateCapability> = {

  /**
   * Example valid private wnfs capability:
   *
   * ```js
   * {
   *   with: { scheme: "wnfs", hierPart: "//boris.fission.name/private/fccXmZ8HYmpwxkvPSjwW9A" },
   *   can: { namespace: "wnfs", segments: [ "OVERWRITE" ] }
   * }
   * ```
   */
  tryParsing(cap: Capability): WnfsPrivateCapability | null {
    if (!isWnfsCap(cap)) return null

    // split up "boris.fission.name/private/fccXmZ8HYmpwxkvPSjwW9A" into "<user>/private/<inumberBase64url>"
    const split = cap.with.hierPart.replace(/^\/\//, "").split("/")
    const user = split[ 0 ]
    const inumberBase64url = split[ 2 ]

    if (user == null || split[ 1 ] !== "private" || inumberBase64url == null) return null

    const ability = wnfsAbilityFromAbility(cap.can)
    if (!ability) return null

    return {
      user,
      requiredINumbers: new Set([ inumberBase64url ]),
      ability
    }
  },

  tryDelegating<T extends WnfsPrivateCapability>(parentCap: T, childCap: T): T | null | CapabilityEscalation<WnfsPrivateCapability> {
    // If the users don't match, these capabilities are unrelated.
    if (childCap.user !== parentCap.user) return null

    // This escalation *could* be wrong, but we shouldn't assume they're unrelated either.
    if (WNFS_ABILITY_LEVELS[ childCap.ability ] > WNFS_ABILITY_LEVELS[ parentCap.ability ]) {
      return {
        escalation: "Capability level escalation",
        capability: childCap,
      }
    }

    return {
      ...childCap,
      requiredINumbers: new Set([ ...childCap.requiredINumbers.values(), ...parentCap.requiredINumbers.values() ]),
    }
  },

}

export function wnfsPrivateCapabilities(ucan: Chained) {
  return capabilities(ucan, wnfsPrivateSemantics)
}
