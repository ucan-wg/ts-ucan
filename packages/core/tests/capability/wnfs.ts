import { Ability, isAbility } from "../../src/capability/ability"
import { Capability } from "../../src/capability"
import { DelegationSemantics, DelegatedCapability, DelegatedOwnership, rootIssuer } from "../../src/attenuation"
import { SUPERUSER } from "../../src/capability/super-user"
import { Ucan } from "../../src/types"
import { ResourcePointer } from "../../src/capability/resource-pointer"
import * as ucans from "../setup"


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


interface WnfsPublicResourcePointer {
  user: string // e.g. matheus23.fission.name
  publicPath: string[]
}

function tryParseWnfsPublicResource(pointer: ResourcePointer): WnfsPublicResourcePointer | null {
  if (pointer.scheme !== "wnfs") return null

  // remove trailing slash
  const path = pointer.hierPart.replace(/^\/\//, "")
  const trimmed = path.endsWith("/") ? path.slice(0, -1) : path
  const split = trimmed.split("/")
  const user = split[ 0 ]
  const publicPath = split.slice(2) // drop first two: matheus23.fission.name/public/keep/this
  if (user == null || split[ 1 ] !== "public") return null

  return {
    user,
    publicPath,
  }
}

export const wnfsPublicSemantics: DelegationSemantics = {

  canDelegateResource(parentResource, childResource) {
    const parent = tryParseWnfsPublicResource(parentResource)
    const child = tryParseWnfsPublicResource(childResource)

    if (parent == null || child == null) {
      return false
    }

    if (parent.user !== child.user) {
      return false
    }

    // parentCap path must be a prefix of childCap path
    if (child.publicPath.length < parent.publicPath.length) {
      return false
    }

    for (let i = 0; i < parent.publicPath.length; i++) {
      if (child.publicPath[ i ] !== parent.publicPath[ i ]) {
        return false
      }
    }

    return true
  },

  canDelegateAbility(parentAbility, childAbility) {
    const parent = wnfsAbilityFromAbility(parentAbility)
    const child = wnfsAbilityFromAbility(childAbility)

    if (parent == null || child == null) {
      return false
    }

    if (WNFS_ABILITY_LEVELS[ child ] > WNFS_ABILITY_LEVELS[ parent ]) {
      return false
    }

    return true
  }

}

export async function * wnfsPublicCapabilities(ucan: Ucan) {
  for await (const delegationChain of ucans.delegationChains(wnfsPublicSemantics, ucan)) {
    if (delegationChain instanceof Error || "ownershipDID" in delegationChain) {
      continue
    }
    yield {
      capability: delegationChain.capability,
      rootIssuer: rootIssuer(delegationChain),
    }
  }
}



///////////////////////////////
// Private WNFS Capabilities //
///////////////////////////////


interface WnfsPrivateResourcePointer {
  user: string
  requiredINumbers: Set<string>
}

function tryParseWnfsPrivateResource(pointer: ResourcePointer): WnfsPrivateResourcePointer | null {
  if (pointer.scheme !== "wnfs") return null

  // split up "boris.fission.name/private/fccXmZ8HYmpwxkvPSjwW9A" into "<user>/private/<inumberBase64url>"
  const split = pointer.hierPart.replace(/^\/\//, "").split("/")
  const user = split[ 0 ]
  const inumberBase64url = split[ 2 ]

  if (user == null || split[ 1 ] !== "private" || inumberBase64url == null) return null

  return {
    user,
    requiredINumbers: new Set([ inumberBase64url ]),
  }
}

const wnfsPrivateSemantics: DelegationSemantics = {

  canDelegateResource(parentResource, childResource) {
    const parent = tryParseWnfsPrivateResource(parentResource)
    const child = tryParseWnfsPrivateResource(childResource)

    if (parent == null || child == null) {
      return false
    }

    // There's more tests that need to be run on the resulting delegation chain.
    return true
  },

  canDelegateAbility(parentAbility, childAbility) {
    const parent = wnfsAbilityFromAbility(parentAbility)
    const child = wnfsAbilityFromAbility(childAbility)

    if (parent == null || child == null) {
      return false
    }

    if (WNFS_ABILITY_LEVELS[ child ] > WNFS_ABILITY_LEVELS[ parent ]) {
      return false
    }

    return true
  }

}

export async function * wnfsPrivateCapabilities(ucan: Ucan) {
  for await (const delegationChain of ucans.delegationChains(wnfsPrivateSemantics, ucan)) {
    if (delegationChain instanceof Error || "ownershipDID" in delegationChain) {
      continue
    }
    
    const requiredINumbers = new Set<string>()
    let chainStep: DelegatedCapability | DelegatedOwnership | undefined = delegationChain
    
    while (chainStep != null && "capability" in chainStep) {
      const hierSplit = chainStep.capability.with.hierPart.split("/")
      const inumber = hierSplit[hierSplit.length - 1]
      requiredINumbers.add(inumber)
      chainStep = chainStep.chainStep
    }

    yield {
      capability: delegationChain.capability,
      requiredINumbers,
      rootIssuer: rootIssuer(delegationChain),
    }
  }
}
