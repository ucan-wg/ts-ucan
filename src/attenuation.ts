import * as token from "./token.js"
import { Capability } from "./capability/index.js"
import { Ucan } from "./types.js"
import { ResourcePointer } from "./capability/resource-pointer.js"
import { Ability } from "./capability/ability.js"
import { SUPERUSER, Superuser } from "./capability/super-user.js"


// TYPES


export interface CapabilitySemantics {
  canDelegateResource(parentResource: ResourcePointer, childResource: ResourcePointer): boolean
  canDelegateAbility(parentAbility: Ability, childAbility: Ability): boolean
}


export type DelegationChain
  = DelegatedCapability
  | DelegatedOwnership


export interface DelegatedCapability {
  capability: Capability
  ucan: Ucan
  // will probably become an array in the future due to rights amplification
  chainStep?: DelegationChain
}

export interface DelegatedOwnership {
  ownershipDID: string
  scope: OwnershipScope
  ucan: Ucan
  chainStep?: DelegatedOwnership
}


export type OwnershipScope
  = Superuser
  | { scheme: string; ability: Ability }



// FUNCTIONS


export async function* delegationChains(
  semantics: CapabilitySemantics,
  ucan: Ucan,
  isRevoked: (ucan: Ucan) => Promise<boolean> = async () => false
): AsyncIterable<DelegationChain | Error> {

  if (await isRevoked(ucan)) {
    yield new Error(`UCAN Revoked: ${token.encode(ucan)}`)
    return
  }

  yield* capabilitiesFromParenthood(ucan)
  yield* capabilitiesFromDelegation(semantics, ucan, isRevoked)
}


export function rootIssuer(delegationChain: DelegationChain): string {
  if ("capability" in delegationChain) {
    return delegationChain.chainStep == null
      ? delegationChain.ucan.payload.iss
      : rootIssuer(delegationChain.chainStep)
  }
  return delegationChain.ownershipDID
}


export const equalCanDelegate: CapabilitySemantics = {
  canDelegateResource(parentResource, childResource) {
    if (parentResource.scheme !== childResource.scheme) {
      return false
    }

    if (parentResource.hierPart === SUPERUSER) {
      return true
    }
    if (childResource.hierPart === SUPERUSER) {
      return false
    }

    return parentResource.hierPart === childResource.hierPart
  },

  canDelegateAbility(parentAbility, childAbility) {
    if (parentAbility === SUPERUSER) {
      return true
    }
    if (childAbility === SUPERUSER) {
      return false
    }

    if (parentAbility.namespace !== childAbility.namespace) {
      return false
    }

    // Array equality
    if (parentAbility.segments.length !== childAbility.segments.length) {
      return false
    }
    return parentAbility.segments.reduce(
      (acc, v, i) => acc && childAbility.segments[ i ] === v,
      true as boolean
    )
  },
}


export function capabilityCanBeDelegated(
  semantics: CapabilitySemantics,
  capability: Capability,
  fromDelegationChain: DelegationChain,
): boolean {
  if ("capability" in fromDelegationChain) {
    return canDelegate(semantics, fromDelegationChain.capability, capability)
  }
  const ownershipScope = fromDelegationChain.scope
  if (ownershipScope === SUPERUSER) {
    return true
  }
  return ownershipScope.scheme == capability.with.scheme
    && semantics.canDelegateAbility(ownershipScope.ability, capability.can)
}


export function ownershipCanBeDelegated(
  semantics: CapabilitySemantics,
  did: string,
  scope: OwnershipScope,
  fromDelegationChain: DelegatedOwnership
): boolean {
  if (did !== fromDelegationChain.ownershipDID) {
    return false
  }

  const parentScope = fromDelegationChain.scope

  // parent OwnershipScope can delegate child OwnershipScope

  if (parentScope === SUPERUSER) {
    return true
  }
  if (scope === SUPERUSER) {
    return false
  }
  return parentScope.scheme === scope.scheme
    && semantics.canDelegateAbility(parentScope.ability, scope.ability)
}



// ㊙️ Internal


function* capabilitiesFromParenthood(ucan: Ucan): Iterable<DelegationChain> {
  for (const capability of ucan.payload.att) {
    switch (capability.with.scheme.toLowerCase()) {
      // If it's a "my" capability, it'll indicate an ownership delegation
      case "my": {
        const scope = capability.with.hierPart === SUPERUSER
          ? SUPERUSER
          : { scheme: capability.with.hierPart, ability: capability.can }

        yield {
          ownershipDID: ucan.payload.iss,
          scope,
          ucan,
        }
        break
      }
      // if it's another known capability, we can ignore them
      // (they're not introduced by parenthood)
      case "as":
      case "prf":
        break
      // otherwise we assume it's a normal parenthood capability introduction
      default:
        yield { capability, ucan }
    }
  }
}


async function* capabilitiesFromDelegation(
  semantics: CapabilitySemantics,
  ucan: Ucan,
  isRevoked: (ucan: Ucan) => Promise<boolean>
): AsyncIterable<DelegationChain | Error> {

  let proofIndex = 0

  for await (const proof of token.validateProofs(ucan)) {
    if (proof instanceof Error) {
      yield proof
      continue
    }

    for (const capability of ucan.payload.att) {
      try {
        switch (capability.with.scheme.toLowerCase()) {
          case "my": continue // cannot be delegated, only introduced by parenthood.
          case "as": {
            yield* handleAsDelegation(semantics, capability, ucan, proof, isRevoked)
            break
          }
          case "prf": {
            yield* handlePrfDelegation(semantics, capability, ucan, proof, proofIndex, isRevoked)
            break
          }
          default: {
            yield* handleNormalDelegation(semantics, capability, ucan, proof, isRevoked)
          }
        }
      } catch (e) {
        yield error(e)
      }
    }

    proofIndex++
  }

  function error(e: unknown): Error {
    if (e instanceof Error) {
      return e
    } else {
      return new Error(`Error during capability delegation checking: ${e}`)
    }
  }
}


async function* handleAsDelegation(
  semantics: CapabilitySemantics,
  capability: Capability,
  ucan: Ucan,
  proof: Ucan,
  isRevoked: (ucan: Ucan) => Promise<boolean>
): AsyncIterable<DelegatedOwnership | Error> {
  const split = capability.with.hierPart.split(":")
  const scheme = split[ split.length - 1 ]
  const ownershipDID = split.slice(0, -1).join(":")
  const scope = scheme === SUPERUSER
    ? SUPERUSER
    : { scheme, ability: capability.can }

  for await (const delegationChain of delegationChains(semantics, proof, isRevoked)) {
    if (delegationChain instanceof Error) {
      yield delegationChain
      continue
    }
    if (!("ownershipDID" in delegationChain)) {
      continue
    }
    if (ownershipCanBeDelegated(
      semantics,
      ownershipDID,
      scope,
      delegationChain
    )) {
      yield {
        ownershipDID,
        scope,
        ucan,
        chainStep: delegationChain
      }
    }
  }
}


async function* handlePrfDelegation(
  semantics: CapabilitySemantics,
  capability: Capability,
  ucan: Ucan,
  proof: Ucan,
  proofIndex: number,
  isRevoked: (ucan: Ucan) => Promise<boolean>
): AsyncIterable<DelegatedCapability | Error> {
  if (
    capability.with.hierPart !== SUPERUSER
    && parseInt(capability.with.hierPart, 10) !== proofIndex
  ) {
    // if it's something like prf:2, we need to make sure that
    // we only process the delegation if proofIndex === 2
    return
  }
  for await (const delegationChain of delegationChains(semantics, proof, isRevoked)) {
    if (delegationChain instanceof Error) {
      yield delegationChain
      continue
    }
    if (!("capability" in delegationChain)) {
      continue
    }
    yield {
      capability: delegationChain.capability,
      ucan,
      chainStep: delegationChain
    }
  }
}


async function* handleNormalDelegation(
  semantics: CapabilitySemantics,
  capability: Capability,
  ucan: Ucan,
  proof: Ucan,
  isRevoked: (ucan: Ucan) => Promise<boolean>
): AsyncIterable<DelegatedCapability | Error> {
  for await (const delegationChain of delegationChains(semantics, proof, isRevoked)) {
    if (delegationChain instanceof Error) {
      yield delegationChain
      continue
    }
    if (!capabilityCanBeDelegated(semantics, capability, delegationChain)) {
      continue
    }
    yield {
      capability,
      ucan,
      chainStep: delegationChain
    }
  }
}


function canDelegate(
  semantics: CapabilitySemantics,
  parentCapability: Capability,
  childCapability: Capability,
): boolean {
  return semantics.canDelegateResource(parentCapability.with, childCapability.with)
    && semantics.canDelegateAbility(parentCapability.can, childCapability.can)
}

