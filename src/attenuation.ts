import * as token from "./token.js"
import * as semver from "./semver.js"
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

function canDelegate(
  semantics: CapabilitySemantics,
  parentCapability: Capability,
  childCapability: Capability,
): boolean {
  return semantics.canDelegateResource(parentCapability.with, childCapability.with)
    && semantics.canDelegateAbility(parentCapability.can, childCapability.can)
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
  chain: Array<{
    scope: OwnershipScope
    ucan: Ucan
  }>
}

export type OwnershipScope
  = Superuser
  | { scheme: string; ability: Ability }


// FUNCTIONS

export function rootIssuer(delegationChain: DelegationChain): string {
  if ("capability" in delegationChain) {
    return delegationChain.chainStep == null
      ? delegationChain.ucan.payload.iss
      : rootIssuer(delegationChain.chainStep)
  }
  return delegationChain.ownershipDID
}


export function capabilityCanBeDelegated(
  semantics: CapabilitySemantics,
  capability: Capability,
  fromDelegationChain: DelegationChain,
): boolean {
  if ("capability" in fromDelegationChain) {
    return canDelegate(semantics, fromDelegationChain.capability, capability)
  }
  if (fromDelegationChain.chain.length <= 0) {
    throw new Error(`Invalid delegation chain with zero entries: ${JSON.stringify(fromDelegationChain)}`)
  }
  const ownershipScope = fromDelegationChain.chain[0].scope
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
  if (fromDelegationChain.chain.length <= 0) {
    throw new Error(`Invalid delegation chain with zero entries: ${JSON.stringify(fromDelegationChain)}`)
  }

  if (did !== fromDelegationChain.ownershipDID) {
    return false
  }

  const parentScope = fromDelegationChain.chain[0].scope

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

export async function* delegationChains(
  semantics: CapabilitySemantics,
  ucan: Ucan,
): AsyncIterable<DelegationChain | Error> {
  yield* capabilitiesFromParenthood(ucan)
  yield* capabilitiesFromDelegation(semantics, ucan)
}

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
          chain: [{
            scope,
            ucan,
          }]
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
): AsyncIterable<DelegationChain | Error> {

  let proofIndex = 0

  for (const prf of ucan.payload.prf) {
    try {
      const proof = await token.validate(prf)

      checkDelegation(ucan, proof)

      for (const capability of ucan.payload.att) {
        try {
          switch (capability.with.scheme.toLowerCase()) {
            case "my": continue // cannot be delegated, only introduced by parenthood.
            case "as": {
              const split = capability.with.hierPart.split(":")
              const scheme = split[split.length - 1]
              const ownershipDID = split.slice(0, -1).join(":")
              const scope = scheme === SUPERUSER
                ? SUPERUSER
                : { scheme, ability: capability.can }

              for await (const delegationChain of delegationChains(semantics, proof)) {
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
                    chain: [{
                      scope,
                      ucan,
                    }, ...delegationChain.chain]
                  }
                }
              }
              break
            }
            case "prf": {
              if (
                capability.with.hierPart !== SUPERUSER
                && parseInt(capability.with.hierPart, 10) !== proofIndex
              ) {
                // if it's something like prf:2, we need to make sure that
                // we only process the delegation if proofIndex === 2
                continue
              }
              for await (const delegationChain of delegationChains(semantics, proof)) {
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
              break
            }
            default: {
              for await (const delegationChain of delegationChains(semantics, proof)) {
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
          }
        } catch (e) {
          yield error(e)
        }
      }

      proofIndex++

    } catch (e) {
      yield error(e)
    }
  }

  function error(e: unknown): Error {
    if (e instanceof Error) {
      return e
    } else {
      return new Error(`Error during capability delegation checking: ${e}`)
    }
  }
}

function checkDelegation(ucan: Ucan, proof: Ucan) {
  if (ucan.payload.iss !== proof.payload.aud) {
    throw new Error(`Invalid Proof: Issuer ${ucan.payload.iss} doesn't match parent's audience ${proof.payload.aud}`)
  }
  if (proof.payload.nbf != null && ucan.payload.exp > proof.payload.nbf) {
    throw new Error(`Invalid Proof: 'Not before' (${proof.payload.nbf}) is after parent's expiration (${ucan.payload.exp})`)
  }

  if (ucan.payload.nbf != null && ucan.payload.nbf > proof.payload.exp) {
    throw new Error(`Invalid Proof: Expiration (${proof.payload.exp}) is before parent's 'not before' (${ucan.payload.nbf})`)
  }
  if (semver.lt(ucan.header.ucv, proof.header.ucv)) {
    throw new Error(`Invalid Proof: Version (${proof.header.ucv}) is higher than parent's version (${ucan.header.ucv})`)
  }
}


interface CapInfo {
  originator: string
  notBefore?: number
  expiresAt: number
}

export async function hasCapability(
  semantics: CapabilitySemantics,
  cap: { capability: Capability; info: CapInfo },
  ucan: Ucan
): Promise<false | { capability: Capability; info: CapInfo }> {
  if (cap.info.expiresAt > ucan.payload.exp) {
    return false
  }
  if (cap.info.notBefore != null) {
    if (ucan.payload.nbf == null) {
      return false
    }
    if (cap.info.notBefore < ucan.payload.nbf) {
      return false
    }
  }

  for await (const delegationChain of delegationChains(semantics, ucan)) {
    if (delegationChain instanceof Error) {
      continue
    }
    if (capabilityCanBeDelegated(semantics, cap.capability, delegationChain)) {
      const originator = rootIssuer(delegationChain)
      if (originator !== cap.info.originator) {
        continue
      }
      return {
        capability: cap.capability,
        info: {
          originator,
          notBefore: ucan.payload.nbf,
          expiresAt: ucan.payload.exp,
        }
      }
    }
  }

  return false
}

// semantics based on the idea "you can delegate something if it's the same capability"
export const equalitySemantics: CapabilitySemantics = {
  canDelegateResource(parentResource, resource) {
    return JSON.stringify(parentResource) === JSON.stringify(resource)
  },

  canDelegateAbility(parentAbility, ability) {
    if (parentAbility === SUPERUSER) {
      return true
    }
    if (ability === SUPERUSER) {
      return false
    }
    return JSON.stringify(parentAbility) === JSON.stringify(ability)
  }
}
