import * as token from "./token.js"
import Plugins from "./plugins.js"
import { Capability } from "./capability/index.js"
import { Ucan } from "./types.js"
import { ResourcePointer } from "./capability/resource-pointer.js"
import { Ability } from "./capability/ability.js"
import { SUPERUSER, Superuser } from "./capability/super-user.js"


// TYPES


/**
 * UCAN capabilities can have arbitrary semantics for delegation.
 * These semantics can be configured via this record of functions.
 * 
 * In most cases you may just want to use `equalCanDelegate` as your semantics,
 * but sometimes you want e.g. path behavior for a file-system-like resource:
 * `path:/parent/` should be able to delegate access to `path:/parent/child/`.
 */
export interface DelegationSemantics {
  /**
   * Whether a parent resource can delegate a child resource.
   * 
   * An implementation may for example decide to return true for
   * `canDelegateResource(resourcePointer.parse("path:/parent/"), resourcePointer.parse("path:/parent/child/"))`
   */
  canDelegateResource(parentResource: ResourcePointer, childResource: ResourcePointer): boolean
  /**
   * Whether a parent ability can delegate a child ability.
   * 
   * An implementation may for example decide to return true for
   * `canDelegateAbility(ability.parse("crud/UPDATE"), ability.parse("crud/CREATE"))`
   */
  canDelegateAbility(parentAbility: Ability, childAbility: Ability): boolean
}


/**
 * A delegation chain for a delegated capability or delegated ownership.
 * 
 * This type represents a valid path of delegations through a UCAN.
 * 
 * It can be cached as a sort of "witness" that a UCAN actually delegates a particular capability.
 *
 * Or it can be scanned to look for UCANs that may have become invalid due to revocation.
 */
export type DelegationChain
  = DelegatedCapability
  | DelegatedOwnership


/**
 * A delegation chain that ends with a concrete capability.
 */
export interface DelegatedCapability {
  /**
   * The capability that the end of the chain grants.
   */
  capability: Capability
  /**
   * The specific UCAN in the chain witnessing the delegated capability.
   */
  ucan: Ucan
  // will probably become an array in the future due to rights amplification
  /**
   * The rest of the delegation chain. This may include entries
   * for `DelegatedOwnership`.
   */
  chainStep?: DelegationChain
}

/**
 * A delegation chain that ends with delegated ownership.
 * 
 * This is ownership over a specific DID at a certain resource and ability scope.
 */
export interface DelegatedOwnership {
  /**
   * The DID that ownership is delegated for.
   */
  ownershipDID: string
  /**
   * The kinds of capabilites that can be delegated from the ownership.
   */
  scope: OwnershipScope
  /**
   * The specific UCAN in the chain witnessing the delegated ownership.
   */
  ucan: Ucan
  /**
   * The rest of the ownership delegation chain.
   */
  chainStep?: DelegatedOwnership
}


/**
 * This describes the scope of capabilities that are allowed to be delegated
 * from delegated ownership.
 */
export type OwnershipScope
  = Superuser
  | { scheme: string; ability: Ability }



// FUNCTIONS


/**
 * This computes all possible delegations from given UCAN with given
 * capability delegation semantics.
 * 
 * For each entry in the attenuations array of the UCAN there will be at least
 * one delegation chain.
 * 
 * These delegation chains are computed lazily, so that if parts of the UCAN have
 * been revoked or can't be loaded, this doesn't keep this function from figuring
 * out different ways of delegating a capability from the attenuations.
 * It also makes it possible to return early if a valid delegation chain has been found.
 */
export const delegationChains = (plugins: Plugins) =>
  async function* ( 
    semantics: DelegationSemantics,
    ucan: Ucan,
    isRevoked: (ucan: Ucan) => Promise<boolean> = async () => false,
  ): AsyncIterable<DelegationChain | Error> {

  if (await isRevoked(ucan)) {
    yield new Error(`UCAN Revoked: ${token.encode(ucan)}`)
    return
  }

  yield* capabilitiesFromParenthood(ucan)
  yield* capabilitiesFromDelegation(plugins, semantics, ucan, isRevoked)
}


/**
 * Figures out the implied root issuer from a delegation chain.
 * 
 * For a given delegation chain this will give you the DID of who
 * "started" the chain, so who claims to be the "owner" of said capability.
 */
export function rootIssuer(delegationChain: DelegationChain): string {
  if ("capability" in delegationChain) {
    return delegationChain.chainStep == null
      ? delegationChain.ucan.payload.iss
      : rootIssuer(delegationChain.chainStep)
  }
  return delegationChain.ownershipDID
}


/**
 * The default delegation semantics.
 * This will just allow equal capabilities to be delegated,
 * except that it also accounts for superuser abilities.
 */
export const equalCanDelegate: DelegationSemantics = {
  canDelegateResource(parentResource, childResource) {
    if (parentResource.scheme !== childResource.scheme) {
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
  semantics: DelegationSemantics,
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
  semantics: DelegationSemantics,
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
  plugins: Plugins,
  semantics: DelegationSemantics,
  ucan: Ucan,
  isRevoked: (ucan: Ucan) => Promise<boolean>,
): AsyncIterable<DelegationChain | Error> {

  let proofIndex = 0

  for await (const proof of token.validateProofs(plugins)(ucan)) {
    if (proof instanceof Error) {
      yield proof
      continue
    }

    for (const capability of ucan.payload.att) {
      try {
        switch (capability.with.scheme.toLowerCase()) {
          case "my": continue // cannot be delegated, only introduced by parenthood.
          case "as": {
            yield* handleAsDelegation(plugins, semantics, capability, ucan, proof, isRevoked)
            break
          }
          case "prf": {
            yield* handlePrfDelegation(plugins, semantics, capability, ucan, proof, proofIndex, isRevoked)
            break
          }
          default: {
            yield* handleNormalDelegation(plugins, semantics, capability, ucan, proof, isRevoked)
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
  plugins: Plugins,
  semantics: DelegationSemantics,
  capability: Capability,
  ucan: Ucan,
  proof: Ucan,
  isRevoked: (ucan: Ucan) => Promise<boolean>,
): AsyncIterable<DelegatedOwnership | Error> {
  const split = capability.with.hierPart.split(":")
  const scheme = split[ split.length - 1 ]
  const ownershipDID = split.slice(0, -1).join(":")
  const scope = scheme === SUPERUSER
    ? SUPERUSER
    : { scheme, ability: capability.can }

  for await (const delegationChain of delegationChains(plugins)(semantics, proof, isRevoked)) {
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
  plugins: Plugins,
  semantics: DelegationSemantics,
  capability: Capability,
  ucan: Ucan,
  proof: Ucan,
  proofIndex: number,
  isRevoked: (ucan: Ucan) => Promise<boolean>,
): AsyncIterable<DelegatedCapability | Error> {
  if (
    capability.with.hierPart !== SUPERUSER
    && parseInt(capability.with.hierPart, 10) !== proofIndex
  ) {
    // if it's something like prf:2, we need to make sure that
    // we only process the delegation if proofIndex === 2
    return
  }
  for await (const delegationChain of delegationChains(plugins)(semantics, proof, isRevoked)) {
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
  plugins: Plugins,
  semantics: DelegationSemantics,
  capability: Capability,
  ucan: Ucan,
  proof: Ucan,
  isRevoked: (ucan: Ucan) => Promise<boolean>,
): AsyncIterable<DelegatedCapability | Error> {
  for await (const delegationChain of delegationChains(plugins)(semantics, proof, isRevoked)) {
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
  semantics: DelegationSemantics,
  parentCapability: Capability,
  childCapability: Capability,
): boolean {
  return semantics.canDelegateResource(parentCapability.with, childCapability.with)
    && semantics.canDelegateAbility(parentCapability.can, childCapability.can)
}

