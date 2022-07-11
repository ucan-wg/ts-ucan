import * as ucans from "../../src"
import {
  Ucan, 
  DelegationSemantics,
  Ability,
  Capability,
  ResourcePointer
} from "../../src"

// 🌸


export interface EmailCapability {
  with: ResourcePointer
  can: Ability
}



// 🏔


export const SEND_ABILITY: Ability = { namespace: "msg", segments: [ "SEND" ] }


export const EMAIL_SEMANTICS: DelegationSemantics = {

  canDelegateResource(parentResource, resource) {
    if (parentResource.scheme !== "email") {
      return false
    }
    if (resource.scheme !== "email") {
      return false
    }
    return parentResource.hierPart === resource.hierPart
  },

  canDelegateAbility(parentAbility, ability) {
    if (parentAbility === ucans.SUPERUSER) {
      return true
    }
    if (ability === ucans.SUPERUSER) {
      return false
    }
    return parentAbility.namespace === "msg"
      && parentAbility.segments.length === 1
      && parentAbility.segments[0] === "SEND"
      && ability.namespace === "msg"
      && ability.segments.length === 1
      && ability.segments[0] === "SEND"
  }

}



// 🛠


export function emailResourcePointer(emailAddress: string): ResourcePointer {
  return { scheme: "email", hierPart: emailAddress }
}


export function emailCapability(emailAddress: string): Capability {
  return {
    with: emailResourcePointer(emailAddress),
    can: SEND_ABILITY
  }
}


export async function * emailCapabilities(ucan: Ucan): AsyncIterable<{ capability: EmailCapability; rootIssuer: string }> {
  for await (const delegationChain of ucans.delegationChains(EMAIL_SEMANTICS, ucan)) {
    if (delegationChain instanceof Error || "ownershipDID" in delegationChain) {
      continue
    }
    yield {
      rootIssuer: ucans.rootIssuer(delegationChain),
      capability: delegationChain.capability
    }
  }
}
