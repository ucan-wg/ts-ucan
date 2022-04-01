import { Ability } from "../../src/capability/ability"
import { CapabilityResult } from "../../src/attenuation"
import { Capability } from "../../src/capability"
import { Chained } from "../../src/chained"
import { ResourcePointer } from "../../src/capability/resource-pointer"

import { capabilities, CapabilityEscalation, CapabilitySemantics } from "../../src/attenuation"

import * as abilities from "../../src/capability/ability"
import * as resourcePointers from "../../src/capability/resource-pointer"


// 🌸


export interface EmailCapability {
  with: ResourcePointer
  can: Ability
}



// 🏔


export const SEND_ABILITY: Ability = { namespace: "msg", segments: [ "SEND" ] }


export const EMAIL_SEMANTICS: CapabilitySemantics<EmailCapability> = {

  tryParsing(cap: Capability): EmailCapability | null {
    if (
      cap.with.scheme === "email" &&
      abilities.isEqual(cap.can, abilities.parse("msg/SEND"))
    ) {
      return cap
    }
    return null
  },

  tryDelegating<T extends EmailCapability>(parentCap: T, childCap: T): T | null | CapabilityEscalation<EmailCapability> {
    // ability is always "msg/SEND" anyway, so doesn't need to be checked
    return resourcePointers.isEqual(childCap.with, parentCap.with) ? childCap : null
  },

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


export function emailCapabilities(ucan: Chained): Iterable<CapabilityResult<EmailCapability>> {
  return capabilities(ucan, EMAIL_SEMANTICS)
}