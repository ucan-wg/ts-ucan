import * as ability from "./capability/ability"
import * as resourcePointer from "./capability/resource-pointer"
import * as superUser from "./capability/super-user"
import * as util from "./util"

import { Ability, isAbility } from "./capability/ability"
import { ResourcePointer, isResourcePointer } from "./capability/resource-pointer"
import { Superuser, SUPERUSER } from "./capability/super-user"


// RE-EXPORTS


export { ability, resourcePointer, superUser }



// 💎


export type Capability = {
  with: ResourcePointer
  can: Ability
}

export type EncodedCapability = {
  with: string
  can: string
}



// TYPE CHECKS


export function isCapability(obj: unknown): obj is Capability {
  return util.isRecord(obj)
    && util.hasProp(obj, "with") && isResourcePointer(obj.with)
    && util.hasProp(obj, "can") && isAbility(obj.can)
}

export function isEncodedCapability(obj: unknown): obj is EncodedCapability {
  return util.isRecord(obj)
    && util.hasProp(obj, "with") && typeof obj.with === "string"
    && util.hasProp(obj, "can") && typeof obj.can === "string"
}



// 🌸


export function as(identifier: string): Capability {
  return {
    with: resourcePointer.as(identifier),
    can: SUPERUSER
  }
}


export function my(resource: Superuser | string): Capability {
  return {
    with: resourcePointer.my(resource),
    can: SUPERUSER
  }
}


export function prf(selector: Superuser | number, ability: Ability): Capability {
  return {
    with: resourcePointer.prf(selector),
    can: ability
  }
}



// ENCODING


/**
 * Encode the individual parts of a capability.
 *
 * @param cap The capability to encode
 */
export function encode(cap: Capability): EncodedCapability {
  return {
    with: resourcePointer.encode(cap.with),
    can: ability.encode(cap.can)
  }
}

/**
 * Parse an encoded capability.
 *
 * @param cap The encoded capability
 */
export function parse(cap: EncodedCapability): Capability {
  return {
    with: resourcePointer.parse(cap.with),
    can: ability.parse(cap.can)
  }
}