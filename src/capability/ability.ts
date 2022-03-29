import { Superuser, SUPERUSER } from "./super-user"
import * as util from "../util"


// 💎


export type Ability
  = Superuser
  | { namespace: string; segments: string[] }

export const SEPARATOR: string = "/"



// TYPE CHECKS


export function isAbility(obj: unknown): obj is Ability {
  return obj === SUPERUSER
    || (
      util.isRecord(obj)
      && util.hasProp(obj, "namespace") && typeof obj.namespace === "string"
      && util.hasProp(obj, "segments") && Array.isArray(obj.segments) && obj.segments.every(s => typeof s === "string")
    )
}



// 🛠


export function isEqual(a: Ability, b: Ability): boolean {
  if (a === SUPERUSER && b === SUPERUSER) return true
  if (a === SUPERUSER || b === SUPERUSER) return false

  return (
    a.namespace.toLowerCase() ===
    b.namespace.toLowerCase()
  ) &&
    (
      joinSegments(a.segments).toLowerCase() ===
      joinSegments(b.segments).toLowerCase()
    )
}


export function joinSegments(segments: string[]): string {
  return segments.join(SEPARATOR)
}



// ENCODING


/**
 * Encode an ability.
 *
 * @param ability The ability to encode
 */
export function encode(ability: Ability): string {
  switch (ability) {
    case SUPERUSER: return ability
    default: return joinSegments([ ability.namespace, ...ability.segments ])
  }
}

/**
 * Parse an encoded ability.
 *
 * @param ability The encoded ability
 */
export function parse(ability: string): Ability {
  switch (ability) {
    case SUPERUSER:
      return SUPERUSER
    default: {
      const [ namespace, ...segments ] = ability.split(SEPARATOR)
      return { namespace, segments }
    }
  }
}