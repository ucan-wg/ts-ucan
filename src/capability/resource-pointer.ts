import { Superuser, SUPERUSER } from "./super-user"
import * as util from "../util"


// 💎


export type ResourcePointer = {
  scheme: string
  hierPart: Superuser | string
}

export const SEPARATOR: string = ":"



// TYPE CHECKS


export function isResourcePointer(obj: unknown): obj is ResourcePointer {
  return util.isRecord(obj)
    && util.hasProp(obj, "scheme") && typeof obj.scheme === "string"
    && util.hasProp(obj, "hierPart") && (obj.hierPart === SUPERUSER || typeof obj.hierPart === "string")
}



// 🌸


export function as(identifier: string): ResourcePointer {
  return {
    scheme: "as",
    hierPart: identifier
  }
}


export function my(resource: Superuser | string): ResourcePointer {
  return {
    scheme: "my",
    hierPart: resource
  }
}


export function prf(selector: Superuser | number): ResourcePointer {
  return {
    scheme: "prf",
    hierPart: selector.toString()
  }
}



// 🛠


export function isEqual(a: ResourcePointer, b: ResourcePointer): boolean {
  return a.scheme.toLowerCase() === a.scheme.toLowerCase() && a.hierPart === b.hierPart
}



// ENCODING


/**
 * Encode a resource pointer.
 *
 * @param pointer The resource pointer to encode
 */
export function encode(pointer: ResourcePointer): string {
  return `${pointer.scheme}${SEPARATOR}${pointer.hierPart}`
}

/**
 * Parse an encoded resource pointer.
 *
 * @param pointer The encoded resource pointer
 */
export function parse(pointer: string): ResourcePointer {
  const [ scheme, ...hierPart ] = pointer.split(SEPARATOR)
  return { scheme, hierPart: hierPart.join(SEPARATOR) }
}