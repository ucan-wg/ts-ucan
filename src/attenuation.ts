import { Capability } from "./types";

export const validAttenuation = (parent: Array<Capability>, child: Array<Capability>): boolean => {
  for(let i=0; i<child.length; i++) {
    const childCap = child[i]
    const found = parent.find((cap) => JSON.stringify(cap) == JSON.stringify(childCap))
    if(!found) return false
  }
  return true
}
