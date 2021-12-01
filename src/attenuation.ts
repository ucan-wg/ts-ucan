import { Capability, CapabilityParser } from "./types"

export const validAttenuation = (parent: Array<Capability>, child: Array<Capability>): boolean => {
  for(let i=0; i<child.length; i++) {
    const childCap = child[i]
    const found = parent.find((cap) => JSON.stringify(cap) == JSON.stringify(childCap))
    if(!found) return false
  }
  return true
}

export function validateAttenuations(
  child: Capability[],
  parent: Capability[],
  parsers: CapabilityParser<unknown>[]
): Capability[] | false {
  const validatedCaps: Capability[] = []
  loop: for (const childCap of child) {
    const resource = resourceTypeFromCapability(childCap)
    if (resource == null) {
      // we don't know this capability type
      // thus we can neither validate it nor prove that it's incorrect
      continue
    }

    const resourceType = knownResourceTypes[resource]

    if (resourceType != null) {
      if (!resourceType.isValid(childCap)) {
        return false
      }

      for (const parentCap of parent) {
        const parentResourceType = knownResourceTypes[resourceTypeFromCapability(parentCap)]
        if (parentResourceType == null) {
          // the resource is ill-formed
          // we can't verify the current capability against this
          continue
        }
        
        if (!parentResourceType.isValid(parentCap)) {
          // we know that the parent capability is ill-formed
          return false
        }

        if (resourceType.subsumes(childCap, parentCap)) {
          // we can justify the child capability, so move on to check more
          validatedCaps.push(childCap)
          continue loop
        } else {
          // we couldn't justify the child capability
          return false
        }
      }
    } else {
      // fallback: We don't really know the child capability.
      // But we know it's justified if we can find the same one at a parent
      if (parent.find(parentCap => JSON.stringify(parentCap) === JSON.stringify(parentCap))) {
        validatedCaps.push(childCap)
      }
    }
  }
  return validatedCaps
}

function resourceTypeFromCapability(cap: Capability): string | null {
  const resource = Object.keys(cap).filter(name => name != "cap")[0]
  if (typeof resource !== "string") {
    return null
  }
  return resource
}

export type WNFSCapability
  = { public: string[],  }
  | { private: Uint8Array /* bloom filter */ }

export type WNFSPotency = "CREATE" | "REVISE" | "SOFT_DELETE" | "OVERWRITE" | "SUPER_USER"

export function isWNFSPotency(obj: unknown): obj is WNFSPotency {
  if (typeof obj !== "string") return false
  return ["CREATE", "REVISE", "SOFT_DELETE", "OVERWRITE", "SUPER_USER"].includes(obj)
}

export const wnfs: CapabilityParser<WNFSCapability> = {
  name: "wnfs",
  parse: capability => {
    if (capability.wnfs == null || typeof capability.wnfs !== "string" || !isWNFSPotency(capability)) {
      return null
    }
    let path = capability.wnfs

    // ensure a trailing slash (even for files)
    // this way we prevent /public/something to match with /public/somethingelse
    if (!path.endsWith("/")) {
      path = `${path}/`
    }
    
    const publicPrefix = "/public/"
    const privatePrefix = "/private/"
    if (path.startsWith(publicPrefix)) {
      // remove /public/ prefix and trailing slash
      return { public: path.slice(publicPrefix.length, -1).split("/") }
    }
    if (path.startsWith())
  }
}
