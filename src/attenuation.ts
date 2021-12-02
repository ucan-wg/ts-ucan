import { Capability, CapabilityParser } from "./types"

type Parsed<C> = null | { cap: C, parser: CapabilityParser<C> }

export function validateAttenuations<C>(
  childAtt: Capability[],
  parentAtt: Capability[],
  parsers: CapabilityParser<C>[]
): (C | Capability)[] | false {
  const valid: (C | Capability)[] = []
  for (const childCap of childAtt) {
    
    // find the first parser that parses the capability (and return the parsed capability)
    const child: Parsed<C> = parsers.reduce((acc: Parsed<C>, parser: CapabilityParser<C>) => {
      if (acc != null) return acc
      const cap = parser.parse(childCap)
      if (cap != null) return { cap, parser }
      return null
    }, null)

    // if we couldn't find a fitting parser we fall back to json-equivalence
    if (child == null) {
      if (parentAtt.find(cap => JSON.stringify(cap) === JSON.stringify(childCap))) {
        // return the fallback
        valid.push(childCap)
        continue
      } else {
        // we couldn't validate this capability
        // this doesn't mean the UCAN is invalid: We might just not know about the
        // semantics that need to be used for this kind of capability
        continue
      }
    }
    
    // we know about the precise semantics for this kind of capability: we have a fitting parser
    // filter out fitting parent capabilities
    const parentCaps = parentAtt.flatMap(cap => {
      const parsed = child.parser.parse(cap)
      if (parsed == null) return []
      return [parsed]
    })

    if (child.parser.subsumedBy(child.cap, parentCaps)) {
      valid.push(child.cap)
    } else {
      return false
    }
  }
  return valid
}


export type WNFSCapability
  = { path: string[], potency: WNFSPotency }

export const wnfsPotencyIdx = {
  "CREATE": 4,
  "REVISE": 3,
  "SOFT_DELETE": 2,
  "OVERWRITE": 1,
  "SUPER_USER": 0,
}

export type WNFSPotency = keyof typeof wnfsPotencyIdx

export function isWNFSPotency(obj: unknown): obj is WNFSPotency {
  if (typeof obj !== "string") return false
  return Object.keys(wnfsPotencyIdx).includes(obj)
}

export function potencySubsumes(lesserPot: WNFSPotency, biggerPot: WNFSPotency): boolean {
  return wnfsPotencyIdx[lesserPot] >= wnfsPotencyIdx[biggerPot]
}

export const wnfs: CapabilityParser<WNFSCapability> = {
  name: "wnfs",
  parse: capability => {
    if (capability.wnfs == null || typeof capability.wnfs !== "string" || !isWNFSPotency(capability.cap)) {
      return null
    }
    let pathStr = capability.wnfs
    pathStr = pathStr.startsWith("/") ? pathStr.slice(1) : pathStr
    pathStr = pathStr.endsWith("/") ? pathStr.slice(0, -1) : pathStr
    const path = pathStr.split("/")
    // disallow empty path segments
    if (path.some(str => str === "")) {
      return null
    }
    return { path, potency: capability.cap }
  },
  subsumedBy: (cap, parentCaps) => {
    return parentCaps.some(parentCap => prefixMatches(parentCap.path, cap.path) && potencySubsumes(cap.potency, parentCap.potency))
  }
}

function prefixMatches(prefix: string[], whole: string[]): boolean {
  if (prefix.length > whole.length) return false
  for (let i = 0; i < prefix.length; i++) {
    if (whole[i] !== prefix[i]) return false
  }
  return true
}


export interface EmailCapability {
  email: string,
  potency: EmailPotency
}

export type EmailPotency = "SEND"

export function isEmailPotency(obj: unknown): obj is EmailPotency {
  return obj === "SEND"
}

export const email: CapabilityParser<EmailCapability> = {
  name: "email",
  parse: capability => {
    if (typeof capability.email !== "string" || !isEmailPotency(capability.cap)) {
      return null
    }
    const email = capability.email
    const potency = capability.cap
    return { email, potency }
  },
  subsumedBy: (cap, parentCaps) => {
    return parentCaps.some(parentCap => parentCap.email === cap.email && parentCap.potency === cap.potency)
  },
}
