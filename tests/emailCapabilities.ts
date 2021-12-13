import { capabilities, CapabilityEscalation, CapabilitySemantics } from "../src/attenuation"
import { Chained } from "../src/chained"
import { Capability } from "../src/types"


/* Very simple example capability semantics */
export interface EmailCapability {
  email: string
  cap: "SEND"
}

export const emailSemantics: CapabilitySemantics<EmailCapability> = {

  tryParsing(cap: Capability): EmailCapability | null {
    if (typeof cap.email === "string" && cap.cap === "SEND") {
      return {
        email: cap.email,
        cap: cap.cap,
      }
    }
    return null
  },

  tryDelegating<T extends EmailCapability>(parentCap: T, childCap: T): T | null | CapabilityEscalation<EmailCapability> {
    // potency is always "SEND" anyway, so doesn't need to be checked
    return childCap.email === parentCap.email ? childCap : null
  },

}

export function emailCapabilities(ucan: Chained) {
  return capabilities(ucan, emailSemantics)
}
