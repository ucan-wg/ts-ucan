import { encode, validate } from "./token.js"
import { capabilities, CapabilityInfo, CapabilitySemantics, isCapabilityEscalation } from "./attenuation.js"
import { Ucan } from "./types.js"


export interface IndexByAudience {
  [ audienceDID: string ]: Ucan[]
}

export class Store {

  private index: IndexByAudience

  constructor(index: IndexByAudience) {
    this.index = index
  }

  static async fromTokens(tokens: Iterable<string> | AsyncIterable<string>): Promise<Store> {
    const store = new Store({})
    for await (const token of tokens) {
      store.add(await validate(token))
    }
    return store
  }

  add(ucan: Ucan): void {
    const audience = ucan.payload.aud
    const byAudience = this.index[ audience ] ?? []
    if (byAudience.find(storedUcan => encode(storedUcan) === encode(ucan)) != null) {
      return
    }
    byAudience.push(ucan)
    this.index[ audience ] = byAudience
  }

  getByAudience(audience: string): Ucan[] {
    return [ ...(this.index[ audience ] ?? []) ]
  }

  findByAudience(audience: string, predicate: (ucan: Ucan) => boolean): Ucan | null {
    return this.index[ audience ]?.find(ucan => predicate(ucan)) ?? null
  }

  async findWithCapability<A>(
    audience: string,
    semantics: CapabilitySemantics<A>,
    requirementsCap: A,
    requirementsInfo: (info: CapabilityInfo) => boolean,
  ): Promise<{ success: true; ucan: Ucan } | FindFailure> {
    const ucans = this.index[ audience ]

    if (ucans == null) {
      return { success: false, reason: `Couldn't find any UCAN for audience ${audience}` }
    }

    for (const ucan of ucans) {
      for await (const result of capabilities(ucan, semantics)) {
        if (isCapabilityEscalation(result)) continue
        const { info, capability } = result
        if (!requirementsInfo(info)) continue
        const delegated = semantics.tryDelegating(capability, requirementsCap)
        if (isCapabilityEscalation(delegated) || delegated == null) continue
        return { success: true, ucan }
      }
    }

    return { success: false, reason: `Couldn't find a UCAN with required capabilities` }
  }

}

type FindFailure = { success: false; reason: string }
