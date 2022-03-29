import { Chained } from "./chained"
import { capabilities, CapabilityInfo, CapabilitySemantics, isCapabilityEscalation } from "./attenuation"


export interface IndexByAudience {
  [ audienceDID: string ]: Chained[]
}

export class Store {

  private index: IndexByAudience

  constructor(index: IndexByAudience) {
    this.index = index
  }

  static async fromTokens(tokens: Iterable<string> | AsyncIterable<string>): Promise<Store> {
    const store = new Store({})
    for await (const token of tokens) {
      store.add(await Chained.fromToken(token))
    }
    return store
  }

  add(ucan: Chained): void {
    const audience = ucan.audience()
    const byAudience = this.index[ audience ] ?? []
    if (byAudience.find(storedUcan => storedUcan.encoded() === ucan.encoded()) != null) {
      return
    }
    byAudience.push(ucan)
    this.index[ audience ] = byAudience
  }

  getByAudience(audience: string): Chained[] {
    return [ ...(this.index[ audience ] ?? []) ]
  }

  findByAudience(audience: string, predicate: (ucan: Chained) => boolean): Chained | null {
    return this.index[ audience ]?.find(ucan => predicate(ucan)) ?? null
  }

  findWithCapability<A>(
    audience: string,
    semantics: CapabilitySemantics<A>,
    requirementsCap: A,
    requirementsInfo: (info: CapabilityInfo) => boolean,
  ): { success: true; ucan: Chained } | FindFailure {
    const ucans = this.index[ audience ]

    if (ucans == null) {
      return { success: false, reason: `Couldn't find any UCAN for audience ${audience}` }
    }

    for (const ucan of ucans) {
      for (const result of capabilities(ucan, semantics)) {
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
