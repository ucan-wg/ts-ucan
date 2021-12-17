import { CID } from "multiformats"
import { Chained } from "./chained"
import { capabilities, CapabilitySemantics, isCapabilityEscalation } from "./attenuation"


// Add some things to the CapabilitySemantics
// I'm thinking of
// indexingKey(c: A): string
// superIndexingKeys(c: A): Iterable<string>

// implementations for current capabilities:
// email: indexingKey(cap) => cap.email
//        superIndexingKeys(cap) => return // a "yield cap.email" is already implied
// wnfs public:
//  indexingKey(cap) => cap.wnfs
//  superIndexingKeys(cap) => let p = parentDir(cap) in p != null ? yield p; yield* superIndexingKeys(p) : return
// wnfs private:
//  indexingKey(cap) => cap.wnfs
//  indexingKey(cap) => yield* allSupersetsOf(cap.requiredINumnbers)?

// I think the last case especially can be more efficient

export interface Context {
  signal?: AbortSignal
}

export interface BlockStore {
  getBlock(cid: CID, options?: Context): Promise<Uint8Array>
  putBlock(bytes: Uint8Array, codec: { code: number; name: string }, options?: Context): Promise<CID>
  knownCIDs(): Set<CID>
}

export interface IndexByAudience {
  [audienceDID: string]: Chained[]
}

export class Indexer {

  index: IndexByAudience

  constructor(index: IndexByAudience) {
    this.index = index
  }

  static async fromTokens(tokens: AsyncIterable<string>) {
    const idx = new Indexer({})
    for await (const token of tokens) {
      idx.add(await Chained.fromToken(token))
    }
  }

  add(ucan: Chained): void {
    const audience = ucan.audience()
    const byAudience = this.index[audience] ?? []
    byAudience.push(ucan)
    this.index[audience] = byAudience
  }

  findByIssuer(audience: string, predicate: (ucan: Chained) => boolean): Chained | null {
    return this.index[audience]?.find(ucan => predicate(ucan)) ?? null
  }

  findWithCapability<A>(audience: string, semantics: CapabilitySemantics<A>, requiredCapability: A): { ucan: Chained; capability: A } | null {
    const ucans = this.index[audience]

    if (ucans == null) {
      return null
    }

    for (const ucan of ucans) {
      for (const result of capabilities(ucan, semantics)) {
        if (isCapabilityEscalation(result)) continue
        const { info, capability } = result
        const delegated = semantics.tryDelegating(capability, requiredCapability)
        if (isCapabilityEscalation(delegated) || delegated == null) continue
        return { ucan, capability: delegated }
      }
    }

    return null
  }

}
