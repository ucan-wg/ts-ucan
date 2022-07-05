import * as token from "./token.js"
import Plugins from "./plugins.js"
import { capabilityCanBeDelegated, DelegationSemantics, DelegationChain, delegationChains, rootIssuer } from "./attenuation.js"
import { Ucan } from "./types.js"
import { Capability } from "./capability/index.js"


export interface IndexByAudience {
  [ audienceDID: string ]: Array<{
    processedUcan: Ucan
    capabilities: DelegationChain[]
  }>
}

export const storeFromTokens = (plugins: Plugins) =>
  async ( 
    knownSemantics: DelegationSemantics,
    tokens: Iterable<string> | AsyncIterable<string>,
  ): Promise<Store> => {
  const store = new Store(plugins, knownSemantics, {})
  for await (const encodedUcan of tokens) {
    const ucan = await token.validate(plugins)(encodedUcan)
    await store.add(ucan)
  }
  return store
}

export const emptyStore = (plugins: Plugins) => 
  (knownSemantics: DelegationSemantics) => {
  return new Store(plugins, knownSemantics, {})
}

export class Store {

  private plugins: Plugins
  private index: IndexByAudience
  private knownSemantics: DelegationSemantics

  constructor(plugins: Plugins, knownSemantics: DelegationSemantics, index: IndexByAudience) {
    this.plugins = plugins
    this.index = index
    this.knownSemantics = knownSemantics
  }

  async add(ucan: Ucan): Promise<void> {
    const audience = ucan.payload.aud
    const byAudience = this.index[ audience ] ?? []
    const encoded = token.encode(ucan)
    
    if (byAudience.find(stored => token.encode(stored.processedUcan) === encoded) != null) {
      return
    }

    const chains = []
    for await (const delegationChain of delegationChains(this.plugins)(this.knownSemantics, ucan)) {
      if (delegationChain instanceof Error) {
        console.warn(`Delegation chain error while storing UCAN:`, delegationChain)
        continue
      }
      chains.push(delegationChain)
    }

    // Also do this *after* the all awaits to prevent races.
    if (byAudience.find(stored => token.encode(stored.processedUcan) === encoded) != null) {
      return
    }

    byAudience.push({
      processedUcan: ucan,
      capabilities: chains
    })
    this.index[ audience ] = byAudience
  }

  getByAudience(audience: string): Ucan[] {
    return (this.index[ audience ] ?? []).map(elem => elem.processedUcan)
  }

  findByAudience(audience: string, predicate: (ucan: Ucan) => boolean): Ucan | null {
    return this.index[ audience ]?.find(elem => predicate(elem.processedUcan))?.processedUcan ?? null
  }

  *findWithCapability(
    audience: string,
    requiredCapability: Capability,
    requiredIssuer: string,
  ): Iterable<DelegationChain> {
    const cache = this.index[ audience ]

    if (cache == null) {
      return
    }

    for (const cacheElement of cache) {
      for (const delegationChain of cacheElement.capabilities) {
        if (capabilityCanBeDelegated(this.knownSemantics, requiredCapability, delegationChain)
          && rootIssuer(delegationChain) === requiredIssuer) {
            yield delegationChain
        }
      }
    }
  }

}
