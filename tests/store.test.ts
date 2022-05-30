import * as token from "../src/token"
import { Store } from "../src/store"
import { Builder } from "../src/builder"
import { alice, bob, mallory } from "./fixtures"
import { wnfsCapability, wnfsPublicSemantics } from "./capability/wnfs"
import { Ucan } from "../src/types"
import { equalitySemantics } from "../src/attenuation"
import { all } from "../src/util"


describe("Store.add", () => {

  it("makes added items retrievable with findByAudience", async () => {
    const ucan = await Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withLifetimeInSeconds(30)
      .build()

    const encoded = token.encode(ucan)

    const store = await Store.fromTokens(equalitySemantics, [])
    await store.add(ucan)
    expect(encodeOrNull(store.findByAudience(ucan.payload.aud, find => token.encode(find) === encoded))).toEqual(encoded)
  })

  it("makes added items retrievable with findByAudience among multiple others", async () => {
    const ucan = await Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withLifetimeInSeconds(30)
      .build()

    const ucan2 = await Builder.create()
      .issuedBy(alice)
      .toAudience(mallory.did())
      .withLifetimeInSeconds(30)
      .build()

    const encoded = token.encode(ucan)
    const store = await Store.fromTokens(equalitySemantics, [])
    await store.add(ucan2)
    await store.add(ucan)
    expect(encodeOrNull(store.findByAudience(ucan.payload.aud, find => token.encode(find) === encoded))).toEqual(encoded)
  })

  it("doesn't add items twice", async () => {
    const ucan = await Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withLifetimeInSeconds(30)
      .build()

    const store = await Store.fromTokens(equalitySemantics, [])
    await store.add(ucan)
    await store.add(ucan)
    expect(store.getByAudience(ucan.payload.aud)).toEqual([ ucan ])
  })

})

describe("Store.findByAudience", () => {

  it("only returns ucans with given audience", async () => {
    const ucanBob = await Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withLifetimeInSeconds(30)
      .build()

    const ucanAlice = await Builder.create()
      .issuedBy(bob)
      .toAudience(alice.did())
      .withLifetimeInSeconds(30)
      .build()

    const store = await Store.fromTokens(equalitySemantics, [ ucanBob, ucanAlice ].map(ucan => token.encode(ucan)))
    expect(store.findByAudience(mallory.did(), () => true)).toEqual(null)
    expect(encodeOrNull(store.findByAudience(bob.did(), () => true))).toEqual(token.encode(ucanBob))
    expect(encodeOrNull(store.findByAudience(alice.did(), () => true))).toEqual(token.encode(ucanAlice))
  })

})

describe("Store.findWithCapability", () => {

  it("finds ucans with more capabilities than the given", async () => {
    const ucan = await Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withLifetimeInSeconds(30)
      .claimCapability(wnfsCapability("alice.fission.name/public/", "SUPER_USER"))
      .build()

    const store = await Store.fromTokens(wnfsPublicSemantics, [ token.encode(ucan) ])

    const results = all(store.findWithCapability(
      bob.did(),
      wnfsCapability("alice.fission.name/public/Apps", "OVERWRITE"),
      alice.did()
    ))

    if (!("capability" in results[0])) {
      throw "no capability"
    }

    expect(encodeOrNull(results[0]?.ucan)).toEqual(token.encode(ucan))
  })

  it("reports an error if the capability can't be found with given audience", async () => {
    const ucanBob = await Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withLifetimeInSeconds(30)
      .claimCapability(wnfsCapability("alice.fission.name/public/", "SUPER_USER"))
      .build()

    const ucanAlice = await Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withLifetimeInSeconds(30)
      .build()

    const store = await Store.fromTokens(wnfsPublicSemantics, [ token.encode(ucanAlice), token.encode(ucanBob) ])

    const results = all(store.findWithCapability(
      alice.did(),
      wnfsCapability("alice.fission.name/public/Apps", "OVERWRITE"),
      alice.did()
    ))

    expect(results).toEqual([])
  })

})

function encodeOrNull(ucan: Ucan<unknown> | null): string {
  if (ucan == null) {
    return "null"
  }
  return token.encode(ucan)
}
