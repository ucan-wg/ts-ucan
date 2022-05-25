import * as token from "../src/token"
import { Store } from "../src/store"
import { Builder } from "../src/builder"
import { alice, bob, mallory } from "./fixtures"
import { wnfsCapability, wnfsPublicSemantics } from "./capability/wnfs"
import { Chained } from "../src/chained"


describe("Store.add", () => {

  it("makes added items retrievable with findByAudience", async () => {
    const ucan = await Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withLifetimeInSeconds(30)
      .build()

    const encoded = token.encode(ucan)

    const store = await Store.fromTokens([])
    store.add(await Chained.fromToken(encoded))
    expect(store.findByAudience(ucan.payload.aud, find => find.encoded() === encoded)?.encoded()).toEqual(encoded)
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
    const store = await Store.fromTokens([])
    store.add(await Chained.fromToken(token.encode(ucan2)))
    store.add(await Chained.fromToken(encoded))
    expect(store.findByAudience(ucan.payload.aud, find => find.encoded() === encoded)?.encoded()).toEqual(encoded)
  })

  it("doesn't add items twice", async () => {
    const ucan = await Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withLifetimeInSeconds(30)
      .build()

    const chained = await Chained.fromToken(token.encode(ucan))
    const store = await Store.fromTokens([])
    store.add(chained)
    store.add(chained)
    expect(store.getByAudience(ucan.payload.aud)).toEqual([ chained ])
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

    const store = await Store.fromTokens([ ucanBob, ucanAlice ].map(ucan => token.encode(ucan)))
    expect(store.findByAudience(mallory.did(), () => true)).toEqual(null)
    expect(store.findByAudience(bob.did(), () => true)?.encoded()).toEqual(token.encode(ucanBob))
    expect(store.findByAudience(alice.did(), () => true)?.encoded()).toEqual(token.encode(ucanAlice))
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

    const store = await Store.fromTokens([ token.encode(ucan) ])

    const result = store.findWithCapability(bob.did(), wnfsPublicSemantics, {
      user: "alice.fission.name",
      publicPath: [ "Apps" ],
      ability: "OVERWRITE",
    }, () => true)

    if (!result.success) {
      expect(result.success).toEqual(true)
      throw new Error(`Unexpected result ${JSON.stringify(result)}`)
    }

    expect(result.ucan.encoded()).toEqual(token.encode(ucan))
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

    const store = await Store.fromTokens([ token.encode(ucanAlice), token.encode(ucanBob) ])

    const result = store.findWithCapability(alice.did(), wnfsPublicSemantics, {
      user: "alice.fission.name",
      publicPath: [ "Apps" ],
      ability: "OVERWRITE",
    }, () => true)

    expect(result.success).toEqual(false)
  })

})
