import { Store } from "../src/store"
import { Builder } from "../src/builder"
import { alice, bob, mallory } from "./fixtures"
import { wnfsCapability, wnfsPublicSemantics } from "./capability/wnfs"


describe("Store.add", () => {

  it("makes added items retrievable with findByAudience", async () => {
    const ucan = await Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withLifetimeInSeconds(30)
      .build()

    const store = await Store.fromTokens([])
    store.add(ucan)
    expect(store.findByAudience(ucan.audience(), find => find === ucan)).toEqual(ucan)
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

    const store = await Store.fromTokens([])
    store.add(ucan2)
    store.add(ucan)
    expect(store.findByAudience(ucan.audience(), find => find === ucan)).toEqual(ucan)
  })

  it("doesn't add items twice", async () => {
    const ucan = await Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withLifetimeInSeconds(30)
      .build()

    const store = await Store.fromTokens([])
    store.add(ucan)
    store.add(ucan)
    expect(store.getByAudience(ucan.audience())).toEqual([ ucan ])
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

    const store = await Store.fromTokens([ ucanBob, ucanAlice ].map(ucan => ucan.encoded()))
    expect(store.findByAudience(mallory.did(), () => true)).toEqual(null)
    expect(store.findByAudience(bob.did(), () => true)?.encoded()).toEqual(ucanBob.encoded())
    expect(store.findByAudience(alice.did(), () => true)?.encoded()).toEqual(ucanAlice.encoded())
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

    const store = await Store.fromTokens([ ucan.encoded() ])

    const result = store.findWithCapability(bob.did(), wnfsPublicSemantics, {
      user: "alice.fission.name",
      publicPath: [ "Apps" ],
      ability: "OVERWRITE",
    }, () => true)

    if (!result.success) {
      expect(result.success).toEqual(true)
      throw new Error(`Unexpected result ${JSON.stringify(result)}`)
    }

    expect(result.ucan.encoded()).toEqual(ucan.encoded())
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

    const store = await Store.fromTokens([ ucanAlice.encoded(), ucanBob.encoded() ])

    const result = store.findWithCapability(alice.did(), wnfsPublicSemantics, {
      user: "alice.fission.name",
      publicPath: [ "Apps" ],
      ability: "OVERWRITE",
    }, () => true)

    expect(result.success).toEqual(false)
  })

})
