import { alice, bob, mallory } from "./fixtures"
import { wnfsCapability, wnfsPublicSemantics } from "./capability/wnfs"
import * as ucans from "../src"
import { Ucan, all } from "../src"

describe("Store.add", () => {

  it("makes added items retrievable with findByAudience", async () => {
    const ucan = await ucans.Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withLifetimeInSeconds(30)
      .build()

    const encoded = ucans.encode(ucan)

    const store = await ucans.Store.empty(ucans.equalCanDelegate)
    await store.add(ucan)
    expect(encodeOrNull(store.findByAudience(ucan.payload.aud, find => ucans.encode(find) === encoded))).toEqual(encoded)
  })

  it("makes added items retrievable with findByAudience among multiple others", async () => {
    const ucan = await ucans.Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withLifetimeInSeconds(30)
      .build()

    const ucan2 = await ucans.Builder.create()
      .issuedBy(alice)
      .toAudience(mallory.did())
      .withLifetimeInSeconds(30)
      .build()

    const encoded = ucans.encode(ucan)
    const store = await ucans.Store.empty(ucans.equalCanDelegate)
    await store.add(ucan2)
    await store.add(ucan)
    expect(encodeOrNull(store.findByAudience(ucan.payload.aud, find => ucans.encode(find) === encoded))).toEqual(encoded)
  })

  it("doesn't add items twice", async () => {
    const ucan = await ucans.Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withLifetimeInSeconds(30)
      .build()

    const store = await ucans.Store.empty(ucans.equalCanDelegate)
    await store.add(ucan)
    await store.add(ucan)
    expect(store.getByAudience(ucan.payload.aud)).toEqual([ ucan ])
  })

})

describe("Store.findByAudience", () => {

  it("only returns ucans with given audience", async () => {
    const ucanBob = await ucans.Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withLifetimeInSeconds(30)
      .build()

    const ucanAlice = await ucans.Builder.create()
      .issuedBy(bob)
      .toAudience(alice.did())
      .withLifetimeInSeconds(30)
      .build()

    const store = await ucans.Store.fromTokens(ucans.equalCanDelegate, [ ucanBob, ucanAlice ].map(ucan => ucans.encode(ucan)))
    expect(store.findByAudience(mallory.did(), () => true)).toEqual(null)
    expect(encodeOrNull(store.findByAudience(bob.did(), () => true))).toEqual(ucans.encode(ucanBob))
    expect(encodeOrNull(store.findByAudience(alice.did(), () => true))).toEqual(ucans.encode(ucanAlice))
  })

})

describe("Store.findWithCapability", () => {

  it("finds ucans with more capabilities than the given", async () => {
    const ucan = await ucans.Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withLifetimeInSeconds(30)
      .claimCapability(wnfsCapability("alice.fission.name/public/", "SUPER_USER"))
      .build()

    const store = await ucans.Store.fromTokens(wnfsPublicSemantics, [ ucans.encode(ucan) ])

    const results = all(store.findWithCapability(
      bob.did(),
      wnfsCapability("alice.fission.name/public/Apps", "OVERWRITE"),
      alice.did()
    ))

    if (!("capability" in results[0])) {
      throw "no capability"
    }

    expect(encodeOrNull(results[0]?.ucan)).toEqual(ucans.encode(ucan))
  })

  it("reports an error if the capability can't be found with given audience", async () => {
    const ucanBob = await ucans.Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withLifetimeInSeconds(30)
      .claimCapability(wnfsCapability("alice.fission.name/public/", "SUPER_USER"))
      .build()

    const ucanAlice = await ucans.Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withLifetimeInSeconds(30)
      .build()

    const store = await ucans.Store.fromTokens(wnfsPublicSemantics, [ ucans.encode(ucanAlice), ucans.encode(ucanBob) ])

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
  return ucans.encode(ucan)
}
