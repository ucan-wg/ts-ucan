import { Builder } from "../src/builder"
import { wnfsPublicSemantics } from "../src/capability/wnfs"
import { emailCapabilities, emailSemantics } from "./emailCapabilities"
import { alice, bob, mallory } from "./fixtures"


describe("Builder", () => {

  it("builds with a simple example", async () => {
    const fact1 = { test: true }
    const fact2 = { preimage: "abc", hash: "sth" }
    const cap1 = { email: "alice@email.com", cap: "SEND" }
    const cap2 = { wnfs: "alice.fission.name/public/", cap: "SUPER_USER" }
    const expiration = Date.now() + 30 * 1000
    const notBefore = Date.now() - 30 * 1000

    const ucan = await Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withExpiraton(expiration)
      .withNotBefore(notBefore)
      .withFact(fact1, fact2)
      .withNonce()
      .claimCapability(cap1, cap2)
      .build()

    expect(ucan.issuer()).toEqual(alice.did())
    expect(ucan.audience()).toEqual(bob.did())
    expect(ucan.expiresAt()).toEqual(expiration)
    expect(ucan.notBefore()).toEqual(notBefore)
    expect(ucan.facts()).toEqual([fact1, fact2])
    expect(ucan.attenuation()).toEqual([cap1, cap2])
    expect(ucan.nonce()).toBeDefined()
  })

  it("builds with lifetimeInSeconds", async () => {
    const parts = Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withLifetimeInSeconds(300)
      .buildParts()

    expect(parts.payload.exp).toBeGreaterThan(Date.now() + 290 * 1000)
  })

  it("prevents duplicate proofs", async () => {
    const ucan = await Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withLifetimeInSeconds(30)
      .claimCapability({ wnfs: "alice.fission.name/public/", cap: "SUPER_USER" })
      .build()

    const parts = Builder.create()
      .issuedBy(bob)
      .toAudience(mallory.did())
      .withLifetimeInSeconds(30)
      .delegateCapability(wnfsPublicSemantics, { wnfs: "alice.fission.name/public/Apps", cap: "CREATE" }, ucan)
      .delegateCapability(wnfsPublicSemantics, { wnfs: "alice.fission.name/public/Documents", cap: "OVERWRITE" }, ucan)
      .buildParts()

    expect(parts.payload.prf).toEqual([ucan.encoded()])
  })

  it("throws when it's not ready to be built", () => {
    expect(() => {
      Builder.create()
        .buildParts()
    }).toThrow()
    // issuer missing
    expect(() => {
      Builder.create()
        .toAudience(bob.did())
        .withLifetimeInSeconds(1)
        .buildParts()
    }).toThrow()
    // audience missing
    expect(() => {
      Builder.create()
        .issuedBy(alice)
        .withLifetimeInSeconds(1)
        .buildParts()
    }).toThrow()
    // expiration missing
    expect(() => {
      Builder.create()
        .issuedBy(alice)
        .toAudience(bob.did())
        .buildParts()
    }).toThrow()
  })

})
