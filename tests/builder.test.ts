import { Builder } from "../src/builder"
import { wnfsPublicSemantics } from "../src/capability/wnfs"
import { emailSemantics } from "./emailCapabilities"
import { alice, bob, mallory } from "./fixtures"


describe("Builder", () => {

  it("builds with a simple example", async () => {
    const fact1 = { test: true }
    const fact2 = { preimage: "abc", hash: "sth" }
    const cap1 = { email: "alice@email.com", cap: "SEND" }
    const cap2 = { wnfs: "alice.fission.name/public/", cap: "SUPER_USER" }
    const expiration = Math.floor(Date.now() / 1000) + 30
    const notBefore = Math.floor(Date.now() / 1000) - 30

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
    const payload = Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withLifetimeInSeconds(300)
      .buildPayload()

    expect(payload.exp).toBeGreaterThan(Date.now() / 1000 + 290)
  })

  it("prevents duplicate proofs", async () => {
    const ucan = await Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withLifetimeInSeconds(30)
      .claimCapability({ wnfs: "alice.fission.name/public/", cap: "SUPER_USER" })
      .build()

    const payload = Builder.create()
      .issuedBy(bob)
      .toAudience(mallory.did())
      .withLifetimeInSeconds(30)
      .delegateCapability(wnfsPublicSemantics, { wnfs: "alice.fission.name/public/Apps", cap: "CREATE" }, ucan)
      .delegateCapability(wnfsPublicSemantics, { wnfs: "alice.fission.name/public/Documents", cap: "OVERWRITE" }, ucan)
      .buildPayload()

    expect(payload.prf).toEqual([ucan.encoded()])
  })

  it("throws when it's not ready to be built", () => {
    expect(() => {
      Builder.create()
        .buildPayload()
    }).toThrow()
    // issuer missing
    expect(() => {
      Builder.create()
        .toAudience(bob.did())
        .withLifetimeInSeconds(1)
        .buildPayload()
    }).toThrow()
    // audience missing
    expect(() => {
      Builder.create()
        .issuedBy(alice)
        .withLifetimeInSeconds(1)
        .buildPayload()
    }).toThrow()
    // expiration missing
    expect(() => {
      Builder.create()
        .issuedBy(alice)
        .toAudience(bob.did())
        .buildPayload()
    }).toThrow()
  })

  it("throws when trying to delegate unproven capabilities", async () => {
    const ucan = await Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withLifetimeInSeconds(30)
      .claimCapability({ email: "alice@email.com", cap: "SEND" })
      .build()

    expect(() => {
      Builder.create()
        .issuedBy(bob)
        .toAudience(mallory.did())
        .withLifetimeInSeconds(30)
        .delegateCapability(emailSemantics, { email: "bob@email.com", cap: "SEND" }, ucan)
        .buildPayload()
    }).toThrow()
  })

})
