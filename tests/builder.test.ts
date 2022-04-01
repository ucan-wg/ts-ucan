import { Builder } from "../src/builder"
import { emailCapability } from "./capability/email"
import { wnfsCapability, wnfsPublicSemantics } from "./capability/wnfs"
import { EMAIL_SEMANTICS } from "./capability/email"
import { alice, bob, mallory } from "./fixtures"


describe("Builder", () => {

  it("builds with a simple example", async () => {
    const fact1 = { test: true }
    const fact2 = { preimage: "abc", hash: "sth" }
    const cap1 = emailCapability("alice@email.com")
    const cap2 = wnfsCapability("alice.fission.name/public/", "SUPER_USER")
    const expiration = Math.floor(Date.now() / 1000) + 30
    const notBefore = Math.floor(Date.now() / 1000) - 30

    const ucan = await Builder.create()
      .issuedBy(alice)
      .toAudience(bob.did())
      .withExpiration(expiration)
      .withNotBefore(notBefore)
      .withFact(fact1, fact2)
      .withNonce()
      .claimCapability(cap1, cap2)
      .build()

    expect(ucan.issuer()).toEqual(alice.did())
    expect(ucan.audience()).toEqual(bob.did())
    expect(ucan.expiresAt()).toEqual(expiration)
    expect(ucan.notBefore()).toEqual(notBefore)
    expect(ucan.facts()).toEqual([ fact1, fact2 ])
    expect(ucan.attenuation()).toEqual([ cap1, cap2 ])
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
      .claimCapability(wnfsCapability("alice.fission.name/public/", "SUPER_USER"))
      .build()

    const payload = Builder.create()
      .issuedBy(bob)
      .toAudience(mallory.did())
      .withLifetimeInSeconds(30)
      .delegateCapability(wnfsPublicSemantics, wnfsCapability("alice.fission.name/public/Apps", "CREATE"), ucan)
      .delegateCapability(wnfsPublicSemantics, wnfsCapability("alice.fission.name/public/Documents", "OVERWRITE"), ucan)
      .buildPayload()

    expect(payload.prf).toEqual([ ucan.encoded() ])
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
      .claimCapability(emailCapability("alice@email.com"))
      .build()

    expect(() => {
      Builder.create()
        .issuedBy(bob)
        .toAudience(mallory.did())
        .withLifetimeInSeconds(30)
        .delegateCapability(EMAIL_SEMANTICS, emailCapability("bob@email.com"), ucan)
        .buildPayload()
    }).toThrow()
  })

})
