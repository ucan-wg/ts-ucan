import * as token from "../src/token"
import { Builder } from "../src/builder"
import { emailCapability } from "./capability/email"
import { wnfsCapability, wnfsPublicSemantics } from "./capability/wnfs"
import { EMAIL_SEMANTICS } from "./capability/email"
import { alice, bob, mallory } from "./fixtures"
import { delegationChains } from "../src/attenuation"
import { first } from "../src/util"


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

    expect(ucan.payload.iss).toEqual(alice.did())
    expect(ucan.payload.aud).toEqual(bob.did())
    expect(ucan.payload.exp).toEqual(expiration)
    expect(ucan.payload.nbf).toEqual(notBefore)
    expect(ucan.payload.fct).toEqual([ fact1, fact2 ])
    expect(ucan.payload.att).toEqual([ cap1, cap2 ])
    expect(ucan.payload.nnc).toBeDefined()
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

    const publicCapability = await first(delegationChains(wnfsPublicSemantics, ucan))

    if (publicCapability == null) {
      throw "no capabilities"
    }

    if (publicCapability instanceof Error) {
      throw publicCapability
    }

    const payload = Builder.create()
      .issuedBy(bob)
      .toAudience(mallory.did())
      .withLifetimeInSeconds(30)
      .delegateCapability(wnfsCapability("alice.fission.name/public/Apps", "CREATE"), publicCapability, wnfsPublicSemantics)
      .delegateCapability(wnfsCapability("alice.fission.name/public/Documents", "OVERWRITE"), publicCapability, wnfsPublicSemantics)
      .buildPayload()

    expect(payload.prf).toEqual([ token.encode(ucan) ])
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

    const delegationChain = await first(delegationChains(EMAIL_SEMANTICS, ucan))

    if (delegationChain == null) {
      throw "no capabilities"
    }

    if (delegationChain instanceof Error) {
      throw delegationChain
    }

    expect(() => {
      Builder.create()
        .issuedBy(bob)
        .toAudience(mallory.did())
        .withLifetimeInSeconds(30)
        .delegateCapability(emailCapability("bob@email.com"), delegationChain, EMAIL_SEMANTICS)
        .buildPayload()
    }).toThrow()
  })

})
