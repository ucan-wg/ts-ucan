import { Chained } from "../src/chained"
import * as token from "../src/token"

import { alice, bob, mallory } from "./fixtures"
import { emailCapabilities, emailCapability } from "./capability/email"
import { maxNbf } from "./utils"


describe("attenuation.emailCapabilities", () => {

  it("works with a simple example", async () => {
    // alice -> bob, bob -> mallory
    // alice delegates access to sending email as her to bob
    // and bob delegates it further to mallory
    const leafUcan = await token.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: [ emailCapability("alice@email.com") ]
    })

    const ucan = await token.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ emailCapability("alice@email.com") ],
      proofs: [ token.encode(leafUcan) ]
    })

    const emailCaps = Array.from(
      emailCapabilities(await Chained.fromToken(token.encode(ucan)))
    )

    expect(emailCaps).toEqual([ {
      info: {
        originator: alice.did(),
        expiresAt: Math.min(leafUcan.payload.exp, ucan.payload.exp),
        notBefore: maxNbf(leafUcan.payload.nbf, ucan.payload.nbf),
      },
      capability: emailCapability("alice@email.com")
    } ])
  })

  it("reports the first issuer in the chain as originator", async () => {
    // alice -> bob, bob -> mallory
    // alice delegates nothing to bob
    // and bob delegates his email to mallory
    const leafUcan = await token.build({
      issuer: alice,
      audience: bob.did(),
    })

    const ucan = await token.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ emailCapability("bob@email.com") ],
      proofs: [ token.encode(leafUcan) ]
    })

    // we implicitly expect the originator to become bob
    expect(Array.from(emailCapabilities(await Chained.fromToken(token.encode(ucan))))).toEqual([ {
      info: {
        originator: bob.did(),
        expiresAt: ucan.payload.exp,
        notBefore: ucan.payload.nbf,
      },
      capability: emailCapability("bob@email.com"),
    } ])
  })

  it("finds the right proof chain for the originator", async () => {
    // alice -> mallory, bob -> mallory, mallory -> alice
    // both alice and bob delegate their email access to mallory
    // mallory then creates a UCAN with capability to send both
    const leafUcanAlice = await token.build({
      issuer: alice,
      audience: mallory.did(),
      capabilities: [ emailCapability("alice@email.com") ]
    })

    const leafUcanBob = await token.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ emailCapability("bob@email.com") ]
    })

    const ucan = await token.build({
      issuer: mallory,
      audience: alice.did(),
      capabilities: [
        emailCapability("alice@email.com"),
        emailCapability("bob@email.com")
      ],
      proofs: [ token.encode(leafUcanAlice), token.encode(leafUcanBob) ]
    })

    const chained = await Chained.fromToken(token.encode(ucan))

    expect(Array.from(emailCapabilities(chained))).toEqual([
      {
        info: {
          originator: alice.did(),
          expiresAt: Math.min(leafUcanAlice.payload.exp, ucan.payload.exp),
          notBefore: maxNbf(leafUcanAlice.payload.nbf, ucan.payload.nbf),
        },
        capability: emailCapability("alice@email.com")
      },
      {
        info: {
          originator: bob.did(),
          expiresAt: Math.min(leafUcanBob.payload.exp, ucan.payload.exp),
          notBefore: maxNbf(leafUcanBob.payload.nbf, ucan.payload.nbf),
        },
        capability: emailCapability("bob@email.com")
      }
    ])
  })

  it("reports all chain options", async () => {
    // alice -> mallory, bob -> mallory, mallory -> alice
    // both alice and bob claim to have access to alice@email.com
    // and both grant that capability to mallory
    // a verifier needs to know both to verify valid email access

    const aliceEmail = emailCapability("alice@email.com")

    const leafUcanAlice = await token.build({
      issuer: alice,
      audience: mallory.did(),
      capabilities: [ aliceEmail ]
    })

    const leafUcanBob = await token.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ aliceEmail ]
    })

    const ucan = await token.build({
      issuer: mallory,
      audience: alice.did(),
      capabilities: [ aliceEmail ],
      proofs: [ token.encode(leafUcanAlice), token.encode(leafUcanBob) ]
    })

    const chained = await Chained.fromToken(token.encode(ucan))

    expect(Array.from(emailCapabilities(chained))).toEqual([
      {
        info: {
          originator: alice.did(),
          expiresAt: Math.min(leafUcanAlice.payload.exp, ucan.payload.exp),
          notBefore: maxNbf(leafUcanAlice.payload.nbf, ucan.payload.nbf),
        },
        capability: emailCapability("alice@email.com")
      },
      {
        info: {
          originator: bob.did(),
          expiresAt: Math.min(leafUcanBob.payload.exp, ucan.payload.exp),
          notBefore: maxNbf(leafUcanBob.payload.nbf, ucan.payload.nbf),
        },
        capability: emailCapability("alice@email.com")
      }
    ])
  })

})
