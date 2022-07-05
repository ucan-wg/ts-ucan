import { emailCapabilities, emailCapability } from "./capability/email"

import { alice, bob, mallory } from "./fixtures"
import { all } from "../src/util"
import * as ucans from "./lib"


describe("attenuation.emailCapabilities", () => {

  it("works with a simple example", async () => {
    // alice -> bob, bob -> mallory
    // alice delegates access to sending email as her to bob
    // and bob delegates it further to mallory
    const leafUcan = await ucans.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: [ emailCapability("alice@email.com") ]
    })

    const ucan = await ucans.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ emailCapability("alice@email.com") ],
      proofs: [ ucans.encode(leafUcan) ]
    })

    expect(await all(emailCapabilities(ucan))).toEqual([
      {
        rootIssuer: bob.did(),
        capability: emailCapability("alice@email.com")
      },
      {
        rootIssuer: alice.did(),
        capability: emailCapability("alice@email.com")
      }
    ])
  })

  it("reports the first issuer in the chain as originator", async () => {
    // alice -> bob, bob -> mallory
    // alice delegates nothing to bob
    // and bob delegates his email to mallory
    const leafUcan = await ucans.build({
      issuer: alice,
      audience: bob.did(),
    })

    const ucan = await ucans.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ emailCapability("bob@email.com") ],
      proofs: [ ucans.encode(leafUcan) ]
    })

    // we implicitly expect the originator to become bob
    expect(await all(emailCapabilities(ucan))).toEqual([ {
      rootIssuer: bob.did(),
      capability: emailCapability("bob@email.com"),
    } ])
  })

  it("finds the right proof chain for the originator", async () => {
    // alice -> mallory, bob -> mallory, mallory -> alice
    // both alice and bob delegate their email access to mallory
    // mallory then creates a UCAN with capability to send both
    const leafUcanAlice = await ucans.build({
      issuer: alice,
      audience: mallory.did(),
      capabilities: [ emailCapability("alice@email.com") ]
    })

    const leafUcanBob = await ucans.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ emailCapability("bob@email.com") ]
    })

    const ucan = await ucans.build({
      issuer: mallory,
      audience: alice.did(),
      capabilities: [
        emailCapability("alice@email.com"),
        emailCapability("bob@email.com")
      ],
      proofs: [ ucans.encode(leafUcanAlice), ucans.encode(leafUcanBob) ]
    })

    const chains = await all(emailCapabilities(ucan))

    expect(chains).toEqual([
      // We expect two capabilities from parenthood:
      {
        rootIssuer: mallory.did(),
        capability: emailCapability("alice@email.com")
      },
      {
        rootIssuer: mallory.did(),
        capability: emailCapability("bob@email.com")
      },
      // Then there's also the delegations
      {
        rootIssuer: alice.did(),
        capability: emailCapability("alice@email.com")
      },
      {
        rootIssuer: bob.did(),
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

    const leafUcanAlice = await ucans.build({
      issuer: alice,
      audience: mallory.did(),
      capabilities: [ aliceEmail ]
    })

    const leafUcanBob = await ucans.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ aliceEmail ]
    })

    const ucan = await ucans.build({
      issuer: mallory,
      audience: alice.did(),
      capabilities: [ aliceEmail ],
      proofs: [ ucans.encode(leafUcanAlice), ucans.encode(leafUcanBob) ]
    })

    expect(await all(emailCapabilities(ucan))).toEqual([
      {
        rootIssuer: mallory.did(),
        capability: aliceEmail
      },
      {
        rootIssuer: alice.did(),
        capability: aliceEmail
      },
      {
        rootIssuer: bob.did(),
        capability: aliceEmail
      }
    ])
  })

})
