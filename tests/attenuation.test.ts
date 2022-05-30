import { EdKeypair } from "../src/keypair/ed25519"
import * as capability from "../src/capability"
import * as token from "../src/token"

import { alice, bob, mallory } from "./fixtures"
import { emailCapabilities, emailCapability } from "./capability/email"
import { maxNbf } from "./utils"

import { CapabilitySemantics, equalitySemantics, hasCapability } from "../src/attenuation"
import { REDELEGATE } from "../src/capability/ability"
import { SUPERUSER } from "../src/capability/super-user"
import { all } from "../src/util"

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
    expect(await all(emailCapabilities(ucan))).toEqual([ {
      rootIssuer: bob.did(),
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
      lifetimeInSeconds: 10000,
      capabilities: [ emailCapability("alice@email.com") ]
    })

    const leafUcanBob = await token.build({
      issuer: bob,
      audience: mallory.did(),
      lifetimeInSeconds: 10000,
      capabilities: [ emailCapability("bob@email.com") ]
    })

    const ucan = await token.build({
      issuer: mallory,
      audience: alice.did(),
      lifetimeInSeconds: 10000,
      capabilities: [
        emailCapability("alice@email.com"),
        emailCapability("bob@email.com")
      ],
      proofs: [ token.encode(leafUcanAlice), token.encode(leafUcanBob) ]
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



describe("hasCapability", () => {

  async function aliceEmailDelegationExample() {
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

    return ucan
  }

  function nowInSeconds() {
    return Math.floor(Date.now() / 1000)
  }

  function aliceCapInfo() {
    const capabilityWithInfo = {
      capability: emailCapability("alice@email.com"),
      // we need to provide some information about who we think originally
      // created/has the capability
      // and for which interval in time we want to check for the capability.
      info: {
        originator: alice.did(),
        expiresAt: nowInSeconds(),
      }
    }

    return capabilityWithInfo
  }

  it("gets a capability", async () => {
    const ucan = await aliceEmailDelegationExample()
    const cap = await hasCapability(equalitySemantics, aliceCapInfo(), ucan)

    expect(cap).toBeTruthy()

    if (!cap) return

    expect(cap.info.originator).toEqual(alice.did())
    expect(cap.capability.with.hierPart).toEqual("alice@email.com")
  })

  it("rejects an invalid escalation", async () => {
    const ucan = await aliceEmailDelegationExample()

    // unix timestamp in seconds
    const nowInSeconds = Math.floor(Date.now() / 1000)

    const capabilityWithInfo = {
      capability: {
        ...emailCapability("alice@email.com"),
        can: SUPERUSER
      },
      // we need to provide some information about who we think originally
      // created/has the capability
      // and for which interval in time we want to check for the capability.
      info: {
        originator: alice.did(),
        expiresAt: nowInSeconds,
      },
    }

    const cap = await hasCapability(equalitySemantics, capabilityWithInfo, ucan)

    expect(cap).toEqual(false)
  })

  it("rejects for an invalid originator", async () => {
    const ucan = await aliceEmailDelegationExample()
    // unix timestamp in seconds
    const nowInSeconds = Math.floor(Date.now() / 1000)

    const capabilityWithInfo = {
      capability: emailCapability("alice@email.com"),
      // we need to provide some information about who we think originally
      // created/has the capability
      // and for which interval in time we want to check for the capability.
      info: {
        // an invalid originator
        originator: bob.did(),
        notBefore: nowInSeconds,
        expiresAt: nowInSeconds
      }
    }

    const cap = await hasCapability(equalitySemantics, capabilityWithInfo, ucan)

    expect(cap).toEqual(false)
  })

  it("rejects for an expired capability", async () => {
    const ucan = await aliceEmailDelegationExample()
    // unix timestamp in seconds. Will be after
    const nowInSeconds = Math.floor(Date.now() / 1000)

    const capabilityWithInfo = {
      capability: emailCapability("alice@email.com"),
      // we need to provide some information about who we think originally
      // created/has the capability
      // and for which interval in time we want to check for the capability.
      info: {
        // an invalid originator
        originator: bob.did(),
        notBefore: nowInSeconds,
        expiresAt: nowInSeconds + 60 * 60 * 24 // expiry is older than it should be
      }
    }

    const cap = await hasCapability(equalitySemantics, capabilityWithInfo, ucan)

    expect(cap).toEqual(false)
  })

  it("supports redelegation with a `prf:*` capability", async () => {
    // alice -> bob
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
      capabilities: [ capability.prf(capability.superUser.SUPERUSER, REDELEGATE) ],
      proofs: [ token.encode(leafUcan) ]
    })

    const cap = await hasCapability(equalitySemantics, aliceCapInfo(), ucan)

    expect(cap).toBeTruthy()

    if (!cap) return

    expect(cap.info.originator).toEqual(alice.did())
    expect(cap.capability.with.hierPart).toEqual("alice@email.com")
  })

  it("supports redelegation with a `prf:1` capability", async () => {
    // alice -> bob
    // alice delegates access to sending email as her to bob
    // and bob delegates it further to mallory
    const leafUcanA = await token.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: [ emailCapability("ignore-me@email.com") ]
    })

    const leafUcanB = await token.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: [ emailCapability("alice@email.com") ]
    })

    const ucan = await token.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ capability.prf(1, REDELEGATE) ],
      proofs: [ token.encode(leafUcanA), token.encode(leafUcanB) ]
    })

    const cap = await hasCapability(equalitySemantics, aliceCapInfo(), ucan)

    expect(cap).toBeTruthy()

    if (!cap) return

    expect(cap.info.originator).toEqual(alice.did())
    expect(cap.capability.with.hierPart).toEqual("alice@email.com")

    // Test invalid `prf:0`
    const faultyUcan = await token.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ capability.prf(0, REDELEGATE) ],
      proofs: [ token.encode(leafUcanA), token.encode(leafUcanB) ]
    })

    const capFaulty = await hasCapability(equalitySemantics, aliceCapInfo(), faultyUcan)

    expect(capFaulty).toBeFalsy()
  })

  it("rejects an improper `prf` redelegation", async () => {
    // alice -> bob
    // alice delegates access to sending email as her to bob
    // and bob delegates it further to mallory
    const leafUcan = await token.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: [ emailCapability("invalid@email.com") ]
    })

    const ucan = await token.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ capability.prf(capability.superUser.SUPERUSER, REDELEGATE) ],
      proofs: [ token.encode(leafUcan) ]
    })

    const cap = await hasCapability(equalitySemantics, aliceCapInfo(), ucan)

    expect(cap).toBeFalsy()
  })

  it("supports redelegation with a `my` capability", async () => {
    // alice -> bob
    // alice delegates access to sending email as her to bob
    // and bob delegates it further to mallory
    const leafUcan = await token.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: [ capability.my(capability.superUser.SUPERUSER) ]
    })

    const ucan = await token.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ emailCapability("alice@email.com") ],
      proofs: [ token.encode(leafUcan) ]
    })

    const cap = await hasCapability(equalitySemantics, aliceCapInfo(), ucan)

    expect(cap).toBeTruthy()

    if (!cap) return

    expect(cap.info.originator).toEqual(alice.did())
  })

  it("supports redelegation with a `my` & `as` capability", async () => {
    // alice -> bob, bob -> mallory, mallory -> "someone"
    // alice delegates access to sending email as her to bob
    // and bob delegates it further to mallory
    const leafUcan = await token.build({
      issuer: alice,
      audience: bob.did(),
      lifetimeInSeconds: 1000000,
      capabilities: [ capability.my(capability.superUser.SUPERUSER) ]
    })

    const middleUcan = await token.build({
      issuer: bob,
      audience: mallory.did(),
      lifetimeInSeconds: 1000000,
      capabilities: [ capability.as(alice.did(), SUPERUSER) ],
      proofs: [ token.encode(leafUcan) ]
    })

    const ucan = await token.build({
      issuer: mallory,
      audience: "did:key:someone",
      lifetimeInSeconds: 1000000,
      capabilities: [ emailCapability("alice@email.com") ],
      proofs: [ token.encode(middleUcan) ]
    })

    const cap = await hasCapability(equalitySemantics, aliceCapInfo(), ucan)

    expect(cap).toBeTruthy()

    if (!cap) return

    expect(cap.info.originator).toEqual(alice.did())
  })

  it("rejects an improper `my` redelegation", async () => {
    // alice -> bob
    // alice delegates access to sending email as her to bob
    // and bob delegates it further to mallory
    const leafUcan = await token.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: []
    })

    const ucan = await token.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ emailCapability("alice@email.com") ],
      proofs: [ token.encode(leafUcan) ]
    })

    const cap = await hasCapability(equalitySemantics, aliceCapInfo(), ucan)

    expect(cap).toBeFalsy()
  })

  it("rejects an improper `as` redelegation - no `my`", async () => {
    // alice -> bob
    // alice delegates access to sending email as her to bob
    // and bob delegates it further to mallory
    const leafUcan = await token.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: [ capability.as(bob.did(), SUPERUSER) ]
    })

    const ucan = await token.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ emailCapability("alice@email.com") ],
      proofs: [ token.encode(leafUcan) ]
    })

    const cap = await hasCapability(equalitySemantics, aliceCapInfo(), ucan)

    expect(cap).toBeFalsy()
  })

})
