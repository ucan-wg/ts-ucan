import { Chained } from "../src/chained"
import * as token from "../src/token"

import { alice, bob, mallory } from "./fixtures"
import { emailCapabilities, emailCapabilityFn,
  /*EmailCapability*/ } from "./capability/email"
import { maxNbf } from "./utils"

import { hasCapability, CapabilityEscalation,
  /*CapabilityWithInfo*/ } from '../src/attenuation'
import { Ucan } from "../src/types"
import { Capability } from "../src/capability"
import { SUPERUSER } from "../src/capability/super-user"

var ucan:Ucan
// var emailCaps:(CapabilityWithInfo<EmailCapability> | CapabilityEscalation<EmailCapability>)[]

describe("attenuation.emailCapabilities", () => {

  it("works with a simple example", async () => {
    // alice -> bob, bob -> mallory
    // alice delegates access to sending email as her to bob
    // and bob delegates it further to mallory
    const leafUcan = await token.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: [ emailCapabilityFn("alice@email.com") ]
    })

    ucan = await token.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ emailCapabilityFn("alice@email.com") ],
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
      capability: emailCapabilityFn("alice@email.com")
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
      capabilities: [ emailCapabilityFn("bob@email.com") ],
      proofs: [ token.encode(leafUcan) ]
    })

    // we implicitly expect the originator to become bob
    expect(Array.from(emailCapabilities(await Chained.fromToken(token.encode(ucan))))).toEqual([ {
      info: {
        originator: bob.did(),
        expiresAt: ucan.payload.exp,
        notBefore: ucan.payload.nbf,
      },
      capability: emailCapabilityFn("bob@email.com"),
    } ])
  })

  it("finds the right proof chain for the originator", async () => {
    // alice -> mallory, bob -> mallory, mallory -> alice
    // both alice and bob delegate their email access to mallory
    // mallory then creates a UCAN with capability to send both
    const leafUcanAlice = await token.build({
      issuer: alice,
      audience: mallory.did(),
      capabilities: [ emailCapabilityFn("alice@email.com") ]
    })

    const leafUcanBob = await token.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ emailCapabilityFn("bob@email.com") ]
    })

    const ucan = await token.build({
      issuer: mallory,
      audience: alice.did(),
      capabilities: [
        emailCapabilityFn("alice@email.com"),
        emailCapabilityFn("bob@email.com")
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
        capability: emailCapabilityFn("alice@email.com")
      },
      {
        info: {
          originator: bob.did(),
          expiresAt: Math.min(leafUcanBob.payload.exp, ucan.payload.exp),
          notBefore: maxNbf(leafUcanBob.payload.nbf, ucan.payload.nbf),
        },
        capability: emailCapabilityFn("bob@email.com")
      }
    ])
  })

  it("reports all chain options", async () => {
    // alice -> mallory, bob -> mallory, mallory -> alice
    // both alice and bob claim to have access to alice@email.com
    // and both grant that capability to mallory
    // a verifier needs to know both to verify valid email access

    const aliceEmail = emailCapabilityFn("alice@email.com")

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
        capability: emailCapabilityFn("alice@email.com")
      },
      {
        info: {
          originator: bob.did(),
          expiresAt: Math.min(leafUcanBob.payload.exp, ucan.payload.exp),
          notBefore: maxNbf(leafUcanBob.payload.nbf, ucan.payload.nbf),
        },
        capability: emailCapabilityFn("alice@email.com")
      }
    ])
  })

})


// let's do semantics based on the idea "you can delegate something if it's
// the same capability"
const testSemantics = {
  // ??? what is `tryParsing` used for?
  tryParsing(cap: Capability): Capability | null {
    return cap
  },

  // here you decide whether the given `childCap` is allowed to be created
  // by the given `parentCap`
  tryDelegating(parentCap: Capability,
    childCap: Capability): Capability | null | CapabilityEscalation<Capability> {
    // a shitty version of deep-equal :P
    const isEq = JSON.stringify(parentCap) === JSON.stringify(childCap)

    return  isEq ? childCap : null
  }
}

describe('hasCapability', () => {

  it('gets a capability', async () => {
    // unix timestamp in seconds
    const nowInSeconds = Math.floor(Date.now() / 1000) 

    const capabilityWithInfo = {
      // you can technically choose your own format for capabilities
      capability: emailCapabilityFn('alice@email.com'),
      // we need to provide some information about who we think originally
      // created/has the capability
      // and for which interval in time we want to check for the capability.
      info: {
        originator: alice.did(),
        notBefore: nowInSeconds,
        expiresAt: nowInSeconds + 30  // now + 30 seconds
      }
    }

    const cap = hasCapability(testSemantics, capabilityWithInfo,
      await Chained.fromToken(token.encode(ucan)))

    expect(cap).toBeTruthy()

    if (!cap) return

    expect(cap.info.originator).toEqual(alice.did())
    expect(cap.capability.with.hierPart).toEqual('alice@email.com')
  })

  it('rejects an invalid escalation', async () => {
    // unix timestamp in seconds
    const nowInSeconds = Math.floor(Date.now() / 1000) 

    const capabilityWithInfo = {
      capability: {
        email: 'alice@email.com',
        cap: 'FOO',
        with: {
          scheme: 'string',
          hierPart: 'Superuser | string'
        },
        can: SUPERUSER
      },
      // we need to provide some information about who we think originally
      // created/has the capability
      // and for which interval in time we want to check for the capability.
      info: {
        originator: alice.did(),
        notBefore: nowInSeconds,
        expiresAt: nowInSeconds + 30  // now + 30 seconds
      }
    }

    const cap = hasCapability(testSemantics, capabilityWithInfo,
      await Chained.fromToken(token.encode(ucan)))

    expect(cap).toEqual(false)
  })

  it('rejects for an invalid originator', async () => {
    // unix timestamp in seconds
    const nowInSeconds = Math.floor(Date.now() / 1000) 

    const capabilityWithInfo = {
      capability: {
        email: 'alice@email.com',
        cap: 'SEND',
        with: {
          scheme: 'string',
          hierPart: 'Superuser | string'
        },
        can: SUPERUSER
      },
      // we need to provide some information about who we think originally
      // created/has the capability
      // and for which interval in time we want to check for the capability.
      info: {
        // an invalid originator
        originator: 'fooo',
        notBefore: nowInSeconds,
        expiresAt: nowInSeconds + 30  // now + 30 seconds
      }
    }

    const cap = hasCapability(testSemantics, capabilityWithInfo,
      await Chained.fromToken(token.encode(ucan)))

    expect(cap).toEqual(false)
  })

})
