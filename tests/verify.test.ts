import * as token from "../src/token"
import * as capability from "../src/capability"
import { SUPERUSER } from "../src/capability/super-user"
import { verify } from "../src/verify"
import { emailCapability } from "./capability/email"
import { alice, bob, mallory } from "./fixtures"
import { REDELEGATE } from "../src/capability/ability"


describe("verify", () => {

  async function aliceEmailDelegationExample(expiration?: number) {
    // alice -> bob, bob -> mallory
    // alice delegates access to sending email as her to bob
    // and bob delegates it further to mallory
    const leafUcan = await token.build({
      issuer: alice,
      audience: bob.did(),
      expiration,
      capabilities: [ emailCapability("alice@email.com") ]
    })

    const ucan = await token.build({
      issuer: bob,
      audience: mallory.did(),
      expiration,
      capabilities: [ emailCapability("alice@email.com") ],
      proofs: [ token.encode(leafUcan) ]
    })

    return token.encode(ucan)
  }

  const nothingIsRevoked = async () => false

  const alicesEmail = {
    capability: emailCapability("alice@email.com"),
    rootIssuer: alice.did(),
  }

  it("verifies a delegation chain", async () => {
    const ucan = await aliceEmailDelegationExample()

    const result = await verify(ucan, mallory.did(), nothingIsRevoked, [ alicesEmail ])

    if (result.ok === false) {
      console.log(result.error)
    }

    expect(result.ok).toEqual(true)

    if (!result.ok) return

    expect(result.value[ 0 ]?.rootIssuer).toEqual(alice.did())
    expect(result.value[ 0 ]?.capability).toEqual(emailCapability("alice@email.com"))
  })

  it("rejects an invalid escalation", async () => {
    const ucan = await aliceEmailDelegationExample()

    const result = await verify(ucan, mallory.did(), nothingIsRevoked, [ {
      capability: {
        ...emailCapability("alice@email.com"),
        can: SUPERUSER,
      },
      rootIssuer: alice.did()
    } ])

    expect(result.ok).toEqual(false)
  })

  it("rejects for an invalid audience", async () => {
    const ucan = await aliceEmailDelegationExample()

    const result = await verify(ucan, bob.did(), nothingIsRevoked, [ alicesEmail ])

    expect(result.ok).toEqual(false)
  })

  it("rejects for an invalid rootIssuer", async () => {
    const ucan = await aliceEmailDelegationExample()

    const result = await verify(ucan, mallory.did(), nothingIsRevoked, [ {
      capability: emailCapability("alice@email.com"),
      // an invalid rootIssuer
      rootIssuer: "did:someone-else",
    } ])

    expect(result.ok).toEqual(false)
  })

  it("rejects for an expired capability", async () => {
    // unix timestamp in seconds. Will be after
    const nowInSeconds = Math.floor(Date.now() / 1000)
    // expiry is in the past
    const ucan = await aliceEmailDelegationExample(nowInSeconds - 60 * 60 * 24)

    const result = await verify(ucan, mallory.did(), nothingIsRevoked, [ alicesEmail ])

    expect(result.ok).toEqual(false)
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

    const result = await verify(token.encode(ucan), mallory.did(), nothingIsRevoked, [ alicesEmail ])

    expect(result.ok).toEqual(true)

    if (!result.ok) return

    expect(result.value[ 0 ]?.rootIssuer).toEqual(alice.did())
    expect(result.value[ 0 ]?.capability).toEqual(emailCapability("alice@email.com"))
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

    const result = await verify(token.encode(ucan), mallory.did(), nothingIsRevoked, [ alicesEmail ])

    expect(result.ok).toEqual(true)

    if (!result.ok) return

    expect(result.value[ 0 ]?.rootIssuer).toEqual(alice.did())
    expect(result.value[ 0 ]?.capability).toEqual(emailCapability("alice@email.com"))
  })

  it("ignores other proofs not referred to by `prf:0`", async () => {
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

    const faultyUcan = await token.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ capability.prf(0, REDELEGATE) ],
      proofs: [ token.encode(leafUcanA), token.encode(leafUcanB) ]
    })

    const result = await verify(token.encode(faultyUcan), mallory.did(), nothingIsRevoked, [ alicesEmail ])

    expect(result.ok).toEqual(false)
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

    const result = await verify(token.encode(ucan), mallory.did(), nothingIsRevoked, [ alicesEmail ])

    expect(result.ok).toEqual(false)
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

    const result = await verify(token.encode(ucan), mallory.did(), nothingIsRevoked, [ alicesEmail ])

    expect(result.ok).toEqual(true)

    if (!result.ok) return

    expect(result.value[ 0 ]?.rootIssuer).toEqual(alice.did())
  })

  it("supports redelegation with a `my` & `as` capability", async () => {
    // alice -> bob, bob -> mallory, mallory -> "someone"
    // alice delegates access to sending email as her to bob
    // and bob delegates it further to mallory
    const leafUcan = await token.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: [ capability.my(capability.superUser.SUPERUSER) ]
    })

    const middleUcan = await token.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ capability.as(alice.did(), SUPERUSER) ],
      proofs: [ token.encode(leafUcan) ]
    })

    const ucan = await token.build({
      issuer: mallory,
      audience: "did:key:someone",
      capabilities: [ emailCapability("alice@email.com") ],
      proofs: [ token.encode(middleUcan) ]
    })

    const result = await verify(token.encode(ucan), "did:key:someone", nothingIsRevoked, [ alicesEmail ])

    expect(result.ok).toEqual(true)

    if (!result.ok) return

    expect(result.value[ 0 ]?.rootIssuer).toEqual(alice.did())
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

    const result = await verify(token.encode(ucan), mallory.did(), nothingIsRevoked, [ alicesEmail ])

    expect(result.ok).toEqual(false)
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

    const result = await verify(token.encode(ucan), mallory.did(), nothingIsRevoked, [ alicesEmail ])

    expect(result.ok).toEqual(false)
  })

})
