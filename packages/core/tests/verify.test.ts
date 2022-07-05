import { emailCapability } from "./capability/email"
import { alice, bob, mallory } from "./fixtures"
import * as ucans from "./lib"

describe("verify", () => {

  async function aliceEmailDelegationExample(expiration?: number) {
    // alice -> bob, bob -> mallory
    // alice delegates access to sending email as her to bob
    // and bob delegates it further to mallory
    const leafUcan = await ucans.build({
      issuer: alice,
      audience: bob.did(),
      expiration,
      capabilities: [ emailCapability("alice@email.com") ]
    })

    const ucan = await ucans.build({
      issuer: bob,
      audience: mallory.did(),
      expiration,
      capabilities: [ emailCapability("alice@email.com") ],
      proofs: [ ucans.encode(leafUcan) ]
    })

    return ucans.encode(ucan)
  }

  const alicesEmail = {
    capability: emailCapability("alice@email.com"),
    rootIssuer: alice.did(),
  }

  it("verifies a delegation chain", async () => {
    const ucan = await aliceEmailDelegationExample()

    const result = await ucans.verify(ucan, {
      audience: mallory.did(),
      requiredCapabilities: [ alicesEmail ]
    })

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

    const result = await ucans.verify(ucan, {
      audience: mallory.did(),
      requiredCapabilities: [ {
        capability: {
          ...emailCapability("alice@email.com"),
          can: ucans.ability.SUPERUSER,
        },
        rootIssuer: alice.did()
      } ]
    })

    expect(result.ok).toEqual(false)
  })

  it("rejects for an invalid audience", async () => {
    const ucan = await aliceEmailDelegationExample()

    const result = await ucans.verify(ucan, {
      audience: bob.did(),
      requiredCapabilities: [ alicesEmail ]
    })

    expect(result.ok).toEqual(false)
  })

  it("rejects for an invalid rootIssuer", async () => {
    const ucan = await aliceEmailDelegationExample()

    const result = await ucans.verify(ucan, {
      audience: mallory.did(),
      requiredCapabilities: [ {
        capability: emailCapability("alice@email.com"),
        // an invalid rootIssuer
        rootIssuer: "did:someone-else",
      } ]
    })

    expect(result.ok).toEqual(false)
  })

  it("rejects for an expired capability", async () => {
    // unix timestamp in seconds. Will be after
    const nowInSeconds = Math.floor(Date.now() / 1000)
    // expiry is in the past
    const ucan = await aliceEmailDelegationExample(nowInSeconds - 60 * 60 * 24)

    const result = await ucans.verify(ucan, {
      audience: mallory.did(),
      requiredCapabilities: [ alicesEmail ]
    })

    expect(result.ok).toEqual(false)
  })

  it("supports redelegation with a `prf:*` capability", async () => {
    // alice -> bob
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
      capabilities: [ ucans.capability.prf(ucans.ability.SUPERUSER, ucans.ability.REDELEGATE) ],
      proofs: [ ucans.encode(leafUcan) ]
    })

    const result = await ucans.verify(ucans.encode(ucan), {
      audience: mallory.did(),
      requiredCapabilities: [ alicesEmail ]
    })

    expect(result.ok).toEqual(true)

    if (!result.ok) return

    expect(result.value[ 0 ]?.rootIssuer).toEqual(alice.did())
    expect(result.value[ 0 ]?.capability).toEqual(emailCapability("alice@email.com"))
  })

  it("supports redelegation with a `prf:1` capability", async () => {
    // alice -> bob
    // alice delegates access to sending email as her to bob
    // and bob delegates it further to mallory
    const leafUcanA = await ucans.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: [ emailCapability("ignore-me@email.com") ]
    })

    const leafUcanB = await ucans.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: [ emailCapability("alice@email.com") ]
    })

    const ucan = await ucans.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ ucans.capability.prf(1, ucans.ability.REDELEGATE) ],
      proofs: [ ucans.encode(leafUcanA), ucans.encode(leafUcanB) ]
    })

    const result = await ucans.verify(ucans.encode(ucan), {
      audience: mallory.did(),
      requiredCapabilities: [ alicesEmail ]
    })

    expect(result.ok).toEqual(true)

    if (!result.ok) return

    expect(result.value[ 0 ]?.rootIssuer).toEqual(alice.did())
    expect(result.value[ 0 ]?.capability).toEqual(emailCapability("alice@email.com"))
  })

  it("ignores other proofs not referred to by `prf:0`", async () => {
    const leafUcanA = await ucans.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: [ emailCapability("ignore-me@email.com") ]
    })

    const leafUcanB = await ucans.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: [ emailCapability("alice@email.com") ]
    })

    const faultyUcan = await ucans.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ ucans.capability.prf(0, ucans.ability.REDELEGATE) ],
      proofs: [ ucans.encode(leafUcanA), ucans.encode(leafUcanB) ]
    })

    const result = await ucans.verify(ucans.encode(faultyUcan), {
      audience: mallory.did(),
      requiredCapabilities: [ alicesEmail ]
    })

    expect(result.ok).toEqual(false)
  })

  it("rejects an improper `prf` redelegation", async () => {
    // alice -> bob
    // alice delegates access to sending email as her to bob
    // and bob delegates it further to mallory
    const leafUcan = await ucans.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: [ emailCapability("invalid@email.com") ]
    })

    const ucan = await ucans.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ ucans.capability.prf(ucans.ability.SUPERUSER, ucans.ability.REDELEGATE) ],
      proofs: [ ucans.encode(leafUcan) ]
    })

    const result = await ucans.verify(ucans.encode(ucan), {
      audience: mallory.did(),
      requiredCapabilities: [ alicesEmail ]
    })

    expect(result.ok).toEqual(false)
  })

  it("supports redelegation with a `my` capability", async () => {
    // alice -> bob
    // alice delegates access to sending email as her to bob
    // and bob delegates it further to mallory
    const leafUcan = await ucans.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: [ ucans.capability.my(ucans.ability.SUPERUSER) ]
    })

    const ucan = await ucans.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ emailCapability("alice@email.com") ],
      proofs: [ ucans.encode(leafUcan) ]
    })

    const result = await ucans.verify(ucans.encode(ucan), {
      audience: mallory.did(),
      requiredCapabilities: [ alicesEmail ],
    })

    expect(result.ok).toEqual(true)

    if (!result.ok) return

    expect(result.value[ 0 ]?.rootIssuer).toEqual(alice.did())
  })

  it("supports redelegation with a `my` & `as` capability", async () => {
    // alice -> bob, bob -> mallory, mallory -> "someone"
    // alice delegates access to sending email as her to bob
    // and bob delegates it further to mallory
    const leafUcan = await ucans.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: [ ucans.capability.my(ucans.ability.SUPERUSER) ]
    })

    const middleUcan = await ucans.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ ucans.capability.as(alice.did(), ucans.ability.SUPERUSER) ],
      proofs: [ ucans.encode(leafUcan) ]
    })

    const ucan = await ucans.build({
      issuer: mallory,
      audience: "did:key:someone",
      capabilities: [ emailCapability("alice@email.com") ],
      proofs: [ ucans.encode(middleUcan) ]
    })

    const result = await ucans.verify(ucans.encode(ucan), {
      audience: "did:key:someone",
      requiredCapabilities: [ alicesEmail ]
    })

    expect(result.ok).toEqual(true)

    if (!result.ok) return

    expect(result.value[ 0 ]?.rootIssuer).toEqual(alice.did())
  })

  it("rejects an improper `my` redelegation", async () => {
    // alice -> bob
    // alice delegates access to sending email as her to bob
    // and bob delegates it further to mallory
    const leafUcan = await ucans.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: []
    })

    const ucan = await ucans.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ emailCapability("alice@email.com") ],
      proofs: [ ucans.encode(leafUcan) ]
    })

    const result = await ucans.verify(ucans.encode(ucan), {
      audience: mallory.did(),
      requiredCapabilities: [ alicesEmail ]
    })

    expect(result.ok).toEqual(false)
  })

  it("rejects an improper `as` redelegation - no `my`", async () => {
    // alice -> bob
    // alice delegates access to sending email as her to bob
    // and bob delegates it further to mallory
    const leafUcan = await ucans.build({
      issuer: alice,
      audience: bob.did(),
      capabilities: [ ucans.capability.as(bob.did(), ucans.ability.SUPERUSER) ]
    })

    const ucan = await ucans.build({
      issuer: bob,
      audience: mallory.did(),
      capabilities: [ emailCapability("alice@email.com") ],
      proofs: [ ucans.encode(leafUcan) ]
    })

    const result = await ucans.verify(ucans.encode(ucan), {
      audience: mallory.did(),
      requiredCapabilities: [ alicesEmail ]
    })

    expect(result.ok).toEqual(false)
  })

})
