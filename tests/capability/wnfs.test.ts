import * as token from "../../src/token"
import { Capability } from "../../src/capability"
import { wnfsCapability, wnfsPrivateCapabilities, wnfsPublicCapabilities } from "./wnfs"

import { alice, bob, mallory } from "../fixtures"
import { all } from "../../src/util"



describe("wnfs public capability", () => {

  it("works with a simple example", async () => {
    const { ucan } = await makeSimpleDelegation(
      [ wnfsCapability("//boris.fission.name/public/Apps/", "OVERWRITE") ],
      [ wnfsCapability("//boris.fission.name/public/Apps/appinator/", "REVISE") ]
    )

    expect(await all(wnfsPublicCapabilities(ucan))).toEqual([
      {
        rootIssuer: bob.did(),
        capability: wnfsCapability("//boris.fission.name/public/Apps/appinator/", "REVISE")
      },
      {
        rootIssuer: alice.did(),
        capability: wnfsCapability("//boris.fission.name/public/Apps/appinator/", "REVISE")
      }
    ])
  })

  it("detects capability escalations", async () => {
    const { ucan } = await makeSimpleDelegation(
      [ wnfsCapability("//boris.fission.name/public/Apps/", "CREATE") ],
      [ wnfsCapability("//boris.fission.name/public/Apps/appinator/", "OVERWRITE") ]
    )

    expect(await all(wnfsPublicCapabilities(ucan))).toEqual([
      {
        rootIssuer: bob.did(),
        capability: wnfsCapability("//boris.fission.name/public/Apps/appinator/", "OVERWRITE")
      }
    ])
  })

  it("detects capability escalations, even if there's valid capabilities", async () => {
    const { ucan } = await makeSimpleDelegation(
      [
        wnfsCapability("//boris.fission.name/public/Apps/", "CREATE"),
        wnfsCapability("//boris.fission.name/public/Apps/", "SUPER_USER")
      ],
      [ wnfsCapability("//boris.fission.name/public/Apps/appinator/", "OVERWRITE")
      ]
    )

    expect(await all(wnfsPublicCapabilities(ucan))).toEqual([
      {
        rootIssuer: bob.did(),
        capability: wnfsCapability("//boris.fission.name/public/Apps/appinator/", "OVERWRITE")
      },
      {
        rootIssuer: alice.did(),
        capability: wnfsCapability("//boris.fission.name/public/Apps/appinator/", "OVERWRITE")
      }
    ])
  })

})

describe("wnfs private capability", () => {

  it("works with a simple example", async () => {
    const { ucan } = await makeSimpleDelegation(
      [ wnfsCapability("//boris.fission.name/private/abc", "OVERWRITE") ],
      [ wnfsCapability("//boris.fission.name/private/def", "REVISE") ]
    )

    expect(await all(wnfsPrivateCapabilities(ucan))).toEqual([
      {
        rootIssuer: bob.did(),
        capability: wnfsCapability("//boris.fission.name/private/def", "REVISE"),
        requiredINumbers: new Set(["def"])
      },
      {
        rootIssuer: alice.did(),
        capability: wnfsCapability("//boris.fission.name/private/def", "REVISE"),
        requiredINumbers: new Set(["abc", "def"])
      }
    ])
  })

  it("detects capability escalations", async () => {
    const { ucan } = await makeSimpleDelegation(
      [ wnfsCapability("//boris.fission.name/private/abc", "OVERWRITE") ],
      [ wnfsCapability("//boris.fission.name/private/def", "SUPER_USER") ]
    )

    expect(await all(wnfsPrivateCapabilities(ucan))).toEqual([
      {
        rootIssuer: bob.did(),
        capability: wnfsCapability("//boris.fission.name/private/def", "SUPER_USER"),
        requiredINumbers: new Set(["def"])
      },
    ])
  })

  it("detects capability escalations, but still returns valid delegations", async () => {
    const { ucan } = await makeSimpleDelegation(
      [ wnfsCapability("//boris.fission.name/private/abc", "OVERWRITE") ],
      [
        wnfsCapability("//boris.fission.name/private/def", "SUPER_USER"),
        wnfsCapability("//boris.fission.name/private/ghi", "CREATE")
      ]
    )

    expect(await all(wnfsPrivateCapabilities(ucan))).toEqual([
      {
        rootIssuer: bob.did(),
        capability: wnfsCapability("//boris.fission.name/private/def", "SUPER_USER"),
        requiredINumbers: new Set(["def"])
      },
      {
        rootIssuer: bob.did(),
        capability: wnfsCapability("//boris.fission.name/private/ghi", "CREATE"),
        requiredINumbers: new Set(["ghi"])
      },
      {
        rootIssuer: alice.did(),
        capability: wnfsCapability("//boris.fission.name/private/ghi", "CREATE"),
        requiredINumbers: new Set(["ghi", "abc"])
      }
    ])
  })

  it("lists all possible inumber combinations", async () => {
    const { ucan } = await makeComplexDelegation(
      {
        alice: [ wnfsCapability("//boris.fission.name/private/inumalice", "OVERWRITE") ],
        bob: [ wnfsCapability("//boris.fission.name/private/inumbob", "OVERWRITE") ]
      },
      [ wnfsCapability("//boris.fission.name/private/subinum", "OVERWRITE") ]
    )

    expect(await all(wnfsPrivateCapabilities(ucan))).toEqual([
      {
        rootIssuer: mallory.did(),
        capability: wnfsCapability("//boris.fission.name/private/subinum", "OVERWRITE"),
        requiredINumbers: new Set(["subinum"])
      },
      {
        rootIssuer: alice.did(),
        capability: wnfsCapability("//boris.fission.name/private/subinum", "OVERWRITE"),
        requiredINumbers: new Set(["subinum", "inumalice"])
      },
      {
        rootIssuer: bob.did(),
        capability: wnfsCapability("//boris.fission.name/private/subinum", "OVERWRITE"),
        requiredINumbers: new Set(["subinum", "inumbob"])
      }
    ])
  })

  it("lists all possible inumber combinations except escalations", async () => {
    const { ucan } = await makeComplexDelegation(
      {
        alice: [ wnfsCapability("//boris.fission.name/private/inumalice", "CREATE") ],
        bob: [ wnfsCapability("//boris.fission.name/private/inumbob", "OVERWRITE") ]
      },
      [ wnfsCapability("//boris.fission.name/private/subinum", "OVERWRITE") ]
    )

    expect(await all(wnfsPrivateCapabilities(ucan))).toEqual([
      {
        rootIssuer: mallory.did(),
        capability: wnfsCapability("//boris.fission.name/private/subinum", "OVERWRITE"),
        requiredINumbers: new Set(["subinum"])
      },
      {
        rootIssuer: bob.did(),
        capability: wnfsCapability("//boris.fission.name/private/subinum", "OVERWRITE"),
        requiredINumbers: new Set(["subinum", "inumbob"])
      }
    ])
  })

})

/**
 * A linear delegation chain:
 * alice -> bob -> mallory
 *
 * The arguments are the capabilities delegated in the first and second arrow, respectively.
 */
async function makeSimpleDelegation(aliceCapabilities: Capability[], bobCapabilities: Capability[]) {
  const leaf = await token.build({
    issuer: alice,
    audience: bob.did(),
    capabilities: aliceCapabilities
  })

  const ucan = await token.build({
    issuer: bob,
    audience: mallory.did(),
    capabilities: bobCapabilities,
    proofs: [ token.encode(leaf) ]
  })

  return { leaf, ucan }
}


/**
 * A tree-like delegation ucan:
 * alice & bob => mallory -> alice
 *
 * The first argument are the capabilities delegated in the first two arrows,
 * the second argument are the capabilities delegated in the last arrow.
 */
async function makeComplexDelegation(proofs: { alice: Capability[]; bob: Capability[] }, final: Capability[]) {
  const leafAlice = await token.build({
    issuer: alice,
    audience: mallory.did(),
    capabilities: proofs.alice,
  })

  const leafBob = await token.build({
    issuer: bob,
    audience: mallory.did(),
    capabilities: proofs.bob,
  })

  const ucan = await token.build({
    issuer: mallory,
    audience: alice.did(),
    capabilities: final,
    proofs: [ token.encode(leafAlice), token.encode(leafBob) ],
  })

  return { leafAlice, leafBob, ucan }
}
