import * as token from "../../src/token"
import { Chained } from "../../src/chained"
import { Capability } from "../../src/capability"
import { wnfsCapability, wnfsPrivateCapabilities, wnfsPublicCapabilities } from "./wnfs"

import { alice, bob, mallory } from "../fixtures"
import { maxNbf } from "../utils"



describe("wnfs public capability", () => {

  it("works with a simple example", async () => {
    const { leaf, ucan, chain } = await makeSimpleDelegation(
      [ wnfsCapability("//boris.fission.name/public/Apps/", "OVERWRITE") ],
      [ wnfsCapability("//boris.fission.name/public/Apps/appinator/", "REVISE") ]
    )

    expect(Array.from(wnfsPublicCapabilities(chain))).toEqual([
      {
        info: {
          originator: alice.did(),
          expiresAt: Math.min(leaf.payload.exp, ucan.payload.exp),
          notBefore: maxNbf(leaf.payload.nbf, ucan.payload.nbf),
        },
        capability: {
          user: "boris.fission.name",
          publicPath: [ "Apps", "appinator" ],
          ability: "REVISE",
        }
      }
    ])
  })

  it("detects capability escalations", async () => {
    const { chain } = await makeSimpleDelegation(
      [ wnfsCapability("//boris.fission.name/public/Apps/", "CREATE") ],
      [ wnfsCapability("//boris.fission.name/public/Apps/appinator/", "OVERWRITE") ]
    )

    expect(Array.from(wnfsPublicCapabilities(chain))).toEqual([ {
      escalation: "Capability level escalation",
      capability: {
        user: "boris.fission.name",
        publicPath: [ "Apps", "appinator" ],
        ability: "OVERWRITE",
      }
    } ])
  })

  it("detects capability escalations, even if there's valid capabilities", async () => {
    const { leaf, ucan, chain } = await makeSimpleDelegation(
      [ wnfsCapability("//boris.fission.name/public/Apps/", "CREATE"),
      wnfsCapability("//boris.fission.name/public/Apps/", "SUPER_USER")
      ],
      [ wnfsCapability("//boris.fission.name/public/Apps/appinator/", "OVERWRITE")
      ]
    )

    expect(Array.from(wnfsPublicCapabilities(chain))).toEqual([
      {
        escalation: "Capability level escalation",
        capability: {
          user: "boris.fission.name",
          publicPath: [ "Apps", "appinator" ],
          ability: "OVERWRITE",
        }
      },
      {
        info: {
          originator: alice.did(),
          expiresAt: Math.min(leaf.payload.exp, ucan.payload.exp),
          notBefore: maxNbf(leaf.payload.nbf, ucan.payload.nbf),
        },
        capability: {
          user: "boris.fission.name",
          publicPath: [ "Apps", "appinator" ],
          ability: "OVERWRITE",
        }
      }
    ])
  })

})

describe("wnfs private capability", () => {

  it("works with a simple example", async () => {
    const { leaf, ucan, chain } = await makeSimpleDelegation(
      [ wnfsCapability("//boris.fission.name/private/abc", "OVERWRITE") ],
      [ wnfsCapability("//boris.fission.name/private/def", "REVISE") ]
    )

    expect(Array.from(wnfsPrivateCapabilities(chain))).toEqual([
      {
        info: {
          originator: alice.did(),
          expiresAt: Math.min(leaf.payload.exp, ucan.payload.exp),
          notBefore: maxNbf(leaf.payload.nbf, ucan.payload.nbf),
        },
        capability: {
          user: "boris.fission.name",
          requiredINumbers: new Set([ "abc", "def" ]),
          ability: "REVISE",
        }
      }
    ])
  })

  it("detects capability escalations", async () => {
    const { chain } = await makeSimpleDelegation(
      [ wnfsCapability("//boris.fission.name/private/abc", "OVERWRITE") ],
      [ wnfsCapability("//boris.fission.name/private/def", "SUPER_USER") ]
    )

    expect(Array.from(wnfsPrivateCapabilities(chain))).toEqual([
      {
        escalation: "Capability level escalation",
        capability: {
          user: "boris.fission.name",
          requiredINumbers: new Set([ "def" ]),
          ability: "SUPER_USER",
        }
      },
    ])
  })

  it("detects capability escalations, but still returns valid delegations", async () => {
    const { leaf, ucan, chain } = await makeSimpleDelegation(
      [ wnfsCapability("//boris.fission.name/private/abc", "OVERWRITE") ],
      [
        wnfsCapability("//boris.fission.name/private/def", "SUPER_USER"),
        wnfsCapability("//boris.fission.name/private/ghi", "CREATE")
      ]
    )

    expect(Array.from(wnfsPrivateCapabilities(chain))).toEqual([
      {
        escalation: "Capability level escalation",
        capability: {
          user: "boris.fission.name",
          requiredINumbers: new Set([ "def" ]),
          ability: "SUPER_USER",
        }
      },
      {
        info: {
          originator: alice.did(),
          expiresAt: Math.min(leaf.payload.exp, ucan.payload.exp),
          notBefore: maxNbf(leaf.payload.nbf, ucan.payload.nbf),
        },
        capability: {
          user: "boris.fission.name",
          requiredINumbers: new Set([ "abc", "ghi" ]),
          ability: "CREATE",
        }
      }
    ])
  })

  it("lists all possible inumber combinations", async () => {
    const { leafAlice, leafBob, ucan, chain } = await makeComplexDelegation(
      {
        alice: [ wnfsCapability("//boris.fission.name/private/inumalice", "OVERWRITE") ],
        bob: [ wnfsCapability("//boris.fission.name/private/inumbob", "OVERWRITE") ]
      },
      [ wnfsCapability("//boris.fission.name/private/subinum", "OVERWRITE") ]
    )

    expect(Array.from(wnfsPrivateCapabilities(chain))).toEqual([
      {
        info: {
          originator: alice.did(),
          expiresAt: Math.min(leafAlice.payload.exp, ucan.payload.exp),
          notBefore: maxNbf(leafAlice.payload.nbf, ucan.payload.nbf),
        },
        capability: {
          user: "boris.fission.name",
          requiredINumbers: new Set([ "inumalice", "subinum" ]),
          ability: "OVERWRITE",
        }
      },
      {
        info: {
          originator: bob.did(),
          expiresAt: Math.min(leafBob.payload.exp, ucan.payload.exp),
          notBefore: maxNbf(leafBob.payload.nbf, ucan.payload.nbf),
        },
        capability: {
          user: "boris.fission.name",
          requiredINumbers: new Set([ "inumbob", "subinum" ]),
          ability: "OVERWRITE",
        }
      }
    ])
  })

  it("lists all possible inumber combinations except escalations", async () => {
    const { leafBob, ucan, chain } = await makeComplexDelegation(
      {
        alice: [ wnfsCapability("//boris.fission.name/private/inumalice", "CREATE") ],
        bob: [ wnfsCapability("//boris.fission.name/private/inumbob", "OVERWRITE") ]
      },
      [ wnfsCapability("//boris.fission.name/private/subinum", "OVERWRITE") ]
    )

    expect(Array.from(wnfsPrivateCapabilities(chain))).toEqual([
      {
        escalation: "Capability level escalation",
        capability: {
          user: "boris.fission.name",
          requiredINumbers: new Set([ "subinum" ]),
          ability: "OVERWRITE",
        }
      },
      {
        info: {
          originator: bob.did(),
          expiresAt: Math.min(leafBob.payload.exp, ucan.payload.exp),
          notBefore: maxNbf(leafBob.payload.nbf, ucan.payload.nbf),
        },
        capability: {
          user: "boris.fission.name",
          requiredINumbers: new Set([ "inumbob", "subinum" ]),
          ability: "OVERWRITE",
        }
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

  const chain = await Chained.fromToken(token.encode(ucan))

  return { leaf, ucan, chain }
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

  const chain = await Chained.fromToken(token.encode(ucan))

  return { leafAlice, leafBob, ucan, chain }
}
