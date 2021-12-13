import * as token from "../../src/token"
import { Chained } from "../../src/chained"
import { Capability } from "../../src/types"
import { wnfsPrivateCapabilities, wnfsPublicCapabilities } from "../../src/capability/wnfs"

import { alice, bob, mallory } from "../fixtures"
import { maxNbf } from "../utils"



describe("wnfs public capability", () => {

  it("works with a simple example", async () => {
    const { leaf, ucan, chain } = await makeSimpleDelegation(
      [{
        wnfs: "boris.fission.name/public/Apps/",
        cap: "OVERWRITE",
      }],
      [{
        wnfs: "boris.fission.name/public/Apps/appinator/",
        cap: "REVISE",
      }]
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
          publicPath: ["Apps", "appinator"],
          cap: "REVISE",
        }
      }
    ])
  })

  it("detects capability escalations", async () => {
    const { chain } = await makeSimpleDelegation(
      [{
        wnfs: "boris.fission.name/public/Apps/",
        cap: "CREATE",
      }],
      [{
        wnfs: "boris.fission.name/public/Apps/appinator/",
        cap: "OVERWRITE",
      }]
    )

    expect(Array.from(wnfsPublicCapabilities(chain))).toEqual([{
      escalation: "Capability level escalation",
      capability: {
        user: "boris.fission.name",
        publicPath: ["Apps", "appinator"],
        cap: "OVERWRITE",
      }
    }])
  })

  it("detects capability escalations, even if there's valid capabilities", async () => {
    const { leaf, ucan, chain } = await makeSimpleDelegation(
      [{
        wnfs: "boris.fission.name/public/Apps/",
        cap: "CREATE",
      },{
        wnfs: "boris.fission.name/public/Apps/",
        cap: "SUPER_USER",
      }],
      [{
        wnfs: "boris.fission.name/public/Apps/appinator/",
        cap: "OVERWRITE",
      }]
    )

    expect(Array.from(wnfsPublicCapabilities(chain))).toEqual([
      {
        escalation: "Capability level escalation",
        capability: {
          user: "boris.fission.name",
          publicPath: ["Apps", "appinator"],
          cap: "OVERWRITE",
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
          publicPath: ["Apps", "appinator"],
          cap: "OVERWRITE",
        }
      }
    ])
  })

})

describe("wnfs private capability", () => {

  it("works with a simple example", async () => {
    const { leaf, ucan, chain } = await makeSimpleDelegation(
      [{
        wnfs: "boris.fission.name/private/abc",
        cap: "OVERWRITE",
      }],
      [{
        wnfs: "boris.fission.name/private/def",
        cap: "REVISE",
      }]
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
          requiredINumbers: new Set(["abc", "def"]),
          cap: "REVISE",
        }
      }
    ])
  })

  it("detects capability escalations", async () => {
    const { chain } = await makeSimpleDelegation(
      [{
        wnfs: "boris.fission.name/private/abc",
        cap: "OVERWRITE",
      }],
      [{
        wnfs: "boris.fission.name/private/def",
        cap: "SUPER_USER",
      }]
    )

    expect(Array.from(wnfsPrivateCapabilities(chain))).toEqual([
      {
        escalation: "Capability level escalation",
        capability: {
          user: "boris.fission.name",
          requiredINumbers: new Set(["def"]),
          cap: "SUPER_USER",
        }
      },
    ])
  })

  it("detects capability escalations, but still returns valid delegations", async () => {
    const { leaf, ucan, chain } = await makeSimpleDelegation(
      [{
        wnfs: "boris.fission.name/private/abc",
        cap: "OVERWRITE",
      }],
      [
        {
          wnfs: "boris.fission.name/private/def",
          cap: "SUPER_USER",
        },
        {
          wnfs: "boris.fission.name/private/ghi",
          cap: "CREATE",
        }
      ]
    )

    expect(Array.from(wnfsPrivateCapabilities(chain))).toEqual([
      {
        escalation: "Capability level escalation",
        capability: {
          user: "boris.fission.name",
          requiredINumbers: new Set(["def"]),
          cap: "SUPER_USER",
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
          requiredINumbers: new Set(["abc", "ghi"]),
          cap: "CREATE",
        }
      }
    ])
  })

  it("lists all possible inumber combinations", async () => {
    const { leafAlice, leafBob, ucan, chain } = await makeComplexDelegation(
      {
        alice: [{
          wnfs: "boris.fission.name/private/inumalice",
          cap: "OVERWRITE",
        }],
        bob: [{
          wnfs: "boris.fission.name/private/inumbob",
          cap: "OVERWRITE",
        }]
      },
      [{
        wnfs: "boris.fission.name/private/subinum",
        cap: "OVERWRITE",
      }]
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
          requiredINumbers: new Set(["inumalice", "subinum"]),
          cap: "OVERWRITE",
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
          requiredINumbers: new Set(["inumbob", "subinum"]),
          cap: "OVERWRITE",
        }
      }
    ])
  })

  it("lists all possible inumber combinations except escalations", async () => {
    const { leafBob, ucan, chain } = await makeComplexDelegation(
      {
        alice: [{
          wnfs: "boris.fission.name/private/inumalice",
          cap: "CREATE",
        }],
        bob: [{
          wnfs: "boris.fission.name/private/inumbob",
          cap: "OVERWRITE",
        }]
      },
      [{
        wnfs: "boris.fission.name/private/subinum",
        cap: "OVERWRITE",
      }]
    )

    expect(Array.from(wnfsPrivateCapabilities(chain))).toEqual([
      {
        escalation: "Capability level escalation",
        capability: {
          user: "boris.fission.name",
          requiredINumbers: new Set(["subinum"]),
          cap: "OVERWRITE",
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
          requiredINumbers: new Set(["inumbob", "subinum"]),
          cap: "OVERWRITE",
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
    proofs: [token.encode(leaf)]
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
async function makeComplexDelegation(proofs: { alice: Capability[], bob: Capability[] }, final: Capability[]) {
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
    proofs: [token.encode(leafAlice), token.encode(leafBob)],
  })

  const chain = await Chained.fromToken(token.encode(ucan))

  return { leafAlice, leafBob, ucan, chain }
}
