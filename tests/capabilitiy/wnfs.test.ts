import { wnfsPublicCapabilities } from "../../src/capability/wnfs"
import * as token from "../../src/token"
import { Chained } from "../../src/chained"
import { Capability } from "../../src/types"

import { alice, bob, mallory } from "../fixtures"
import { maxNbf } from "../utils"


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


describe("wnfs public capability", () => {

  it("works with a simple example", async () => {
    const { leaf, ucan, chain } = await makeSimpleDelegation(
      [{
        wnfs: "boris.fission.codes/public/Apps/",
        cap: "OVERWRITE",
      }],
      [{
        wnfs: "boris.fission.codes/public/Apps/appinator/",
        cap: "REVISE",
      }]
    )

    expect(Array.from(wnfsPublicCapabilities(chain))).toEqual([
      {
        originator: alice.did(),
        expiresAt: Math.min(leaf.payload.exp, ucan.payload.exp),
        notBefore: maxNbf(leaf.payload.nbf, ucan.payload.nbf),
        user: "boris.fission.codes",
        publicPath: ["Apps", "appinator"],
        cap: "REVISE",
      }
    ])
  })

  it("detects capability escalations", async () => {
    const { chain } = await makeSimpleDelegation(
      [{
        wnfs: "boris.fission.codes/public/Apps/",
        cap: "CREATE",
      }],
      [{
        wnfs: "boris.fission.codes/public/Apps/appinator/",
        cap: "OVERWRITE",
      }]
    )

    expect(Array.from(wnfsPublicCapabilities(chain))).toEqual([{
      escalation: "Capability level escalation",
      capability: {
        user: "boris.fission.codes",
        publicPath: ["Apps", "appinator"],
        cap: "OVERWRITE",
      }
    }])
  })

  it("detects capability escalations, even if there's valid capabilities", async () => {
    const { leaf, ucan, chain } = await makeSimpleDelegation(
      [{
        wnfs: "boris.fission.codes/public/Apps/",
        cap: "CREATE",
      },{
        wnfs: "boris.fission.codes/public/Apps/",
        cap: "SUPER_USER",
      }],
      [{
        wnfs: "boris.fission.codes/public/Apps/appinator/",
        cap: "OVERWRITE",
      }]
    )

    expect(Array.from(wnfsPublicCapabilities(chain))).toEqual([
      {
        escalation: "Capability level escalation",
        capability: {
          user: "boris.fission.codes",
          publicPath: ["Apps", "appinator"],
          cap: "OVERWRITE",
        }
      },
      {
        originator: alice.did(),
        expiresAt: Math.min(leaf.payload.exp, ucan.payload.exp),
        notBefore: maxNbf(leaf.payload.nbf, ucan.payload.nbf),
        user: "boris.fission.codes",
        publicPath: ["Apps", "appinator"],
        cap: "OVERWRITE",
      }
    ])
  })

})
