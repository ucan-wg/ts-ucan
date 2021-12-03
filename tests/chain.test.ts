import * as token from "../src/token"
import { UcanChain } from "../src/chain"
import { alice, bob, mallory } from "./fixtures"

describe("UcanChain.fromToken", () => {
    
    it("decodes deep ucan chains", async () => {
        // alice -> bob, bob -> mallory
        // delegating rights from alice to mallory through bob
        const leafUcan = token.encode(await token.build({
            issuer: alice,
            audience: bob.did(),
        }))

        const ucan = token.encode(await token.build({
            issuer: bob,
            audience: mallory.did(),
            proofs: [leafUcan]
        }))

        const chain = await UcanChain.fromToken(ucan)
        expect(chain.payload().aud).toEqual(mallory.did())
        expect(chain.proofs()[0]?.payload().iss).toEqual(alice.did())
    })

    it("fails with incorrect chaining", async () => {
        // alice -> bob, alice -> mallory
        // incorrect chain. leaf's audience doesn't match final ucan's issuer
        const leafUcan = token.encode(await token.build({
            issuer: alice,
            audience: bob.did(),
        }))

        const ucan = token.encode(await token.build({
            issuer: alice,
            audience: mallory.did(),
            proofs: [leafUcan]
        }))

        await expect(() => UcanChain.fromToken(ucan)).rejects.toBeDefined()
    })

    it("can handle multiple ucan leafs", async () => {
        // alice -> bob, mallory -> bob, bob -> alice
        const leafUcanAlice = token.encode(await token.build({
            issuer: alice,
            audience: bob.did(),
        }))

        const leafUcanMallory = token.encode(await token.build({
            issuer: mallory,
            audience: bob.did(),
        }))

        const ucan = token.encode(await token.build({
            issuer: bob,
            audience: alice.did(),
            proofs: [leafUcanAlice, leafUcanMallory]
        }))

        await UcanChain.fromToken(ucan)
    })
})
