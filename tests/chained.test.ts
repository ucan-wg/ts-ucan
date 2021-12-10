import * as token from "../src/token"
import { Chained } from "../src/chained"
import { Ucan } from "../src/types"
import { alice, bob, mallory } from "./fixtures"


describe("Chained.fromToken", () => {

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

        const chain = await Chained.fromToken(ucan)
        expect(chain.audience()).toEqual(mallory.did())
        expect(chain.proofs()[0]?.issuer()).toEqual(alice.did())
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

        await expect(() => Chained.fromToken(ucan)).rejects.toBeDefined()
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

        await Chained.fromToken(ucan)
    })
})


describe("Chained.reduce", () => {

    it("can reconstruct the UCAN tree", async () => {
        // alice -> bob, mallory -> bob, bob -> alice
        const ucan = await Chained.fromToken(token.encode(await token.build({
            issuer: bob,
            audience: alice.did(),
            proofs: [
                token.encode(await token.build({
                    issuer: mallory,
                    audience: bob.did(),
                })),
                token.encode(await token.build({
                    issuer: alice,
                    audience: bob.did(),
                })),
            ]
        })))

        const reconstruction = ucan.reduce<string>((ucan: Ucan<never>, iterProofs: () => Iterable<string>) => {
            const proofs = Array.from(iterProofs())
            return token.encode({
                ...ucan,
                payload: {
                    ...ucan.payload,
                    prf: proofs
                }
            })
        })
        expect(reconstruction).toEqual(ucan.encoded())
    })

})
