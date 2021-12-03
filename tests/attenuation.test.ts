import { emailCapabilities } from "../src/attenuation"
import { Chained } from "../src/chain"
import * as token from "../src/token"
import { alice, bob, mallory } from "./fixtures"


describe("attenuation.emailCapabilities", () => {

    it("works with an example", async () => {
        // alice -> bob, bob -> mallory
        // alice delegates access to sending email as her to bob
        // and bob delegates it further to mallory
        const leafUcan = token.encode(await token.build({
            issuer: alice,
            audience: bob.did(),
            capabilities: [{
                email: "alice@email.com",
                cap: "SEND",
            }]
        }))

        const ucan = token.encode(await token.build({
            issuer: bob,
            audience: mallory.did(),
            capabilities: [{
                email: "alice@email.com",
                cap: "SEND",
            }],
            proofs: [leafUcan]
        }))

        const emailCaps = emailCapabilities(await Chained.fromToken(ucan))
        expect(emailCaps).toEqual([{
            originator: alice.did(),
            email: "alice@email.com",
            potency: "SEND"
        }])
    })

    it("will report the first issuer in the chain as originator", async () => {
        // alice -> bob, bob -> mallory
        // alice delegates nothing to bob
        // and bob delegates his email to mallory
        const leafUcan = token.encode(await token.build({
            issuer: alice,
            audience: bob.did(),
        }))

        const ucan = token.encode(await token.build({
            issuer: bob,
            audience: mallory.did(),
            capabilities: [{
                email: "bob@email.com",
                cap: "SEND",
            }],
            proofs: [leafUcan]
        }))

        // we implicitly expect the originator to become bob
        expect(emailCapabilities(await Chained.fromToken(ucan))).toEqual([{
            originator: bob.did(),
            email: "bob@email.com",
            potency: "SEND"
        }])
    })

    it("will find the right proof chain for the originator", async () => {
        // alice -> mallory, bob -> mallory, mallory -> alice
        // both alice and bob delegate their email access to mallory
        // mallory then creates a UCAN with capability to send both
        const leafUcanAlice = token.encode(await token.build({
            issuer: alice,
            audience: mallory.did(),
            capabilities: [{
                email: "alice@email.com",
                cap: "SEND",
            }]
        }))

        const leafUcanBob = token.encode(await token.build({
            issuer: bob,
            audience: mallory.did(),
            capabilities: [{
                email: "bob@email.com",
                cap: "SEND",
            }]
        }))

        const ucan = token.encode(await token.build({
            issuer: mallory,
            audience: alice.did(),
            capabilities: [
                {
                    email: "alice@email.com",
                    cap: "SEND",
                },
                {
                    email: "bob@email.com",
                    cap: "SEND",
                }
            ],
            proofs: [leafUcanAlice, leafUcanBob]
        }))

        expect(emailCapabilities(await Chained.fromToken(ucan))).toEqual([
            {
                originator: alice.did(),
                email: "alice@email.com",
                potency: "SEND",
            },
            {
                originator: bob.did(),
                email: "bob@email.com",
                potency: "SEND",
            }
        ])
    })

})
