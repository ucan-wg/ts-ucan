import { emailCapabilities } from "../src/attenuation"
import { Chained } from "../src/chained"
import * as token from "../src/token"
import { alice, bob, mallory } from "./fixtures"


describe("attenuation.emailCapabilities", () => {

    it("works with a simple example", async () => {
        // alice -> bob, bob -> mallory
        // alice delegates access to sending email as her to bob
        // and bob delegates it further to mallory
        const leafUcan = await token.build({
            issuer: alice,
            audience: bob.did(),
            capabilities: [{
                email: "alice@email.com",
                cap: "SEND",
            }]
        })

        const ucan = await token.build({
            issuer: bob,
            audience: mallory.did(),
            capabilities: [{
                email: "alice@email.com",
                cap: "SEND",
            }],
            proofs: [token.encode(leafUcan)]
        })

        const emailCaps = emailCapabilities(await Chained.fromToken(token.encode(ucan)))
        expect(emailCaps).toEqual([{
            originator: alice.did(),
            expiresAt: Math.min(leafUcan.payload.exp, ucan.payload.exp),
            email: "alice@email.com",
            potency: "SEND"
        }])
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
            capabilities: [{
                email: "bob@email.com",
                cap: "SEND",
            }],
            proofs: [token.encode(leafUcan)]
        })

        // we implicitly expect the originator to become bob
        expect(emailCapabilities(await Chained.fromToken(token.encode(ucan)))).toEqual([{
            originator: bob.did(),
            expiresAt: ucan.payload.exp,
            email: "bob@email.com",
            potency: "SEND"
        }])
    })

    it("finds the right proof chain for the originator", async () => {
        // alice -> mallory, bob -> mallory, mallory -> alice
        // both alice and bob delegate their email access to mallory
        // mallory then creates a UCAN with capability to send both
        const leafUcanAlice = await token.build({
            issuer: alice,
            audience: mallory.did(),
            capabilities: [{
                email: "alice@email.com",
                cap: "SEND",
            }]
        })

        const leafUcanBob = await token.build({
            issuer: bob,
            audience: mallory.did(),
            capabilities: [{
                email: "bob@email.com",
                cap: "SEND",
            }]
        })

        const ucan = await token.build({
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
            proofs: [token.encode(leafUcanAlice), token.encode(leafUcanBob)]
        })

        const chained = await Chained.fromToken(token.encode(ucan))

        expect(emailCapabilities(chained)).toEqual([
            {
                originator: alice.did(),
                expiresAt: Math.min(leafUcanAlice.payload.exp, ucan.payload.exp),
                email: "alice@email.com",
                potency: "SEND",
            },
            {
                originator: bob.did(),
                expiresAt: Math.min(leafUcanBob.payload.exp, ucan.payload.exp),
                email: "bob@email.com",
                potency: "SEND",
            }
        ])
    })

    it("reports all chain options", async () => {
        // alice -> mallory, bob -> mallory, mallory -> alice
        // both alice and bob claim to have access to alice@email.com
        // and both grant that capability to mallory
        // a verifier needs to know both to verify valid email access

        const aliceEmail = {
            email: "alice@email.com",
            cap: "SEND",
        }

        const leafUcanAlice = await token.build({
            issuer: alice,
            audience: mallory.did(),
            capabilities: [aliceEmail]
        })

        const leafUcanBob = await token.build({
            issuer: bob,
            audience: mallory.did(),
            capabilities: [aliceEmail]
        })

        const ucan = await token.build({
            issuer: mallory,
            audience: alice.did(),
            capabilities: [aliceEmail],
            proofs: [token.encode(leafUcanAlice), token.encode(leafUcanBob)]
        })

        const chained = await Chained.fromToken(token.encode(ucan))

        expect(emailCapabilities(chained)).toEqual([
            {
                originator: alice.did(),
                expiresAt: Math.min(leafUcanAlice.payload.exp, ucan.payload.exp),
                email: "alice@email.com",
                potency: "SEND",
            },
            {
                originator: bob.did(),
                expiresAt: Math.min(leafUcanBob.payload.exp, ucan.payload.exp),
                email: "alice@email.com",
                potency: "SEND",
            }
        ])
    })

})
