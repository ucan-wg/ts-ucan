import { Ucan, Capability, Fact } from "./types"
import * as token from "./token"


/**
 * Represents a deeply verified chain of UCANs.
 *
 * These chains can actually be trees sometimes (if a ucan has >1 proofs).
 */
export class Chained {

    // We need to keep the encoded version around to preserve the signature
    private _encoded: string
    private _decoded: Ucan<Chained>

    constructor(encoded: string, decoded: Ucan<Chained>) {
        this._encoded = encoded
        this._decoded = decoded
    }

    static async fromToken(encodedUcan: string, options?: token.ValidateOptions): Promise<Chained> {
        const ucan = await token.validate(encodedUcan, options)

        // parse proofs recursively
        const proofs = await Promise.all(ucan.payload.prf.map(encodedPrf => Chained.fromToken(encodedPrf, options)))

        // check sender/receiver matchups. A parent ucan's audience must match the child ucan's issuer
        const incorrectProof = proofs.find(proof => proof.audience() !== ucan.payload.iss)
        if (incorrectProof != null) {
            throw new Error(`Invalid UCAN: Audience ${incorrectProof.audience()} doesn't match issuer ${ucan.payload.iss}`)
        }

        const ucanTransformed: Ucan<Chained> = {
            ...ucan,
            payload: {
                ...ucan.payload,
                prf: proofs
            },
        }
        return new Chained(encodedUcan, ucanTransformed)
    }

    encoded(): string {
        return this._encoded
    }

    /* Header */

    algorithm(): string {
        return this._decoded.header.alg
    }

    version(): string {
        return this._decoded.header.ucv
    }

    /* payload */

    payload(): Ucan<never> {
        return {
            ...this._decoded,
            payload: {
                ...this._decoded.payload,
                prf: ([] as never[])
            }
        }
    }

    issuer(): string {
        return this._decoded.payload.iss
    }

    audience(): string {
        return this._decoded.payload.aud
    }

    expiresAt(): number {
        return this._decoded.payload.exp
    }

    notBefore(): number | null {
        return this._decoded.payload.nbf ?? null
    }

    nonce(): string | null {
        return this._decoded.payload.nnc ?? null
    }

    attenuation(): Capability[] {
        return this._decoded.payload.att
    }

    facts(): Fact[] {
        return this._decoded.payload.fct ?? []
    }

    proofs(): Chained[] {
        return this._decoded.payload.prf
    }

    /* signature */

    signature(): string {
        return this._decoded.signature
    }

}
