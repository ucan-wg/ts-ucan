import { Ucan, UcanPayload, UcanHeader } from "./types"
import * as token from "./token"

export class UcanChain {

    // We need to keep the encoded version around to preserve the signature
    private _encoded: string
    private _decoded: Ucan<UcanChain>

    constructor(encoded: string, decoded: Ucan<UcanChain>) {
        this._encoded = encoded
        this._decoded = decoded
    }

    static async fromToken(encodedUcan: string, options?: token.ValidateOptions): Promise<UcanChain> {
        const ucan = await token.validate(encodedUcan, options)

        // parse proofs recursively
        const proofs = await Promise.all(ucan.payload.prf.map(encodedPrf => UcanChain.fromToken(encodedPrf, options)))

        // check sender/receiver matchups. A parent ucan's audience must match the child ucan's issuer
        const incorrectProof = proofs.find(proof => proof.payload().aud !== ucan.payload.iss)
        if (incorrectProof != null) {
            throw new Error(`Invalid UCAN: Audience ${incorrectProof.payload().aud} doesn't match issuer ${ucan.payload.iss}`)
        }

        const ucanTransformed: Ucan<UcanChain> = {
            ...ucan,
            payload: {
                ...ucan.payload,
                prf: proofs
            },
        }
        return new UcanChain(encodedUcan, ucanTransformed)
    }

    encoded(): string {
        return this._encoded
    }

    header(): UcanHeader {
        return this._decoded.header
    }

    payload(): UcanPayload<string> {
        return {
            ...this._decoded.payload,
            prf: this._decoded.payload.prf.map(ucan => ucan.encoded())
        }
    }

    proofs(): UcanChain[] {
        return this._decoded.payload.prf
    }

    signature(): string {
        return this._decoded.signature
    }

}
