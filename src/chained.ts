import { Capability } from "./capability"
import { Ucan, Fact } from "./types"
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

  /**
   * Validate a UCAN chain from a given JWT-encoded UCAN.
   *
   * This will validate
   * - The encoding
   * - The signatures (unless turned off in the `options`)
   * - The UCAN time bounds (unless turned off in the `options`)
   * - The audience from parent proof UCANs matching up with the issuer of child UCANs
   *
   * @returns A promise of a deeply-validated, deeply-parsed UCAN.
   * @throws If the UCAN chain can't be validated.
   */
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

  /**
   * @returns The original JWT-encoded UCAN this chain was parsed from.
   */
  encoded(): string {
    return this._encoded
  }

  /**
   * @returns A representation of delgated capabilities throughout all ucan chains
   */
  reduce<A>(reduceLayer: (ucan: Ucan<never>, reducedProofs: () => Iterable<A>) => A): A {
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const that = this

    function* reduceProofs() {
      for (const proof of that.proofs()) {
        yield proof.reduce(reduceLayer)
      }
    }

    return reduceLayer(this.payload(), reduceProofs)
  }

  /* Header */

  /**
   * @returns An identifier for the signature algorithm used.
   * Possible values include "RS256" and "EdDSA".
   */
  algorithm(): string {
    return this._decoded.header.alg
  }

  /**
   * @returns A string encoding the semantic version specified in the original encoded UCAN.
   */
  version(): string {
    return this._decoded.header.ucv
  }

  /* payload */

  /**
   * @returns the payload the top level represented by this Chain element.
   *          Its proofs are omitted. To access proofs, use `.proofs()`
   */
  payload(): Ucan<never> {
    return {
      ...this._decoded,
      payload: {
        ...this._decoded.payload,
        prf: ([] as never[])
      }
    }
  }

  /**
   * @returns `iss`: The issuer as a DID string ("did:key:...").
   *
   * The UCAN must be signed with the private key of the issuer to be valid.
   */
  issuer(): string {
    return this._decoded.payload.iss
  }

  /**
   * @returns `aud`: The audience as a DID string ("did:key:...").
   *
   * This is the identity this UCAN transfers rights to.
   * It could e.g. be the DID of a service you're posting this UCAN as a JWT to,
   * or it could be the DID of something that'll use this UCAN as a proof to
   * continue the UCAN chain as an issuer.
   */
  audience(): string {
    return this._decoded.payload.aud
  }

  /**
   * @returns `exp`: The UTCTime timestamp (in seconds) for when the UCAN expires.
   */
  expiresAt(): number {
    return this._decoded.payload.exp
  }

  /**
   * @returns `nbf`: The UTCTime timestamp (in seconds) of when the UCAN becomes active.
   * If `null`, then it's only bound by `.expiresAt()`.
   */
  notBefore(): number | null {
    return this._decoded.payload.nbf ?? null
  }

  /**
   * @returns `nnc`: A nonce (number used once).
   */
  nonce(): string | null {
    return this._decoded.payload.nnc ?? null
  }

  /**
   * @returns `att`: Attenuated capabilities.
   */
  attenuation(): Capability[] {
    return this._decoded.payload.att
  }

  /**
   * @returns `fct`: Arbitrary facts or proofs of knowledge in this UCAN as an array of records.
   */
  facts(): Fact[] {
    return this._decoded.payload.fct ?? []
  }

  /**
   * @returns `prf`: Further UCANs possibly providing proof or origin for some capabilities in this UCAN.
   */
  proofs(): Chained[] {
    return this._decoded.payload.prf
  }

  /* signature */

  /**
   * @returns a base64-encoded signature.
   * @see algorithm
   */
  signature(): string {
    return this._decoded.signature
  }

}
