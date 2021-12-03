import * as uint8arrays from 'uint8arrays'
import * as base64 from "./base64"
import * as util from './util'
import * as did from './did'
import { verifySignature } from "./did/validation"
import { validAttenuation } from './attenuation'
import { Keypair, KeyType, Capability, Fact, Ucan, UcanHeader, UcanPayload } from "./types"

/**
 * Create a UCAN, User Controlled Authorization Networks, JWT.
 * This JWT can be used for authorization.
 *
 * ### Header
 *
 * `alg`, Algorithm, the type of signature.
 * `typ`, Type, the type of this data structure, JWT.
 * `ucv`, UCAN version.
 *
 * ### Payload
 *
 * `aud`, Audience, the ID of who it's intended for.
 * `exp`, Expiry, unix timestamp of when the jwt is no longer valid.
 * `fct`, Facts, an array of extra facts or information to attach to the jwt.
 * `iss`, Issuer, the ID of who sent this.
 * `nbf`, Not Before, unix timestamp of when the jwt becomes valid.
 * `nnc`, Nonce, a randomly generated string, used to ensure the uniqueness of the jwt.
 * `prf`, Proofs, nested tokens with equal or greater privileges.
 * `att`, Attenuation, a list of resources and capabilities that the ucan grants.
 *
 */

export async function build(params: {
  // to/from
  audience: string
  issuer: Keypair

  // capabilities
  capabilities?: Array<Capability>

  // time bounds
  lifetimeInSeconds?: number // expiration overrides lifetimeInSeconds
  expiration?: number
  notBefore?: number

  // proofs / other info
  facts?: Array<Fact>
  proofs?: Array<string>
  addNonce?: boolean

  // in the weeds
  ucanVersion?: string
}): Promise<Ucan> {
  const keypair = params.issuer
  const didStr = did.publicKeyBytesToDid(keypair.publicKey, keypair.keyType)
  const { header, payload } = buildParts({
    ...params,
    issuer: didStr,
    keyType: keypair.keyType
  })
  return sign(header, payload, keypair)
}

export function buildParts(params: {
  // to/from
  audience: string
  issuer: string
  keyType: KeyType

  // capabilities
  capabilities?: Array<Capability>

  // time bounds
  lifetimeInSeconds?: number // expiration overrides lifetimeInSeconds
  expiration?: number
  notBefore?: number

  // proofs / other info
  facts?: Array<Fact>
  proofs?: Array<string>
  addNonce?: boolean

  // in the weeds
  ucanVersion?: string
}): { header: UcanHeader, payload: UcanPayload } {
  const {
    audience,
    issuer,
    capabilities = [],
    keyType,
    lifetimeInSeconds = 30,
    expiration,
    notBefore,
    facts,
    proofs = [],
    addNonce = false,
    ucanVersion = "0.7.0"
  } = params

  // Timestamps
  const currentTimeInSeconds = Math.floor(Date.now() / 1000)
  let exp = expiration || (currentTimeInSeconds + lifetimeInSeconds)
  let nbf = notBefore || currentTimeInSeconds - 60

  const header = {
    alg: jwtAlgorithm(keyType),
    typ: "JWT",
    ucv: ucanVersion,
  } as UcanHeader

  const payload = {
    aud: audience,
    att: capabilities,
    exp,
    fct: facts,
    iss: issuer,
    nbf,
    prf: proofs,
  } as UcanPayload

  if (addNonce) {
    payload.nnc = util.generateNonce()
  }

  return { header, payload }
}

/**
 * Try to decode a UCAN.
 * Will throw if it fails.
 *
 * @param ucan The encoded UCAN to decode
 */
export function decode(ucan: string): Ucan  {
  const split = ucan.split(".")
  const header = JSON.parse(base64.urlDecode(split[0]))
  const payload = JSON.parse(base64.urlDecode(split[1]))

  return {
    header,
    payload,
    signature: split[2] || null
  }
}

/**
 * Encode a UCAN.
 *
 * @param ucan The UCAN to encode
 */
export function encode(ucan: Ucan): string {
  const encodedHeader = encodeHeader(ucan.header)
  const encodedPayload = encodePayload(ucan.payload)

  return encodedHeader + "." +
         encodedPayload + "." +
         ucan.signature
}

/**
 * Encode the header of a UCAN.
 *
 * @param header The UcanHeader to encode
 */
 export function encodeHeader(header: UcanHeader): string {
  return base64.urlEncode(JSON.stringify(header))
}

/**
 * Encode the payload of a UCAN.
 *
 * @param payload The UcanPayload to encode
 */
export function encodePayload(payload: UcanPayload): string {
  return base64.urlEncode(JSON.stringify({
    ...payload
  }))
}

/**
 * Check if a UCAN is expired.
 *
 * @param ucan The UCAN to validate
 */
export function isExpired(ucan: Ucan): boolean {
  return ucan.payload.exp <= Math.floor(Date.now() / 1000)
}

/**
 * Check if a UCAN is not active yet.
 *
 * @param ucan The UCAN to validate
 */
export const isTooEarly = (ucan: Ucan): boolean => {
  return ucan.payload.nbf > Math.floor(Date.now() / 1000)
}

/**
 * Check if a UCAN is valid.
 *
 * @param ucan The decoded UCAN
 * @param did The DID associated with the signature of the UCAN
 */
 export async function isValid(ucan: Ucan): Promise<boolean> {
  const encodedHeader = encodeHeader(ucan.header)
  const encodedPayload = encodePayload(ucan.payload)

  const data = uint8arrays.fromString(`${encodedHeader}.${encodedPayload}`)
  const sig = uint8arrays.fromString(ucan.signature, 'base64url')

  const valid = await verifySignature(data, sig, ucan.payload.iss)
  if (!valid) return false
  if (!ucan.payload.prf) return true

  // Verify proofs
  for (const prf of ucan.payload.prf) {
    const proof = decode(prf)
    if (proof.payload.aud !== ucan.payload.iss) return false

    // Check attenuation
    if(!validAttenuation(proof.payload.att, ucan.payload.att)) return false
    if (!await isValid(proof)) return false
  }

  return true
}


/**
 * Generate UCAN signature.
 */
export async function sign(header: UcanHeader, payload: UcanPayload, key: Keypair): Promise<Ucan> {
  return addSignature(header, payload, (data) => key.sign(data))
}

export async function addSignature(header: UcanHeader, payload: UcanPayload, signFn: (data: Uint8Array) => Promise<Uint8Array>): Promise<Ucan> {
  const encodedHeader = encodeHeader(header)
  const encodedPayload = encodePayload(payload)

  const toSign = uint8arrays.fromString(`${encodedHeader}.${encodedPayload}`)
  const sig = await signFn(toSign)

  return {
    header,
    payload,
    signature: uint8arrays.toString(sig, 'base64url')
  }
}

// ㊙️


/**
 * JWT algorithm to be used in a JWT header.
 */
function jwtAlgorithm(keyType: KeyType): string | null {
  switch (keyType) {
    case 'ed25519': return "EdDSA"
    case 'rsa': return "RS256"
    default: return null
  }
}


/**
 * Extract the payload of a UCAN.
 *
 * Throws when given an improperly formatted UCAN.
 */
function extractPayload(ucan: string, level: number): { iss: string; prf: string | null } {
  try {
    return JSON.parse(base64.urlDecode(ucan.split(".")[1]))
  } catch (_) {
    throw new Error(`Invalid UCAN (${level} level${level === 1 ? "" : "s"} deep): \`${ucan}\``)
  }
}
