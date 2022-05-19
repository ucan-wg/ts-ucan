import * as uint8arrays from "uint8arrays"

import * as capability from "./capability/index.js"
import * as did from "./did.js"
import * as util from "./util.js"

import { Capability, isCapability, isEncodedCapability } from "./capability/index.js"
import { Fact, KeyType, Keypair } from "./types.js"
import { Ucan, UcanHeader, UcanParts, UcanPayload } from "./types.js"
import { handleCompatibility } from "./compatibility.js"
import { verifySignatureUtf8 } from "./did/validation.js"


// CONSTANTS


const TYPE = "JWT"
const VERSION = "0.8.1"



// COMPOSING


/**
 * Create a UCAN, User Controlled Authorization Networks, JWT.
 *
 * ### Header
 *
 * `alg`, Algorithm, the type of signature.
 * `typ`, Type, the type of this data structure, JWT.
 * `ucv`, UCAN version.
 *
 * ### Payload
 *
 * `att`, Attenuation, a list of resources and capabilities that the ucan grants.
 * `aud`, Audience, the ID of who it's intended for.
 * `exp`, Expiry, unix timestamp of when the jwt is no longer valid.
 * `fct`, Facts, an array of extra facts or information to attach to the jwt.
 * `iss`, Issuer, the ID of who sent this.
 * `nbf`, Not Before, unix timestamp of when the jwt becomes valid.
 * `nnc`, Nonce, a randomly generated string, used to ensure the uniqueness of the jwt.
 * `prf`, Proofs, nested tokens with equal or greater privileges.
 *
 */
export async function build(params: {
  // from/to
  issuer: Keypair
  audience: string

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
}): Promise<Ucan> {
  const keypair = params.issuer
  const didStr = did.publicKeyBytesToDid(keypair.publicKey, keypair.keyType)
  const payload = buildPayload({ ...params, issuer: didStr })
  return signWithKeypair(payload, keypair)
}

/**
 * Construct the payload for a UCAN.
 */
export function buildPayload(params: {
  // from/to
  issuer: string
  audience: string

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
}): UcanPayload {
  const {
    issuer,
    audience,
    capabilities = [],
    lifetimeInSeconds = 30,
    expiration,
    notBefore,
    facts,
    proofs = [],
    addNonce = false
  } = params

  // Validate
  if (!issuer.startsWith("did:")) throw new Error("The issuer must be a DID")
  if (!audience.startsWith("did:")) throw new Error("The audience must be a DID")

  // Timestamps
  const currentTimeInSeconds = Math.floor(Date.now() / 1000)
  const exp = expiration || (currentTimeInSeconds + lifetimeInSeconds)

  // 📦
  return {
    aud: audience,
    att: capabilities,
    exp,
    fct: facts,
    iss: issuer,
    nbf: notBefore,
    nnc: addNonce ? util.generateNonce() : undefined,
    prf: proofs,
  }
}

/**
 * Encloses a UCAN payload as to form a finalised UCAN.
 */
export async function sign(
  payload: UcanPayload,
  keyType: KeyType,
  signFn: (data: Uint8Array) => Promise<Uint8Array>
): Promise<Ucan> {
  const header: UcanHeader = {
    alg: jwtAlgorithm(keyType),
    typ: TYPE,
    ucv: VERSION,
  }

  // Issuer key type must match UCAN algorithm
  if (did.didToPublicKey(payload.iss).type !== keyType) {
    throw new Error("The issuer's key type must match the given key type.")
  }

  // Encode parts
  const encodedHeader = encodeHeader(header)
  const encodedPayload = encodePayload(payload)

  // Sign
  const toSign = uint8arrays.fromString(`${encodedHeader}.${encodedPayload}`, "utf8")
  const sig = await signFn(toSign)

  // 📦
  return {
    header,
    payload,
    signature: uint8arrays.toString(sig, "base64url")
  }
}

/**
 * `sign` with a `Keypair`.
 */
export async function signWithKeypair(
  payload: UcanPayload,
  keypair: Keypair
): Promise<Ucan> {
  return sign(
    payload,
    keypair.keyType,
    data => keypair.sign(data)
  )
}



// ENCODING


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
 * @returns The header of a UCAN encoded as url-safe base64 JSON
 */
export function encodeHeader(header: UcanHeader): string {
  return uint8arrays.toString(
    uint8arrays.fromString(JSON.stringify(header), "utf8"),
    "base64url"
  )
}

/**
 * Encode the payload of a UCAN.
 *
 * NOTE: This will encode capabilities as well, so that it matches the UCAN spec.
 *       In other words, `{ with: { scheme, hierPart }, can: { namespace, segments } }`
 *       becomes `{ with: "${scheme}:${hierPart}", can: "${namespace}/${segment}" }`
 *
 * @param payload The UcanPayload to encode
 */
export function encodePayload(payload: UcanPayload): string {
  const payloadWithEncodedCaps = {
    ...payload,
    att: payload.att.map(capability.encode)
  }

  return uint8arrays.toString(
    uint8arrays.fromString(JSON.stringify(payloadWithEncodedCaps), "utf8"),
    "base64url"
  )
}

/**
 * Parse an encoded UCAN.
 *
 * @param encodedUcan The encoded UCAN.
 */
export function parse(encodedUcan: string): UcanParts {
  const [ encodedHeader, encodedPayload, signature ] = encodedUcan.split(".")

  if (encodedHeader == null || encodedPayload == null || signature == null) {
    throw new Error(`Can't parse UCAN: ${encodedUcan}: Expected JWT format: 3 dot-separated base64url-encoded values.`)
  }

  // Header
  let headerJson: string
  let headerObject: unknown

  try {
    headerJson = uint8arrays.toString(
      uint8arrays.fromString(encodedHeader, "base64url"),
      "utf8"
    )
  } catch {
    throw new Error(`Can't parse UCAN header: ${encodedHeader}: Can't parse as base64url.`)
  }

  try {
    headerObject = JSON.parse(headerJson)
  } catch {
    throw new Error(`Can't parse UCAN header: ${encodedHeader}: Can't parse encoded JSON inside.`)
  }

  // Payload
  let payloadJson: string
  let payloadObject: unknown

  try {
    payloadJson = uint8arrays.toString(
      uint8arrays.fromString(encodedPayload, "base64url"),
      "utf8"
    )
  } catch {
    throw new Error(`Can't parse UCAN payload: ${encodedPayload}: Can't parse as base64url.`)
  }

  try {
    payloadObject = JSON.parse(payloadJson)
  } catch {
    throw new Error(`Can't parse UCAN payload: ${encodedPayload}: Can't parse encoded JSON inside.`)
  }

  // Compatibility layer
  const { header, payload } = handleCompatibility(headerObject, payloadObject)

  // Ensure proper types/structure
  const parsedAttenuations = payload.att.reduce((acc: Capability[], cap: unknown): Capability[] => {
    return isEncodedCapability(cap)
      ? [ ...acc, capability.parse(cap) ]
      : isCapability(cap) ? [ ...acc, cap ] : acc
  }, [])

  // Fin
  return {
    header: header,
    payload: { ...payload, att: parsedAttenuations }
  }
}



// VALIDATION


/**
 * Validation options
 */
export interface ValidateOptions {
  checkIssuer?: boolean
  checkIsExpired?: boolean
  checkIsTooEarly?: boolean
  checkSignature?: boolean
}

/**
 * Parse & Validate **one layer** of a UCAN.
 * This doesn't validate attenutations and doesn't validate the whole UCAN chain.
 *
 * By default, this will check the signature and time bounds.
 *
 * @param encodedUcan the JWT-encoded UCAN to validate
 * @param options an optional parameter to configure turning off some validation options
 * @returns the parsed & validated UCAN (one layer)
 * @throws Error if the UCAN is invalid
 */
export async function validate(encodedUcan: string, options?: ValidateOptions): Promise<Ucan> {
  const checkIssuer = options?.checkIssuer ?? true
  const checkIsExpired = options?.checkIsExpired ?? true
  const checkIsTooEarly = options?.checkIsTooEarly ?? true
  const checkSignature = options?.checkSignature ?? true

  const { header, payload } = parse(encodedUcan)
  const [ encodedHeader, encodedPayload, signature ] = encodedUcan.split(".")

  if (checkIssuer) {
    const issuerKeyType = did.didToPublicKey(payload.iss).type
    if (jwtAlgorithm(issuerKeyType) !== header.alg) {
      throw new Error(`Invalid UCAN: ${encodedUcan}: Issuer key type does not match UCAN's \`alg\` property.`)
    }
  }

  if (checkSignature) {
    if (!await verifySignatureUtf8(`${encodedHeader}.${encodedPayload}`, signature, payload.iss)) {
      throw new Error(`Invalid UCAN: ${encodedUcan}: Signature invalid.`)
    }
  }

  const ucan: Ucan = { header, payload, signature }

  if (checkIsExpired && isExpired(ucan)) {
    throw new Error(`Invalid UCAN: ${encodedUcan}: Expired.`)
  }

  if (checkIsTooEarly && isTooEarly(ucan)) {
    throw new Error(`Invalid UCAN: ${encodedUcan}: Not active yet (too early).`)
  }

  return ucan
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
  if (ucan.payload.nbf == null) return false
  return ucan.payload.nbf > Math.floor(Date.now() / 1000)
}



// ㊙️


/**
 * JWT algorithm to be used in a JWT header.
 *
 * TODO(appcypher): Learn more about JWA spec.
 * The algorithms here are not JWA spec-compliant even though they may have similar names.
 * keyType does not say anything about the hash functions used in encryption algorithms which JWA seems to make explicit.
 *
 * See https://datatracker.ietf.org/doc/html/rfc7518#page-6
 */
function jwtAlgorithm(keyType: KeyType): string {
  switch (keyType) {
    case "bls12-381": throw new Error(`Unknown KeyType "${keyType}"`)
    case "ed25519": return "EdDSA"
    case "rsa": return "RS256"
    case "p256": return "ES256"
    case "p384": return "ES384"
    case "p521": return "ES521"
    default: throw new Error(`Unknown KeyType "${keyType}"`)
  }
}
