import * as uint8arrays from "uint8arrays"

import * as semver from "./semver.js"
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
const VERSION = { major: 0, minor: 8, patch: 1 }



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
  const signedData = `${encodedHeader}.${encodedPayload}`
  const toSign = uint8arrays.fromString(signedData, "utf8")
  const sig = await signFn(toSign)

  // 📦
  // we freeze the object to make it more unlikely
  // for signedData & header/payload to get out of sync
  return Object.freeze({
    header,
    payload,
    signedData,
    signature: uint8arrays.toString(sig, "base64url")
  })
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
export function encode(ucan: Ucan<unknown>): string {
  return `${ucan.signedData}.${ucan.signature}`
}

/**
 * Encode the header of a UCAN.
 *
 * @param header The UcanHeader to encode
 * @returns The header of a UCAN encoded as url-safe base64 JSON
 */
export function encodeHeader(header: UcanHeader): string {
  const headerFormatted = {
    ...header,
    ucv: semver.format(header.ucv)
  }
  return uint8arrays.toString(
    uint8arrays.fromString(JSON.stringify(headerFormatted), "utf8"),
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

  const signedData = `${encodedHeader}.${encodedPayload}`
  const ucan: Ucan = { header, payload, signedData, signature }

  if (checkIsExpired && isExpired(ucan)) {
    throw new Error(`Invalid UCAN: ${encodedUcan}: Expired.`)
  }

  if (checkIsTooEarly && isTooEarly(ucan)) {
    throw new Error(`Invalid UCAN: ${encodedUcan}: Not active yet (too early).`)
  }

  return ucan
}

/**
 * Iterates over all proofs and parses & validates them at the same time.
 * 
 * If there's an audience/issuer mismatch, the iterated item will contain an `Error`.
 * Otherwise the iterated out will contain a `Ucan`.
 * 
 * @param ucan a parsed UCAN
 * @param options optional ValidateOptions to use for validating each proof
 * @return an async iterator of the given ucan's proofs parsed & validated, or an `Error`
 *         for each proof that couldn't be validated or parsed.
 */
export async function* validateProofs(ucan: Ucan, options?: ValidateOptions): AsyncIterable<Ucan | Error> {
  for (const prf of ucan.payload.prf) {
    try {
      const proof = await validate(prf, options)

      if (proof.payload.aud !== ucan.payload.iss) {
        throw new Error(`Invalid UCAN: Proof's audience ${proof.payload.aud} doesn't match issuer ${ucan.payload.iss}`)
      }

      yield proof
    } catch (e) {
      if (e instanceof Error) {
        yield e
      } else {
        yield new Error(`Error when trying to parse UCAN proof: ${e}`)
      }
    }
  }
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
 */
function jwtAlgorithm(keyType: KeyType): string {
  switch (keyType) {
    case "bls12-381": throw new Error(`Unknown KeyType "${keyType}"`)
    case "ed25519": return "EdDSA"
    case "rsa": return "RS256"
    default: throw new Error(`Unknown KeyType "${keyType}"`)
  }
}
