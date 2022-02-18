import { webcrypto } from "one-webcrypto"
import * as uint8arrays from "uint8arrays"

export const RSA_ALG = "RSASSA-PKCS1-v1_5"
export const DEFAULT_KEY_SIZE = 2048
export const DEFAULT_HASH_ALG = "SHA-256"
export const SALT_LEGNTH = 128


export const generateKeypair = async (size: number = DEFAULT_KEY_SIZE): Promise<CryptoKeyPair> => {
  return await webcrypto.subtle.generateKey(
    {
      name: RSA_ALG,
      modulusLength: size,
      publicExponent: new Uint8Array([ 0x01, 0x00, 0x01 ]),
      hash: { name: DEFAULT_HASH_ALG }
    },
    false,
    [ "sign", "verify" ]
  )
}

export const exportKey = async (key: CryptoKey): Promise<Uint8Array> => {
  const buf = await webcrypto.subtle.exportKey("spki", key)
  return new Uint8Array(buf)
}

export const importKey = async (key: Uint8Array): Promise<CryptoKey> => {
  return await webcrypto.subtle.importKey(
    "spki",
    key.buffer,
    { name: RSA_ALG, hash: { name: DEFAULT_HASH_ALG } },
    true,
    [ "verify" ]
  )
}

export const sign = async (msg: Uint8Array, privateKey: CryptoKey): Promise<Uint8Array> => {
  const buf = await webcrypto.subtle.sign(
    { name: RSA_ALG, saltLength: SALT_LEGNTH },
    privateKey,
    msg.buffer
  )
  return new Uint8Array(buf)
}

export const verify = async (msg: Uint8Array, sig: Uint8Array, pubKey: Uint8Array): Promise<boolean> => {
  return await webcrypto.subtle.verify(
    { name: RSA_ALG, saltLength: SALT_LEGNTH },
    await importKey(pubKey),
    sig.buffer,
    msg.buffer
  )
}

/**
 * The ASN.1 DER encoded header that needs to be added to an
 * ASN.1 DER encoded RSAPublicKey to make it a SubjectPublicKeyInfo.
 *
 * This byte sequence is always the same.
 *
 * A human-readable version of this as part of a dumpasn1 dump:
 *
 *     SEQUENCE {
 *       OBJECT IDENTIFIER rsaEncryption (1 2 840 113549 1 1 1)
 *       NULL
 *     }
 *
 * See https://github.com/ucan-wg/ts-ucan/issues/30
 */
const SPKI_PARAMS_ENCODED = new Uint8Array([ 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0 ])
const ASN_SEQUENCE_TAG = new Uint8Array([ 0x30 ])
const ASN_BITSTRING_TAG = new Uint8Array([ 0x03 ])

export const convertRSAPublicKeyToSubjectPublicKeyInfo = (rsaPublicKey: Uint8Array): Uint8Array => {
  // More info on bitstring encoding: https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-bit-string
  const bitStringEncoded = uint8arrays.concat([
    ASN_BITSTRING_TAG,
    asn1DERLengthEncode(rsaPublicKey.length + 1),
    new Uint8Array([ 0x00 ]), // amount of unused bits at the end of our bitstring (counts into length?!)
    rsaPublicKey
  ])
  return uint8arrays.concat([
    ASN_SEQUENCE_TAG,
    asn1DERLengthEncode(SPKI_PARAMS_ENCODED.length + bitStringEncoded.length),
    SPKI_PARAMS_ENCODED,
    bitStringEncoded,
  ])
}

export const convertSubjectPublicKeyInfoToRSAPublicKey = (subjectPublicKeyInfo: Uint8Array): Uint8Array => {
  let position = 0
  // go into the top-level SEQUENCE
  position = asn1Into(subjectPublicKeyInfo, ASN_SEQUENCE_TAG, position).position
  // skip the header we expect (SKPI_PARAMS_ENCODED)
  position = asn1Skip(subjectPublicKeyInfo, ASN_SEQUENCE_TAG, position)
  // we expect the bitstring next
  const bitstringParams = asn1Into(subjectPublicKeyInfo, ASN_BITSTRING_TAG, position)
  const bitstring = subjectPublicKeyInfo.subarray(bitstringParams.position, bitstringParams.position + bitstringParams.length)
  const unusedBitPadding = bitstring[ 0 ]
  if (unusedBitPadding !== 0) {
    throw new Error(`Can't convert SPKI to PKCS: Expected bitstring length to be multiple of 8, but got ${unusedBitPadding} unused bits in last byte.`)
  }
  return bitstring.slice(1)
}

// ㊙️
// but some exposed for testing :/

export function asn1DERLengthEncode(length: number): Uint8Array {
  if (length < 0 || !isFinite(length)) {
    throw new TypeError(`Expected non-negative number. Got ${length}`)
  }

  if (length <= 127) {
    return new Uint8Array([ length ])
  }

  const octets: number[] = []
  while (length !== 0) {
    octets.push(length & 0xFF)
    length = length >>> 8
  }
  octets.reverse()
  return new Uint8Array([ 0x80 | (octets.length & 0xFF), ...octets ])
}

function asn1DERLengthDecodeWithConsumed(bytes: Uint8Array): { number: number; consumed: number } {
  if ((bytes[ 0 ] & 0x80) === 0) {
    return { number: bytes[ 0 ], consumed: 1 }
  }

  const numberBytes = bytes[ 0 ] & 0x7F
  if (bytes.length < numberBytes + 1) {
    throw new Error(`ASN parsing error: Too few bytes. Expected encoded length's length to be at least ${numberBytes}`)
  }

  let length = 0
  for (let i = 0; i < numberBytes; i++) {
    length = length << 8
    length = length | bytes[ i + 1 ]
  }
  return { number: length, consumed: numberBytes + 1 }
}

export function asn1DERLengthDecode(bytes: Uint8Array): number {
  return asn1DERLengthDecodeWithConsumed(bytes).number
}

function asn1Skip(input: Uint8Array, expectedTag: Uint8Array, position: number): number {
  const parsed = asn1Into(input, expectedTag, position)
  return parsed.position + parsed.length
}

function asn1Into(input: Uint8Array, expectedTag: Uint8Array, position: number): { position: number; length: number } {
  // tag
  const lengthPos = position + expectedTag.length
  const actualTag = input.subarray(position, lengthPos)
  if (!uint8arrays.equals(actualTag, expectedTag)) {
    throw new Error(`ASN parsing error: Expected tag 0x${uint8arrays.toString(expectedTag, "hex")} at position ${position}, but got ${uint8arrays.toString(actualTag, "hex")}.`)
  }

  // length
  const length = asn1DERLengthDecodeWithConsumed(input.subarray(lengthPos/*, we don't know the end */))
  const contentPos = position + 1 + length.consumed

  // content
  return { position: contentPos, length: length.number }
}
