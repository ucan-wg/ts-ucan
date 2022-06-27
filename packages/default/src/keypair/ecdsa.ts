import { webcrypto } from "one-webcrypto"
import * as uint8arrays from "uint8arrays"

import * as ecdsa from "../crypto/ecdsa.js"
import {
  AvailableCryptoKeyPair,
  Encodings,
  isAvailableCryptoKeyPair,
  NamedCurve,
  PrivateKeyJwk,
} from "../types.js"
import BaseKeypair from "./base.js"

export class EcdsaKeypair extends BaseKeypair {
  private keypair: AvailableCryptoKeyPair

  constructor(
    keypair: AvailableCryptoKeyPair,
    publicKey: Uint8Array,
    namedCurve: NamedCurve,
    exportable: boolean
  ) {
    super(publicKey, ecdsa.toKeyType(namedCurve), exportable)
    this.keypair = keypair
  }

  static async create(params?: {
    namedCurve?: NamedCurve
    exportable?: boolean
  }): Promise<EcdsaKeypair> {
    const { namedCurve = "P-256", exportable = false } = params || {}
    const keypair = await ecdsa.generateKeypair(namedCurve)

    if (!isAvailableCryptoKeyPair(keypair)) {
      throw new Error(`Couldn't generate valid keypair`)
    }

    const publicKey = await ecdsa.exportKey(keypair.publicKey)
    return new EcdsaKeypair(keypair, publicKey, namedCurve, exportable)
  }

  static async importFromJwk(
    jwk: PrivateKeyJwk,
    params?: {
      namedCurve?: NamedCurve
      exportable?: boolean
    }): Promise<EcdsaKeypair> {
      const { namedCurve = "P-256", exportable = false } = params || {}
      const keypair = await ecdsa.importKeypairJwk(jwk, namedCurve, exportable)

      if (!isAvailableCryptoKeyPair(keypair)) {
        throw new Error(`Couldn't generate valid keypair`)
      }

    const publicKey = await ecdsa.exportKey(keypair.publicKey)
    return new EcdsaKeypair(keypair, publicKey, namedCurve, exportable)
    }

  async sign(msg: Uint8Array): Promise<Uint8Array> {
    return await ecdsa.sign(msg, this.keypair.privateKey)
  }

  async export(format: Encodings = "base64pad"): Promise<string> {
    if (!this.exportable) {
      throw new Error("Key is not exportable")
    }
    const arrayBuffer = await webcrypto.subtle.exportKey(
      "pkcs8",
      this.keypair.privateKey
    )
    return uint8arrays.toString(new Uint8Array(arrayBuffer), format)
  }
}

export default EcdsaKeypair
