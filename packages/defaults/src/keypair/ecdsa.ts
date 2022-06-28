import { webcrypto } from "one-webcrypto"
import * as uint8arrays from "uint8arrays"
import { Encodings } from '@ucans/core'

import * as ecdsa from "../crypto/ecdsa.js"
import {
  AvailableCryptoKeyPair,
  isAvailableCryptoKeyPair,
  PrivateKeyJwk,
} from "../types.js"
import BaseKeypair from "./base.js"

export class EcdsaKeypair extends BaseKeypair {
  private keypair: AvailableCryptoKeyPair

  constructor(
    keypair: AvailableCryptoKeyPair,
    publicKey: Uint8Array,
    exportable: boolean
  ) {
    super(publicKey, "p256", exportable)
    this.keypair = keypair
  }

  static async create(params?: {
    exportable?: boolean
  }): Promise<EcdsaKeypair> {
    const { exportable = false } = params || {}
    const keypair = await ecdsa.generateKeypair()

    if (!isAvailableCryptoKeyPair(keypair)) {
      throw new Error(`Couldn't generate valid keypair`)
    }

    const publicKey = await ecdsa.exportKey(keypair.publicKey)
    return new EcdsaKeypair(keypair, publicKey, exportable)
  }

  static async importFromJwk(
    jwk: PrivateKeyJwk,
    params?: {
      exportable?: boolean
    }): Promise<EcdsaKeypair> {
      const { exportable = false } = params || {}
      const keypair = await ecdsa.importKeypairJwk(jwk, exportable)

      if (!isAvailableCryptoKeyPair(keypair)) {
        throw new Error(`Couldn't generate valid keypair`)
      }

    const publicKey = await ecdsa.exportKey(keypair.publicKey)
    return new EcdsaKeypair(keypair, publicKey, exportable)
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
