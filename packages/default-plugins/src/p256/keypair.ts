import { webcrypto } from "one-webcrypto"
import * as uint8arrays from "uint8arrays"
import { DidableKey, Encodings, ExportableKey } from "@ucans/core"

import * as crypto from "./crypto.js"
import {
  AvailableCryptoKeyPair,
  isAvailableCryptoKeyPair,
  PrivateKeyJwk,
} from "../types.js"


export class EcdsaKeypair implements DidableKey, ExportableKey {

  public jwtAlg = "ES256"

  private publicKey: Uint8Array
  private keypair: AvailableCryptoKeyPair
  private exportable: boolean

  constructor(
    keypair: AvailableCryptoKeyPair,
    publicKey: Uint8Array,
    exportable: boolean
  ) {
    this.keypair = keypair
    this.publicKey = publicKey
    this.exportable = exportable
  }

  static async create(params?: {
    exportable?: boolean
  }): Promise<EcdsaKeypair> {
    const { exportable = false } = params || {}
    const keypair = await crypto.generateKeypair()

    if (!isAvailableCryptoKeyPair(keypair)) {
      throw new Error(`Couldn't generate valid keypair`)
    }

    const publicKey = await crypto.exportKey(keypair.publicKey)
    return new EcdsaKeypair(keypair, publicKey, exportable)
  }

  static async importFromJwk(
    jwk: PrivateKeyJwk,
    params?: {
      exportable?: boolean
    }): Promise<EcdsaKeypair> {
      const { exportable = false } = params || {}
      const keypair = await crypto.importKeypairJwk(jwk, exportable)

      if (!isAvailableCryptoKeyPair(keypair)) {
        throw new Error(`Couldn't generate valid keypair`)
      }

    const publicKey = await crypto.exportKey(keypair.publicKey)
    return new EcdsaKeypair(keypair, publicKey, exportable)
  }

  did(): string {
    return crypto.publicKeyToDid(this.publicKey)
  }

  async sign(msg: Uint8Array): Promise<Uint8Array> {
    return await crypto.sign(msg, this.keypair.privateKey)
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
