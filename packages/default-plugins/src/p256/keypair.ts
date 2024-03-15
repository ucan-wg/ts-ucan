import { DidableKey, ExportableKey } from "@ucans/core"

import * as crypto from "./crypto.js"
import {
  AvailableCryptoKeyPair,
  isAvailableCryptoKeyPair,
  PrivateKeyJwk,
} from "../types.js"


export class EcdsaKeypair implements DidableKey, ExportableKey<PrivateKeyJwk> {

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
    const keypair = await crypto.generateKeypair(exportable)

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

  async export(): Promise<PrivateKeyJwk> {
    if (!this.exportable) {
      throw new Error("Key is not exportable")
    }
    return await crypto.exportPrivateKeyJwk(this.keypair)
  }

  /**
   * Convenience function on the Keypair class to allow for keys to be exported / persisted.
   * This is most useful for situations where you want to have consistent keys between restarts.
   * A Developer can export a key, save it in a vault, and rehydrate it for use in a later run.
   * @param jwk 
   * @returns 
   */
  static async import(jwk: PrivateKeyJwk): Promise<EcdsaKeypair> {
    return EcdsaKeypair.importFromJwk(jwk, { exportable: true })
  }
}

export default EcdsaKeypair
