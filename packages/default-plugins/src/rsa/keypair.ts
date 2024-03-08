import * as crypto from "./crypto.js"
import { AvailableCryptoKeyPair, PrivateKeyJwk, isAvailableCryptoKeyPair } from "../types.js"
import { DidableKey, ExportableKey } from "@ucans/core"


export class RsaKeypair implements DidableKey, ExportableKey {

  public jwtAlg = "RS256"

  private publicKey: Uint8Array
  private keypair: AvailableCryptoKeyPair
  private exportable: boolean

  constructor(keypair: AvailableCryptoKeyPair, publicKey: Uint8Array, exportable: boolean) {
    this.keypair = keypair
    this.publicKey = publicKey
    this.exportable = exportable
  }

  static async create(params?: {
    size?: number
    exportable?: boolean
  }): Promise<RsaKeypair> {
    const { size = 2048, exportable = false } = params || {}
    const keypair = await crypto.generateKeypair(size, exportable)
    if (!isAvailableCryptoKeyPair(keypair)) {
      throw new Error(`Couldn't generate valid keypair`)
    }
    const publicKey = await crypto.exportKey(keypair.publicKey)
    return new RsaKeypair(keypair, publicKey, exportable)
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
    return await crypto.exportPrivateKeyJwk(this.keypair) as PrivateKeyJwk
  }

  static async importFromJwk(jwk: PrivateKeyJwk, params: { exportable: true }): Promise<RsaKeypair> {
    const { exportable = false } = params || {}
    const keypair = await crypto.importKeypairJwk(jwk, exportable)

    if (!isAvailableCryptoKeyPair(keypair)) {
      throw new Error(`Couldn't generate valid keypair`)
    }

    const publicKey = await crypto.exportKey(keypair.publicKey)
    return new RsaKeypair(keypair, publicKey, exportable)
  }

  static async import(jwk: PrivateKeyJwk): Promise<RsaKeypair> {
    return RsaKeypair.importFromJwk(jwk, { exportable: true })
  }
}

export default RsaKeypair
