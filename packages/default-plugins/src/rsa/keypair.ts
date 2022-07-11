import { webcrypto } from "one-webcrypto"
import * as uint8arrays from "uint8arrays"

import * as crypto from "./crypto.js"
import { AvailableCryptoKeyPair, isAvailableCryptoKeyPair } from "../types.js"
import { DidableKey, Encodings, ExportableKey } from "@ucans/core"


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
    const keypair = await crypto.generateKeypair(size)
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

  async export(format: Encodings = "base64pad"): Promise<string> {
    if (!this.exportable) {
      throw new Error("Key is not exportable")
    }
    const arrayBuffer = await webcrypto.subtle.exportKey("pkcs8", this.keypair.privateKey)
    return uint8arrays.toString(new Uint8Array(arrayBuffer), format)
  }

}

export default RsaKeypair
