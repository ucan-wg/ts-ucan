import { webcrypto } from "one-webcrypto"
import * as uint8arrays from "uint8arrays"

import * as rsa from "../crypto/rsa"
import BaseKeypair from "./base"
import { Encodings, AvailableCryptoKeyPair, isAvailableCryptoKeyPair } from "../types"


export class RsaKeypair extends BaseKeypair {

  private keypair: AvailableCryptoKeyPair

  constructor(keypair: AvailableCryptoKeyPair, publicKey: Uint8Array, exportable: boolean) {
    super(publicKey, "rsa", exportable)
    this.keypair = keypair
  }

  static async create(params?: {
    size?: number
    exportable?: boolean
  }): Promise<RsaKeypair> {
    const { size = 2048, exportable = false } = params || {}
    const keypair = await rsa.generateKeypair(size)
    if (!isAvailableCryptoKeyPair(keypair)) {
      throw new Error(`Couldn't generate valid keypair`)
    }
    const publicKey = await rsa.exportKey(keypair.publicKey)
    return new RsaKeypair(keypair, publicKey, exportable)
  }

  async sign(msg: Uint8Array): Promise<Uint8Array> {
    return await rsa.sign(msg, this.keypair.privateKey)
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
