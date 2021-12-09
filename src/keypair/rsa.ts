import * as rsa  from "../crypto/rsa"
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
    throw new Error("Exporting not enabled for RSA yet")
  }

}

export default RsaKeypair
