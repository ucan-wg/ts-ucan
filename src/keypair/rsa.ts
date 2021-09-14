import * as rsa  from '../crypto/rsa'
import BaseKeypair from './base'
import {  KeyType } from '../types'

export default class RsaKeypair extends BaseKeypair {

  private keypair: CryptoKeyPair

  constructor(keypair: CryptoKeyPair, publicKey: Uint8Array) {
    super(publicKey, KeyType.RSA)
    this.keypair = keypair
  }

  static async create(size: number = 2048): Promise<RsaKeypair> {
    const keypair = await rsa.generateKeypair(size)
    const publicKey = await rsa.exportKey(keypair.publicKey)
    return new RsaKeypair(keypair, publicKey)
  }

  async sign(msg: Uint8Array): Promise<Uint8Array> {
    return await rsa.sign(msg, this.keypair)
  }

}
