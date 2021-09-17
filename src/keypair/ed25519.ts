import nacl from 'tweetnacl'
import BaseKeypair from './base'
import {  KeyType } from '../types'

export default class EdKeypair extends BaseKeypair {

  private secretKey: Uint8Array

  constructor(secretKey: Uint8Array, publicKey: Uint8Array) {
    super(publicKey, KeyType.Edwards)
    this.secretKey = secretKey
  }

  static async create(): Promise<EdKeypair> {
    const keypair = nacl.sign.keyPair()
    return new EdKeypair(keypair.secretKey, keypair.publicKey)
  }

  async sign(msg: Uint8Array): Promise<Uint8Array> {
    return nacl.sign.detached(msg, this.secretKey)
  }

}
