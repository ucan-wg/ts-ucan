import * as ed from 'noble-ed25519'
import BaseKeypair from './base'
import {  KeyType } from '../types'

export default class EdKeypair extends BaseKeypair {

  private secretKey: Uint8Array

  constructor(secretKey: Uint8Array, publicKey: Uint8Array) {
    super(publicKey, KeyType.Edwards)
    this.secretKey = secretKey
  }

  static async create(): Promise<EdKeypair> {
    const secretKey = ed.utils.randomPrivateKey()
    const publicKey = await ed.getPublicKey(secretKey)
    return new EdKeypair(secretKey, publicKey)
  }

  async sign(msg: Uint8Array): Promise<Uint8Array> {
    return ed.sign(msg, this.secretKey)
  }

}
