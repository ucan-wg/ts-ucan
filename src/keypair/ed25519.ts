import nacl from 'tweetnacl'
import BaseKeypair from './base'
import {  KeyType } from '../types'

export default class EdKeypair extends BaseKeypair {

  private secretKey: Uint8Array

  constructor(secretKey: Uint8Array, publicKey: Uint8Array, exportable: boolean) {
    super(publicKey, KeyType.Edwards, exportable)
    this.secretKey = secretKey
  }

  static async create(params: {
    exportable: boolean
  }): Promise<EdKeypair> {
    const { exportable } = params
    const keypair = nacl.sign.keyPair()
    return new EdKeypair(keypair.secretKey, keypair.publicKey, exportable)
  }

  async sign(msg: Uint8Array): Promise<Uint8Array> {
    return nacl.sign.detached(msg, this.secretKey)
  }

  async export(): Promise<Uint8Array> {
    if (!this.exportable) {
      throw new Error("Key is not exportable")
    }
    return this.secretKey
  }

}
