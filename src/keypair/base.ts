import * as uint8arrays from 'uint8arrays'
import { publicKeyBytesToDid } from '../did/transformers'
import { Keypair, KeyType, Encodings } from '../types'

export default abstract class BaseKeypair implements Keypair {

  publicKey: Uint8Array
  keyType: KeyType

  constructor (publicKey: Uint8Array, keyType: KeyType) {
    this.publicKey = publicKey
    this.keyType = keyType
  }


  publicKeyStr(encoding: Encodings = 'base64pad'): string {
    return uint8arrays.toString(this.publicKey, encoding)
  }

  did(): string {
    return publicKeyBytesToDid(this.publicKey, this.keyType)
  }

  abstract sign(msg: Uint8Array): Promise<Uint8Array>
}
