import * as uint8arrays from "uint8arrays"
import { publicKeyBytesToDid } from "../did/transformers"
import { Keypair, KeyType, Encodings, Didable, ExportableKey } from "../types"


export default abstract class BaseKeypair implements Keypair, Didable, ExportableKey {

  publicKey: Uint8Array
  keyType: KeyType
  exportable: boolean

  constructor(publicKey: Uint8Array, keyType: KeyType, exportable: boolean) {
    this.publicKey = publicKey
    this.keyType = keyType
    this.exportable = exportable
  }

  publicKeyStr(encoding: Encodings = "base64pad"): string {
    return uint8arrays.toString(this.publicKey, encoding)
  }

  did(): string {
    return publicKeyBytesToDid(this.publicKey, this.keyType)
  }

  abstract sign(msg: Uint8Array): Promise<Uint8Array>
  abstract export(): Promise<string>
}
