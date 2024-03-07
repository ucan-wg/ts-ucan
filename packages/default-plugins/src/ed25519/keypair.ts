import * as ed25519 from "@stablelib/ed25519"
import * as crypto from "./crypto.js"

import { DidableKey, Encodings, ExportableKey } from "@ucans/core"


export class EdKeypair implements DidableKey, ExportableKey {

  public jwtAlg = "EdDSA"

  private secretKey: Uint8Array
  private publicKey: Uint8Array
  private exportable: boolean

  constructor(secretKey: Uint8Array, publicKey: Uint8Array, exportable: boolean) {
    this.secretKey = secretKey
    this.publicKey = publicKey
    this.exportable = exportable
  }

  static async create(params?: {
    exportable: boolean
  }): Promise<EdKeypair> {
    const { exportable } = params || {}
    const keypair = ed25519.generateKeyPair()
    return new EdKeypair(keypair.secretKey, keypair.publicKey, exportable ?? false)
  }

  static fromSecretKey(key: string, params?: {
    exportable?: boolean
  }): EdKeypair {
    const { exportable = false } = params || {}

    const secretKey = new Uint8Array(Buffer.from(key, 'base64'))
    const publicKey = ed25519.extractPublicKeyFromSecretKey(secretKey)
    return new EdKeypair(secretKey, publicKey, exportable)
  }

  did(): string {
    return crypto.publicKeyToDid(this.publicKey)
  }

  async sign(msg: Uint8Array): Promise<Uint8Array> {
    return ed25519.sign(this.secretKey, msg)
  }

  async export(): Promise<string> {
    if (!this.exportable) {
      throw new Error("Key is not exportable")
    }
    const buf = Buffer.from(this.secretKey)
    return buf.toString('base64')
  }

  static async import(secretKey: string, params?: { exportable: boolean }): Promise<EdKeypair> {
    const { exportable = false } = params || {}
    return EdKeypair.fromSecretKey(secretKey, { exportable })
  }
}


export default EdKeypair
