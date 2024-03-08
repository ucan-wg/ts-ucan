import * as uint8arrays from "uint8arrays"
import * as ed25519 from "@stablelib/ed25519"
import * as crypto from "./crypto.js"

import { DidableKey, Encodings, ExportableKey } from "@ucans/core"
import { PrivateKeyJwk } from "../types.js"


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
    format?: Encodings
    exportable?: boolean
  }): EdKeypair {
    const { format = "base64pad", exportable = false } = params || {}
    const secretKey = uint8arrays.fromString(key, format)
    const publicKey = ed25519.extractPublicKeyFromSecretKey(secretKey)
    return new EdKeypair(secretKey, publicKey, exportable)
  }

  did(): string {
    return crypto.publicKeyToDid(this.publicKey)
  }

  async sign(msg: Uint8Array): Promise<Uint8Array> {
    return ed25519.sign(this.secretKey, msg)
  }

  async export(): Promise<PrivateKeyJwk> {
    if (!this.exportable) {
      throw new Error("Key is not exportable")
    }

    const jwk: PrivateKeyJwk = {
      kty: "EC",
      crv: "Ed25519",
      d: uint8arrays.toString(this.secretKey, "base64pad"),
    }
    return jwk
  }

  static async import(jwk: PrivateKeyJwk, params?: { exportable: boolean }): Promise<EdKeypair> {
    const { exportable = false } = params || {}

    if (jwk.kty !== "EC" || jwk.crv !== "Ed25519") {
      throw new Error("Cannot import key of type: ${jwk.kty} curve: ${jwk.crv} into ED25519 key")
    }

    return EdKeypair.fromSecretKey(jwk.d, { exportable })
  }
}


export default EdKeypair
