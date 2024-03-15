import * as uint8arrays from "uint8arrays"
import { ed25519Plugin } from "../src/ed25519/plugin.js"
import EdwardsKey, { EdKeypair } from "../src/ed25519/keypair.js"

describe("ed25519", () => {

  let keypair: EdwardsKey
  let signature: Uint8Array
  const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9])

  it("creates an edwards curve keypair", async () => {
    keypair = await EdwardsKey.create()
  })

  it("has the correct JWT alg", async () => {
    expect(keypair.jwtAlg).toEqual("EdDSA")
  })

  it("signs data", async () => {
    signature = await keypair.sign(data)
  })

  it("can verify signature", async () => {
    const isValid = await ed25519Plugin.verifySignature(keypair.did(), data, signature)
    expect(isValid).toBeTruthy()
  })

})

describe("Import / Export", () => {
  let exportableKey: EdKeypair
  let nonExportableKey: EdKeypair

  beforeAll(async () => {
    exportableKey = await EdKeypair.create({ exportable: true })
    nonExportableKey = await EdKeypair.create({ exportable: false })
  })

  it("Will export a key that is exportable", async () => {
    const exported = exportableKey.export()
    expect(exported).not.toBe(null)
  })

  it("Will not export a key that is not exportable", async () => {
    await expect(nonExportableKey.export())
      .rejects
      .toThrow("Key is not exportable")
  })

  it("Will import an exported key", async () => {
    const exported = await exportableKey.export()
    const newKey = await EdKeypair.import(exported)

    expect(newKey.did()).toEqual(exportableKey.did())

    // Sign and verify
    const msg = uint8arrays.fromString("test signing", "utf-8")
    let signed = await exportableKey.sign(msg)
    expect(await ed25519Plugin.verifySignature(await newKey.did(), msg, signed)).toBe(true)

    signed = await newKey.sign(msg)
    expect(await ed25519Plugin.verifySignature(await exportableKey.did(), msg, signed)).toBe(true)
  })
})