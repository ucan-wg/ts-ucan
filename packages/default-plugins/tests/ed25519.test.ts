import { ed25519Plugin } from "../src/ed25519/plugin.js"
import EdwardsKey from "../src/ed25519/keypair.js"

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
