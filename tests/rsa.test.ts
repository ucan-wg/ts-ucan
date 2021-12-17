import * as did from "../src/did"
import RSAKeypair from "../src/keypair/rsa"

describe("rsa", () => {

  let keypair: RSAKeypair
  let signature: Uint8Array
  const data = new Uint8Array([1,2,3,4,5,6,7,8,9])

  it("creates an rsa keypair", async () => {
    keypair = await RSAKeypair.create()
  })

  it("returns a publicKeyStr and did", () => {
    const publicKey = keypair.publicKeyStr()
    const keyDid = keypair.did()
    const transformed = did.didToPublicKey(keyDid)
    expect(transformed.publicKey).toEqual(publicKey)
    expect(transformed.type).toEqual("rsa")
  })

  it("signs data", async () => {
    signature = await keypair.sign(data)
  })

  it("can verify signature", async () => {
    const isValid = await did.verifySignature(data, signature, keypair.did())
    expect(isValid).toEqual(true)
  })

})
