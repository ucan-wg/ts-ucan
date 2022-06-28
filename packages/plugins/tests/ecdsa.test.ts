import * as did from "../src/did"
import ECDSAKeyPair from "../src/keypair/ecdsa"


describe("ecdsa", () => {

  let p256Keypair: ECDSAKeyPair

  let p256Signature: Uint8Array

  const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9])

  it("creates an ecdsa keypairs with different curves", async () => {
    p256Keypair = await ECDSAKeyPair.create()
  })

  it("returns a publicKeyStr and did: curve P-256", () => {
    const keyDid = p256Keypair.did()
    const publicKey = p256Keypair.publicKeyStr()
    const transformed = did.didToPublicKey(keyDid)
    expect(transformed.publicKey).toEqual(publicKey)
    expect(transformed.type).toEqual("p256")
  })

  it("signs data: curve P-256", async () => {
    p256Signature = await p256Keypair.sign(data)
  })

  it("can verify signature: P-256", async () => {
    const isValid = await did.verifySignature(data, p256Signature, p256Keypair.did())
    expect(isValid).toBeTruthy()
  })

})
