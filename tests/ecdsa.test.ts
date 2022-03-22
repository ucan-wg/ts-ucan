import * as did from "../src/did"
import ECDSAKeyPair from "../src/keypair/ecdsa"


describe("ecdsa", () => {

  let p256Keypair: ECDSAKeyPair
  let p384Keypair: ECDSAKeyPair
  let p521Keypair: ECDSAKeyPair

  let p256Signature: Uint8Array
  let p384Signature: Uint8Array
  let p521Signature: Uint8Array

  const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9])

  it("creates an ecdsa keypairs with different curves", async () => {
    p256Keypair = await ECDSAKeyPair.create()
    p384Keypair = await ECDSAKeyPair.create({ namedCurve: "P-384" })
    p521Keypair = await ECDSAKeyPair.create({ namedCurve: "P-521" })
  })

  it("returns a publicKeyStr and did: curve P-256", () => {
    const keyDid = p256Keypair.did()
    const publicKey = p256Keypair.publicKeyStr()
    const transformed = did.didToPublicKey(keyDid)
    expect(transformed.publicKey).toEqual(publicKey)
    expect(transformed.type).toEqual("p256")
  })

  it("returns a publicKeyStr and did: curve P-384", async () => {
    const publicKey = p384Keypair.publicKeyStr()
    const keyDid = p384Keypair.did()
    const transformed = did.didToPublicKey(keyDid)
    expect(transformed.publicKey).toEqual(publicKey)
    expect(transformed.type).toEqual("p384")
  })

  it("returns a publicKeyStr and did: curve P-521", async () => {
    const publicKey = p521Keypair.publicKeyStr()
    const keyDid = p521Keypair.did()
    const transformed = did.didToPublicKey(keyDid)
    expect(transformed.publicKey).toEqual(publicKey)
    expect(transformed.type).toEqual("p521")
  })

  it("signs data: curve P-256", async () => {
    p256Signature = await p256Keypair.sign(data)
  })

  it("signs data: curve P-384", async () => {
    p384Signature = await p384Keypair.sign(data)
  })

  it("signs data: curve P-521", async () => {
    p521Signature = await p521Keypair.sign(data)
  })

  it("can verify signature: P-256", async () => {
    const isValid = await did.verifySignature(data, p256Signature, p256Keypair.did())
    expect(isValid).toBeTruthy()
  })

  it("can verify signature: P-384", async () => {
    const isValid = await did.verifySignature(data, p384Signature, p384Keypair.did())
    expect(isValid).toBeTruthy()
  })

  it("can verify signature: P-521", async () => {
    const isValid = await did.verifySignature(data, p521Signature, p521Keypair.did())
    expect(isValid).toBeTruthy()
  })

})
