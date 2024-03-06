import { p256Plugin } from "../src/p256/plugin.js"
import EcdsaKeypair from "../src/p256/keypair.js"

describe("ecdsa", () => {

  let keypair: EcdsaKeypair
  let signature: Uint8Array
  const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9])

  it("creates an ecdsa keypair", async () => {
    keypair = await EcdsaKeypair.create()
  })

  it("has the correct JWT alg", async () => {
    expect(keypair.jwtAlg).toEqual("ES256")
  })

  it("signs data", async () => {
    signature = await keypair.sign(data)
  })

  it("can verify signature", async () => {
    const isValid = await p256Plugin.verifySignature(keypair.did(), data, signature)
    expect(isValid).toBeTruthy()
  })

})

// did:key test vectors from W3C
// https://github.com/w3c-ccg/did-method-key/blob/main/test-vectors/nist-curves.json
const testVectors = [
  {
    id: "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv",
    jwk: {
      kty: "EC",
      crv: "P-256",
      x: "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns",
      y: "efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM",
      d: "gPh-VvVS8MbvKQ9LSVVmfnxnKjHn4Tqj0bmbpehRlpc"
    }
  },
  {
    id: "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
    jwk: {
      kty: "EC",
      crv: "P-256",
      x: "fyNYMN0976ci7xqiSdag3buk-ZCwgXU4kz9XNkBlNUI",
      y: "hW2ojTNfH7Jbi8--CJUo3OCbH3y5n91g-IMA9MLMbTU",
      d: "YjRs6vNvw4sYrzVVY8ipkEpDAD9PFqw1sUnvPRMA-WI"
    }
  }
]

describe("ecdsa did:key", () => {
  it("derives the correct DID from the JWK", async () => {
    for (const vector of testVectors) {
      const keypair = await EcdsaKeypair.importFromJwk(vector.jwk)
      const did = keypair.did()
      expect(did).toEqual(vector.id)
    }
  })
})

describe("import and exporting a key", () => {
  let exportableKeypair: EcdsaKeypair;
  let nonExportableKeypair: EcdsaKeypair;

  beforeAll(async () => {
    exportableKeypair = await EcdsaKeypair.create({ exportable: true })
    nonExportableKeypair = await EcdsaKeypair.create({ exportable: false })
  })

  it("can export a key using jwk", async () => {
    const exported = await exportableKeypair.export()
    expect(exported.length).toBeGreaterThan(0)
  })

  it("won't export a non exportable keypar", async () => {
    await expect(nonExportableKeypair.export())
      .rejects
      .toThrow('Key is not exportable')
  })

  it('Can export a key and re-import from it', async () => {
    const exported = await exportableKeypair.export()

    const jwk = JSON.parse(exported)
    const newKey = await EcdsaKeypair.import(jwk)

    const input = new Uint8Array(Buffer.from("test", "utf-8"));
    const msg = new Uint8Array(Buffer.from("test message", "utf-8"))


    // Expect the public keys to match
    expect(exportableKeypair.did()).toEqual(newKey.did())

    // Verify old and new keys are compatible
    let signedMessage = await exportableKeypair.sign(msg)
    expect(await p256Plugin.verifySignature(newKey.did(), msg, signedMessage)).toBe(true)

    signedMessage = await newKey.sign(msg)
    expect(await p256Plugin.verifySignature(exportableKeypair.did(), msg, signedMessage)).toBe(true)
  })
})