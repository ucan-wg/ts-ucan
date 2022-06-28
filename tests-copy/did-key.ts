import EcdsaKeypair from "../src/keypair/ecdsa.js"

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

describe("did:key ECDSA P-256", () => {
  it("derives the correct DID from the JWK", async () => {
    for(const vector of testVectors) {
      const keypair = await EcdsaKeypair.importFromJwk(vector.jwk)
      const did = keypair.did()
      expect(did).toEqual(vector.id)
    }
  })
})