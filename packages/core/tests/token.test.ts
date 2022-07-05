import * as uint8arrays from "uint8arrays"
import { alice, bob } from "./fixtures"
import * as ucans from "./lib"

// COMPOSING


describe("token.build", () => {

  // beforeAll(loadTestPlugins)

  it("can build payloads without nbf", () => {
    const payload = ucans.buildPayload({
      issuer: alice.did(),
      audience: bob.did(),
    })
    expect(payload.nbf).not.toBeDefined()
  })

  it("builds payloads that expire in the future", () => {
    const payload = ucans.buildPayload({
      issuer: alice.did(),
      audience: bob.did(),

      lifetimeInSeconds: 30,
    })
    expect(payload.exp).toBeGreaterThan(Date.now() / 1000)
  })

  it("throws when enclosing tokens with an invalid key type", async () => {
    await expect(() => {
      const payload = ucans.buildPayload({
        issuer: alice.did(),
        audience: bob.did(),
      })

      return ucans.sign(
        payload,
        "rsa",
        data => alice.sign(data)
      )
    }).rejects.toBeDefined()
  })

})



// ENCODING


describe("token.encodePayload", () => {

  it("encodes capabilities", () => {
    const encodedCaps = {
      with: "wnfs://boris.fission.name/public/photos/",
      can: "crud/DELETE"
    }

    const payload = ucans.buildPayload({
      issuer: alice.did(),
      audience: bob.did(),
      capabilities: [ ucans.capability.parse(encodedCaps) ]
    })

    const encoded = ucans.encodePayload(payload)
    const decodedString = uint8arrays.toString(
      uint8arrays.fromString(encoded, "base64url"),
      "utf8"
    )

    const decoded = JSON.parse(decodedString)

    expect(
      JSON.stringify(decoded.att)
    ).toEqual(
      JSON.stringify([ encodedCaps ])
    )
  })

})



// VALIDATION


describe("token.validate", () => {

  async function makeUcan() {
    return await ucans.build({
      audience: bob.did(),
      issuer: alice,
      capabilities: [
        {
          "with": { scheme: "wnfs", hierPart: "//boris.fission.name/public/photos/" },
          "can": { namespace: "crud", segments: [ "DELETE" ] }
        },
        {
          "with": { scheme: "wnfs", hierPart: "//boris.fission.name/private/84MZ7aqwKn7sNiMGsSbaxsEa6EPnQLoKYbXByxNBrCEr" },
          "can": { namespace: "wnfs", segments: [ "APPEND" ] }
        },
        {
          "with": { scheme: "mailto", hierPart: "boris@fission.codes" },
          "can": { namespace: "msg", segments: [ "SEND" ] }
        }
      ]
    })
  }

  it("round-trips with token.build", async () => {
    const ucan = await makeUcan()
    const parsedUcan = await ucans.validate(ucans.encode(ucan))
    expect(parsedUcan).toBeDefined()
  })

  it("throws with a bad audience", async () => {
    const ucan = await makeUcan()
    const badPayload = {
      ...ucan.payload,
      aud: "fakeaudience"
    }
    const badUcan = `${ucans.encodeHeader(ucan.header)}.${ucans.encodePayload(badPayload)}.${ucan.signature}`
    await expect(() => ucans.validate(badUcan)).rejects.toBeDefined()
  })

  it("throws with a bad issuer", async () => {
    const ucan = await makeUcan()
    const badHeader = {
      ...ucan.header,
      alg: "RS256"
    }
    const badUcan = `${ucans.encodeHeader(badHeader)}.${ucans.encodePayload(ucan.payload)}.${ucan.signature}`
    await expect(() => ucans.validate(badUcan)).rejects.toBeDefined()
  })

  it("identifies a ucan that is not active yet", async () => {
    const ucan = await makeUcan()
    const badUcan = {
      ...ucan,
      payload: {
        ...ucan.payload,
        nbf: 2637252774,
        exp: 2637352774
      }
    }
    expect(ucans.isTooEarly(badUcan)).toBe(true)
  })

  it("identifies a ucan that has become active", async () => {
    const ucan = await makeUcan()
    const activeUcan = {
      ...ucan,
      payload: {
        ...ucan.payload,
        nbf: Math.floor(Date.now() / 1000),
        lifetimeInSeonds: 30
      }
    }
    expect(ucans.isTooEarly(activeUcan)).toBe(false)
  })
})