import * as token from "../src/token"
import { alice, bob } from "./fixtures"


describe("token.validate", () => {
  async function makeUcan() {
    return await token.build({
      audience: bob.did(),
      issuer: alice,
      capabilities: [
        {
          "wnfs": "boris.fission.name/public/photos/",
          "cap": "OVERWRITE"
        },
        {
          "wnfs": "boris.fission.name/private/4tZA6S61BSXygmJGGW885odfQwpnR2UgmCaS5CfCuWtEKQdtkRnvKVdZ4q6wBXYTjhewomJWPL2ui3hJqaSodFnKyWiPZWLwzp1h7wLtaVBQqSW4ZFgyYaJScVkBs32BThn6BZBJTmayeoA9hm8XrhTX4CGX5CVCwqvEUvHTSzAwdaR",
          "cap": "APPEND"
        },
        {
          "email": "boris@fission.codes",
          "cap": "SEND"
        }
      ]
    })
  }

  it("round-trips with token.build", async () => {
    const ucan = await makeUcan()
    const parsedUcan = await token.validate(token.encode(ucan))
    expect(parsedUcan).toBeDefined()
  })

  it("throws with a bad audience", async () => {
    const ucan = await makeUcan()
    const badUcan = token.encode({
      ...ucan,
      payload: {
        ...ucan.payload,
        aud: "fakeaudience"
      }
    })
    await expect(() => token.validate(badUcan)).rejects.toBeDefined()
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
    expect(token.isTooEarly(badUcan)).toBe(true)
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
    expect(token.isTooEarly(activeUcan)).toBe(false)
  })
})