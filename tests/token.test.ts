import * as token from "../src/token"
import EdKey from "../src/keypair/ed25519"


describe("token.validate", () => {
  const alice = EdKey.fromSecretKey("t0rXPzUXY9lDyrIf1y96e1/hToGe/t0hBPxZdMp9NWwPrLmvmuQ0fw7vWvZfT5W9mRJKN1hW7+YrY+pAqk8X8g==")
  const bob = EdKey.fromSecretKey("w/X3iLRv+NZmDbs1ZOyOHVcAwJTN4Gw0lRW5jOB832ThDYAoRQ3Cs5/OoMpuuXedg64tTt63C+3n/UMR5l+QrQ==")
  // const mallory = EdKey.fromSecretKey("IxS23xpPSV5Ae7tYpjVOMBAaM7SNGNBEsOLp7CUVFdMB0By5QJILOgVvSGFUzht1P8TteLd8ZOK+cLq0fexu4Q==")

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