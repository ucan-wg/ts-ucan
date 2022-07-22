import * as fc from "fast-check"
import * as uint8arrays from "uint8arrays"
import { rsaPlugin } from "../src/rsa/plugin.js"
import * as rsaCrypto from "../src/rsa/crypto.js"
import RSAKeypair from "../src/rsa/keypair.js"


describe("rsa", () => {

  let keypair: RSAKeypair
  let signature: Uint8Array
  const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9])

  it("creates an rsa keypair", async () => {
    keypair = await RSAKeypair.create()
  })

  it("has the correct JWT alg", async () => {
    expect(keypair.jwtAlg).toEqual("RS256")
  })

  it("signs data", async () => {
    signature = await keypair.sign(data)
  })

  it("can verify signature", async () => {
    const isValid = await rsaPlugin.verifySignature(keypair.did(), data, signature)
    expect(isValid).toBeTruthy()
  })

  it("handles old RSA keys", () => {
    const toDecode = "did:key:z13V3Sog2YaUKhdGCmgx9UZuW1o1ShFJYc6DvGYe7NTt689NoL2RtpVs65Zw899YrTN9WuxdEEDm54YxWuQHQvcKfkZwa8HTgokHxGDPEmNLhvh69zUMEP4zjuARQ3T8bMUumkSLGpxNe1bfQX624ef45GhWb3S9HM3gvAJ7Qftm8iqnDQVcxwKHjmkV4hveKMTix4bTRhieVHi1oqU4QCVy4QPWpAAympuCP9dAoJFxSP6TNBLY9vPKLazsg7XcFov6UuLWsEaxJ5SomCpDx181mEgW2qTug5oQbrJwExbD9CMgXHLVDE2QgLoQMmgsrPevX57dH715NXC2uY6vo2mYCzRY4KuDRUsrkuYCkewL8q2oK1BEDVvi3Sg8pbC9QYQ5mMiHf8uxiHxTAmPedv8"
    const expectedKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQAB"
    const publicKey = rsaCrypto.oldDidToPublicKey(toDecode)
    const publicKeyB64 = uint8arrays.toString(publicKey, "base64pad")
    expect(publicKeyB64).toEqual(expectedKey)
  })

})

describe("ASN", () => {

  describe("asn1DERLengthEncode/Decode", () => {

    it("works with simple examples", () => {
      // 82 - bigger than 127 & 2 length octets
      // 01 - 1 * 256^1 +
      // b3 - 179 * 256^0
      // = 435
      // Example from https://en.wikipedia.org/wiki/X.690#Length_octets
      expect(uint8arrays.toString(rsaCrypto.asn1DERLengthEncode(435), "hex")).toEqual("8201b3")
    })

    it("round-trips", () => {
      fc.assert(fc.property(fc.nat(), n => {
        expect(rsaCrypto.asn1DERLengthDecode(rsaCrypto.asn1DERLengthEncode(n))).toEqual(n)
      }))
    })

    it("encodes in a simple way until 127", () => {
      for (let i = 0; i < 128; i++) {
        expect(`Encoded ${i}: ${uint8arrays.toString(rsaCrypto.asn1DERLengthEncode(i), "hex")}`)
          .toEqual(`Encoded ${i}: ${uint8arrays.toString(new Uint8Array([i]), "hex")}`)
      }
    })
  })

  describe("SPKI/PKCS1 conversion", () => {

    it("round trips with webcrypto-generated spki keys", async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.constantFrom(1024, 2048, 3072, 4096),
          async size => {
            const key = await rsaCrypto.generateKeypair(size)
            if (key.publicKey == null) {
              expect(key.publicKey).toBeDefined()
              throw "public key is undefined"
            }
            const spki = await rsaCrypto.exportKey(key.publicKey)
            const converted =
              rsaCrypto.convertRSAPublicKeyToSubjectPublicKeyInfo(
                rsaCrypto.convertSubjectPublicKeyInfoToRSAPublicKey(
                  spki
                )
              )

            // I find hex dumps the most readable when it comes to ASN1
            expect(uint8arrays.toString(converted, "hex")).toEqual(uint8arrays.toString(spki, "hex"))
          }
        ),
        {
          numRuns: 5, // unfortunately, generating rsa keys is quite slow. Let's try to reliably keep below the 5s timeout
          examples: [[1024], [2048], [3072], [4096]], // ensure we're testing each variant at least once
        }
      )
    })

  })
})
