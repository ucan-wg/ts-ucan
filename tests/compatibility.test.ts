import * as uint8arrays from "uint8arrays"
import * as token from "../src/token"


const oldUcan = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsInVhdiI6IjEuMC4wIn0.eyJhdWQiOiJkaWQ6a2V5OnoxM1YzU29nMllhVUtoZEdDbWd4OVVadVcxbzFTaEZKWWM2RHZHWWU3TlR0Njg5Tm9MMXRrZUd3NGMydGFQa2dBdWloUjh0cmg2azg2VHRVaTNIR2ZrNEh1NDg3czNiTWY4V1MzWjJoU3VwRktiNmhnV3VwajFIRzhheUxRdDFmeWJSdThjTGdBMkNKanFRYm16YzRFOEFKU0tKeDNndVFYa2F4c3R2Um5RRGN1eDFkZzhVR1BRS3haN2lLeUFKWkFuQlcyWXJUM2o0TVQxdTJNcWZQWG9RYU01WFZQMk04clBFN0FCSEREOXdMbWlKdjkzUUFDRFR5MllnZkVSS3JualNWaTdFb3RNOFR3NHg3M1pNUXJEQnZRRW01Zm9tTWZVaTZVSmJUTmVaaldDTUJQYllNbXRKUDZQZlRpaWZYZG0zdXprVFg5NnExUkVFOExodkU2Rzg2cUR0Wjg5MzdFYUdXdXFpNkRHVDFvc2FRMUVnR3NFN3Jac2JSdDFLNnRXeTZpYktlNTlKZWtnTWFlNW9XNER2IiwiZXhwIjozMjc0NDE5MTQyMywiZmN0IjpbXSwiaXNzIjoiZGlkOmtleTp6MTNWM1NvZzJZYVVLaGRHQ21neDlVWnVXMW8xU2hGSlljNkR2R1llN05UdDY4OU5vTDJWanZBR2JXdTFrdmZWUWFyVTVWMXBTUnNjOWFwR2h2dDdaODJmUWg1QWE1NW41Zm0zZGs2SnFuTXczZGU4WG91dWZUV2Z1eHpEVkhrSFNGV0sxOW1SWWI4d205d1VwZkxtUWl4QVdtMndFWVZqU2dENEd6YzhVUDlDSjFxMkY4ZXlpVXViMThGbld4Y2djUWhqdXB3OTNxUlMzWDlXUDViemlSYjE4TTZ0Vm8zaUJ4ZUozb2lrRTNaa3RScEtTZDlkcHU5WWNXZFhoeDZDQmY5NTZ1UXhkTDZoTkppNmVMbmZ1eFY2NEhpZU1rZFVoTTJSeThRd3lqZjQ4ZnZWMVhFVU1zeEM5YWFjNEtCcGJONDJHR3U4UmFkRDU3cjZuMWFOc2IyTjU3RkNOYnFIMXVLdHhNTmVHZHJ2QWlUUGRzVjJBRmppczJvN243ajhMNW41YmJ4TFl4VThNVHB3QVphdFpkSiIsIm5iZiI6MTY0MDE5MTQ1NywicHJmIjoiZXlKaGJHY2lPaUpTVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0lzSW5WaGRpSTZJakV1TUM0d0luMC5leUpoZFdRaU9pSmthV1E2YTJWNU9ub3hNMVl6VTI5bk1sbGhWVXRvWkVkRGJXZDRPVlZhZFZjeGJ6RlRhRVpLV1dNMlJIWkhXV1UzVGxSME5qZzVUbTlNTWxacWRrRkhZbGQxTVd0MlpsWlJZWEpWTlZZeGNGTlNjMk01WVhCSGFIWjBOMW80TW1aUmFEVkJZVFUxYmpWbWJUTmthelpLY1c1TmR6TmtaVGhZYjNWMVpsUlhablY0ZWtSV1NHdElVMFpYU3pFNWJWSlpZamgzYlRsM1ZYQm1URzFSYVhoQlYyMHlkMFZaVm1wVFowUTBSM3BqT0ZWUU9VTktNWEV5UmpobGVXbFZkV0l4T0VadVYzaGpaMk5SYUdwMWNIYzVNM0ZTVXpOWU9WZFFOV0o2YVZKaU1UaE5OblJXYnpOcFFuaGxTak52YVd0Rk0xcHJkRkp3UzFOa09XUndkVGxaWTFka1dHaDROa05DWmprMU5uVlJlR1JNTm1oT1NtazJaVXh1Wm5WNFZqWTBTR2xsVFd0a1ZXaE5NbEo1T0ZGM2VXcG1ORGhtZGxZeFdFVlZUWE40UXpsaFlXTTBTMEp3WWs0ME1rZEhkVGhTWVdSRU5UZHlObTR4WVU1ellqSk9OVGRHUTA1aWNVZ3hkVXQwZUUxT1pVZGtjblpCYVZSUVpITldNa0ZHYW1sek1tODNiamRxT0V3MWJqVmlZbmhNV1hoVk9FMVVjSGRCV21GMFdtUktJaXdpWlhod0lqb3pNamMwTkRFNU1UUXlNeXdpWm1OMElqcGJYU3dpYVhOeklqb2laR2xrT210bGVUcDZNVE5XTTFOdlp6SlpZVlZMYUdSSFEyMW5lRGxWV25WWE1XOHhVMmhHU2xsak5rUjJSMWxsTjA1VWREWTRPVTV2VERKaE5VcE9hMlI0VmpabWJYVm9WbU5SWkRkSVIycHhkRXBRYVc1WlZWQTRRMUp4Y21veVkyVm5hVTFyT1RKUlNIazJRbWRXT1hveVVGQnJWMkZZU0RkUlRsQmlRekphZEUxNWFXbGFjWGRLUkVOd05sZG9VbkZVUzJodVFtaENUbWQ1WkRkTFJuUTNjRkkyTkhCa1ZIQjZUbXRNUlZKNGFHNTNUVUZqZURKcVJGZFlOelpDVG5SS04xUTFWVXQ0TTIxcWRHWTBaak0wWjJwVGRUaHJkME5UY0V0alFuQTRWV2RwU0hkdllVSkhkREUxVkZjNVUzQlNXVkoxYUZKdk1tdEljVFZ5Y0ROTmRFSnFSa2QyVUdZeVRsTlpZbUUzTmxoSGJYcFhlVEZyZUZOelEySTVUSGhqTW5welEwdG1lSEF5ZUd0VVFqWmtPVVJDUlVwVE5sUnhXbFo1WkhKU05GWmFNVkE1ZFhJeGRGcHBlbk5qYWtWd1kzVlViV1EzV0VRemRYSjZVelpqY0RSdU1sZHdSbFZNYjNsMk5tOW5ibWxaZEVOSGFUVlVlbWxEY2pKT1FWRjNWMEZYY25CMldVMWllbVEyVmt0a2RUVmpaekZZUWxoTVZFNWhUQ0lzSW01aVppSTZNVFkwTURFNU1UTTJNeXdpY0hSaklqb2lVMVZRUlZKZlZWTkZVaUlzSW5Kell5STZJaW9pZlEuQ0k5SjlOLVhUZUxQNEM5WTktUl9TcEE1aE80dHdpNUQxNFpTR2lwUzdjNS1jTlJWTVItc285Z0JZMlQzSFNaTHFmQ2xyMEtlQVJicFk2TFBwSm1NRGQ1ODdvck1TVVRnMndqN043eUNVeksxSWhOazhQMkQ3RGVlSHNxQ1lsTVotdXpjMHBSbnFJb3dPTWl6MVFkbHZXaTZ0UHNxZkZVYnl4bEx1bXRHdjV1a1hqc1FZcmYzdko3aU5DMkJibWotMGhTV25wNTNBN01TQTllLWFXVGpLUWEwSkpXVVVhWG5XS19CNjRaa3NyTWRXdW5mVFNuSE9lR2o3MFRuSXhieVcxbFhodk5pcnhIUV90ZVlKZ2xIZTRBbldEQXdUa2dnaVotdkp0WUhsYnVwQkt4S1YtNm9OMTlXS3dUT3U3QnpPX2QyUHAtWVVyY1RSSS1KZ0F2NUpnIiwicHRjIjoiU1VQRVJfVVNFUiIsInJzYyI6IioifQ.CRLB4gBBHhnsbfUhLALiCfo6mHnHSlEUczyZsWhh9TNjv9UxdgvsSWQsehGIT4XR0jQeYZo2OhasEVaF-Gtt_qqtUQIrducKngd0qzmpfjVbicsQPKVdJjlcTwm9dqhLSEtL195El0oucLzYdqMEZMf-txEmyhCd_Q8CaNExhAnwN32v1salnO6vrAw33ZJID7ZaFmBleoGUXBHQwnkv9_m_P6Fh-UGIKjaOuNmBkGXGn-4irm-eXrne2OPZCoPjhiaf0xTONu4ROrQQYykG8CppvsSXeiylOFY11Ot0sdAlHGSlyZk1_chJ3ud17K9S-CKWK9NtqiMNcUdQGFnNQQ"
const [header, payload, signature] = oldUcan.split(".").map((x, i) => i < 2 ? JSON.parse(uint8arrays.toString(uint8arrays.fromString(x, "base64url"))) : x)

describe("compatibility", () => {

  it("allows parsing UCANs with 'uav: 1.0.0' into 'ucv: 0.0.1'", async () => {
    const ucan = await token.validate(oldUcan, { checkIsExpired: false, checkIsTooEarly: false, checkSignature: false })
    expect(ucan).toEqual({
      header: {
        alg: header.alg, // "RS256",
        typ: header.typ, // "JWT",
        ucv: "0.0.1" // we translate uav: 1.0.0 to ucv: 0.0.1
      },
      payload: {
        iss: payload.iss, // "did:key:z13V3Sog2YaUKhdGCmgx9UZuW1o1ShFJYc6DvGYe7NTt689NoL2VjvAGbWu1kvfVQarU5V1pSRsc9apGhvt7Z82fQh5Aa55n5fm3dk6JqnMw3de8XouufTWfuxzDVHkHSFWK19mRYb8wm9wUpfLmQixAWm2wEYVjSgD4Gzc8UP9CJ1q2F8eyiUub18FnWxcgcQhjupw93qRS3X9WP5bziRb18M6tVo3iBxeJ3oikE3ZktRpKSd9dpu9YcWdXhx6CBf956uQxdL6hNJi6eLnfuxV64HieMkdUhM2Ry8Qwyjf48fvV1XEUMsxC9aac4KBpbN42GGu8RadD57r6n1aNsb2N57FCNbqH1uKtxMNeGdrvAiTPdsV2AFjis2o7n7j8L5n5bbxLYxU8MTpwAZatZdJ",
        aud: payload.aud, // "did:key:z13V3Sog2YaUKhdGCmgx9UZuW1o1ShFJYc6DvGYe7NTt689NoL1tkeGw4c2taPkgAuihR8trh6k86TtUi3HGfk4Hu487s3bMf8WS3Z2hSupFKb6hgWupj1HG8ayLQt1fybRu8cLgA2CJjqQbmzc4E8AJSKJx3guQXkaxstvRnQDcux1dg8UGPQKxZ7iKyAJZAnBW2YrT3j4MT1u2MqfPXoQaM5XVP2M8rPE7ABHDD9wLmiJv93QACDTy2YgfERKrnjSVi7EotM8Tw4x73ZMQrDBvQEm5fomMfUi6UJbTNeZjWCMBPbYMmtJP6PfTiifXdm3uzkTX96q1REE8LhvE6G86qDtZ8937EaGWuqi6DGT1osaQ1EgGsE7rZsbRt1K6tWy6ibKe59JekgMae5oW4Dv",
        nbf: payload.nbf, // 1640191457,
        exp: payload.exp, // 32744191423,
        att: [{
          rsc: payload.rsc, // "*",
          cap: payload.ptc, // "SUPER_USER",
        }],
        prf: [
          payload.prf, // "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsInVhdiI6IjEuMC4wIn0.eyJhdWQiOiJkaWQ6a2V5OnoxM1YzU29nMllhVUtoZEdDbWd4OVVadVcxbzFTaEZKWWM2RHZHWWU3TlR0Njg5Tm9MMlZqdkFHYld1MWt2ZlZRYXJVNVYxcFNSc2M5YXBHaHZ0N1o4MmZRaDVBYTU1bjVmbTNkazZKcW5NdzNkZThYb3V1ZlRXZnV4ekRWSGtIU0ZXSzE5bVJZYjh3bTl3VXBmTG1RaXhBV20yd0VZVmpTZ0Q0R3pjOFVQOUNKMXEyRjhleWlVdWIxOEZuV3hjZ2NRaGp1cHc5M3FSUzNYOVdQNWJ6aVJiMThNNnRWbzNpQnhlSjNvaWtFM1prdFJwS1NkOWRwdTlZY1dkWGh4NkNCZjk1NnVReGRMNmhOSmk2ZUxuZnV4VjY0SGllTWtkVWhNMlJ5OFF3eWpmNDhmdlYxWEVVTXN4QzlhYWM0S0JwYk40MkdHdThSYWRENTdyNm4xYU5zYjJONTdGQ05icUgxdUt0eE1OZUdkcnZBaVRQZHNWMkFGamlzMm83bjdqOEw1bjViYnhMWXhVOE1UcHdBWmF0WmRKIiwiZXhwIjozMjc0NDE5MTQyMywiZmN0IjpbXSwiaXNzIjoiZGlkOmtleTp6MTNWM1NvZzJZYVVLaGRHQ21neDlVWnVXMW8xU2hGSlljNkR2R1llN05UdDY4OU5vTDJhNUpOa2R4VjZmbXVoVmNRZDdIR2pxdEpQaW5ZVVA4Q1JxcmoyY2VnaU1rOTJRSHk2QmdWOXoyUFBrV2FYSDdRTlBiQzJadE15aWlacXdKRENwNldoUnFUS2huQmhCTmd5ZDdLRnQ3cFI2NHBkVHB6TmtMRVJ4aG53TUFjeDJqRFdYNzZCTnRKN1Q1VUt4M21qdGY0ZjM0Z2pTdThrd0NTcEtjQnA4VWdpSHdvYUJHdDE1VFc5U3BSWVJ1aFJvMmtIcTVycDNNdEJqRkd2UGYyTlNZYmE3NlhHbXpXeTFreFNzQ2I5THhjMnpzQ0tmeHAyeGtUQjZkOURCRUpTNlRxWlZ5ZHJSNFZaMVA5dXIxdFppenNjakVwY3VUbWQ3WEQzdXJ6UzZjcDRuMldwRlVMb3l2Nm9nbmlZdENHaTVUemlDcjJOQVF3V0FXcnB2WU1iemQ2VktkdTVjZzFYQlhMVE5hTCIsIm5iZiI6MTY0MDE5MTM2MywicHRjIjoiU1VQRVJfVVNFUiIsInJzYyI6IioifQ.CI9J9N-XTeLP4C9Y9-R_SpA5hO4twi5D14ZSGipS7c5-cNRVMR-so9gBY2T3HSZLqfClr0KeARbpY6LPpJmMDd587orMSUTg2wj7N7yCUzK1IhNk8P2D7DeeHsqCYlMZ-uzc0pRnqIowOMiz1QdlvWi6tPsqfFUbyxlLumtGv5ukXjsQYrf3vJ7iNC2Bbmj-0hSWnp53A7MSA9e-aWTjKQa0JJWUUaXnWK_B64ZksrMdWunfTSnHOeGj70TnIxbyW1lXhvNirxHQ_teYJglHe4AnWDAwTkggiZ-vJtYHlbupBKxKV-6oN19WKwTOu7BzO_d2Pp-YUrcTRI-JgAv5Jg",
        ],
      },
      signature // "CRLB4gBBHhnsbfUhLALiCfo6mHnHSlEUczyZsWhh9TNjv9UxdgvsSWQsehGIT4XR0jQeYZo2OhasEVaF-Gtt_qqtUQIrducKngd0qzmpfjVbicsQPKVdJjlcTwm9dqhLSEtL195El0oucLzYdqMEZMf-txEmyhCd_Q8CaNExhAnwN32v1salnO6vrAw33ZJID7ZaFmBleoGUXBHQwnkv9_m_P6Fh-UGIKjaOuNmBkGXGn-4irm-eXrne2OPZCoPjhiaf0xTONu4ROrQQYykG8CppvsSXeiylOFY11Ot0sdAlHGSlyZk1_chJ3ud17K9S-CKWK9NtqiMNcUdQGFnNQQ"
    })
  })

})
