# ts-ucan
[![NPM](https://img.shields.io/npm/v/ucans)](https://www.npmjs.com/package/ucans)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/fission-suite/blob/master/LICENSE)
[![Discussions](https://img.shields.io/github/discussions/ucan-wg/ts-ucan)](https://github.com/ucan-wg/ts-ucan/discussions)

UCANs are JWTs that contain special keys.

At a high level, UCANs (“User Controlled Authorization Network”) are an authorization scheme ("what you can do") where users are fully in control. UCANs use DIDs ("Decentralized Identifiers") to identify users and services ("who you are").

No all-powerful authorization server or server of any kind is required for UCANs. Instead, everything a user can do is captured directly in a key or token, which can be sent to anyone who knows how to interpret the UCAN format. Because UCANs are self-contained, they are easy to consume permissionlessly, and they work well offline and in distributed systems.

UCANs work
- Server → Server
- Client → Server
- Peer-to-peer

**OAuth is designed for a centralized world, UCAN is the distributed user-controlled version.**

Read more in the whitepaper: https://whitepaper.fission.codes/access-control/ucan



## Structure

### Header

 `alg`, Algorithm, the type of signature.

 `typ`, Type, the type of this data structure, JWT.

 `uav`, UCAN version.

### Payload

 `att`, Attenuation, a list of resources and capabilities that the ucan grants.

 `aud`, Audience, the DID of who it's intended for.

 `exp`, Expiry, unix timestamp of when the jwt is no longer valid.

 `fct`, Facts, an array of extra facts or information to attach to the jwt.

 `iss`, Issuer, the DID of who sent this.

 `nbf`, Not Before, unix timestamp of when the jwt becomes valid.

 `prf`, Proof, an optional nested token with equal or greater privileges.

 ### Signature

 A signature (using `alg`) of the base64 encoded header and payload concatenated together and delimited by `.`



## Build

`ucan.build` can be used to help in formatting and signing a UCAN. It takes the following parameters:
```ts
type BuildParams = {
  // from/to
  issuer: Keypair
  audience: string

  // capabilities
  capabilities?: Array<Capability>

  // time bounds
  lifetimeInSeconds?: number // expiration overrides lifetimeInSeconds
  expiration?: number
  notBefore?: number

  // proofs / other info
  facts?: Array<Fact>
  proofs?: Array<string>
  addNonce?: boolean
}
```

### Capabilities

`capabilities` is an array of resource pointers and abilities:
```ts
{
  // `with` is a resource pointer in the form of a URI, which has a `scheme` and `hierPart`.
  // → "mailto:boris@fission.codes"
  with: { scheme: "mailto", hierPart: "boris@fission.codes" },

  // `can` is an ability, which always has a namespace and optional segments.
  // → "msg/SEND"
  can: { namespace: "msg", segments: [ "SEND" ] }
}
```



## Installation

### NPM:

```
npm install --save ucans
```

### yarn:

```
yarn add ucans
```

## Example
```ts
import * as ucans from "ucans"

// in-memory keypair
const keypair = await ucans.EdKeypair.create()
const ucan = await ucans.build({
  audience: "did:key:zabcde...", // recipient DID
  issuer: keypair, // signing key
  capabilities: [ // permissions for ucan
    {
      with: { scheme: "wnfs", hierPart: "//boris.fission.name/public/photos/" },
      can: { namespace: "wnfs", segments: [ "OVERWRITE" ] }
    },
    {
      with: { scheme: "wnfs", hierPart: "//boris.fission.name/private/4tZA6S61BSXygmJGGW885odfQwpnR2UgmCaS5CfCuWtEKQdtkRnvKVdZ4q6wBXYTjhewomJWPL2ui3hJqaSodFnKyWiPZWLwzp1h7wLtaVBQqSW4ZFgyYaJScVkBs32BThn6BZBJTmayeoA9hm8XrhTX4CGX5CVCwqvEUvHTSzAwdaR" },
      can: { namespace: "wnfs", segments: [ "APPEND" ] }
    },
    {
      with: { scheme: "mailto", hierPart: "boris@fission.codes" },
      can: { namespace: "wnfs", segments: [ "SEND" ] }
    }
  ]
})
const token = ucans.encode(ucan) // base64 jwt-formatted auth token

// You can also use your own signing function if you're bringing your own key management solution
const payload = await ucans.buildPayload(...)
const ucan = await ucans.sign(payload, keyType, signingFn)
```



## Validating

```ts
import * as ucans from "ucans"

const ucan = ucans.build({ ... })

ucans.isExpired(ucan)
ucans.isTooEarly(ucan)
ucans.validate(ucans.encode(ucan)) // checks signature, issuer key type, and the above.
```


## Capabilities

```ts
import * as ucans from "ucans"

// Utility functions to create capabilities
const ucan = ucans.build({
  audience: "did:key:zabcde...",
  issuer: keypair,
  capabilities: [
    ucans.capability.my("resource"),
    {
      with: ucans.capability.resourcePointer.parse("wnfs://boris.fission.name/public/photos/"),
      can: ucans.capability.ability.parse("wnfs/OVERWRITE")
    }
  ]
})

// Capability semantics
const SEMANTICS = {
  // wether or not to use the default capability structure
  // (this would parse a regular capability into a custom one)
  tryParsing: a => a,

  // capability delegation
  tryDelegating: (parentCapability, childCapability) => {
    const isEq = JSON.stringify(parentCapability) === JSON.stringify(childCapability)
    return isEq ? childCap : null
  }
}

// Capability checking
const nowInSeconds = Math.floor(Date.now() / 1000)
const result = ucans.hasCapability(
  SEMANTICS,
  {
    originator: keypair.did(),  // capability must have been originated from this issuer
    expiresAt: nowInSeconds,    // ucan must not have been expired before this timestamp
    notBefore: nowInSeconds     // optional
  },
  ucans.Chained.fromToken(ucans.encode(ucan))
)

if (result === false) log("UCAN does not have this capability 🚨")
else log("UCAN has the capability ✅ Info:", result.info, "Capability:", result.capability)
```



## Sponsors

Sponsors that contribute developer time or resources to this implementation of UCANs:

- [Fission](https://fission.codes/)



## UCAN Toucan

![](https://ipfs.runfission.com/ipfs/QmcyAwK7AjvLXbGuL4cqG5nufEKJquFmFGo2SDsaAe939Z)
