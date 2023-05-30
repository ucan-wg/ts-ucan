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
npm install --save @ucans/ucans
```

### yarn:

```
yarn add @ucans/ucans
```

## Example
```ts
import * as ucans from "@ucans/ucans"

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
      with: { scheme: "wnfs", hierPart: "//boris.fission.name/private/6m-mLXYuXi5m6vxgRTfJ7k_xzbmpk7LeD3qYt0TM1M0" },
      can: { namespace: "wnfs", segments: [ "APPEND" ] }
    },
    {
      with: { scheme: "mailto", hierPart: "boris@fission.codes" },
      can: { namespace: "msg", segments: [ "SEND" ] }
    }
  ]
})
const token = ucans.encode(ucan) // base64 jwt-formatted auth token

// You can also use your own signing function if you're bringing your own key management solution
const payload = await ucans.buildPayload(...)
const ucan = await ucans.sign(payload, keyType, signingFn)
```



## Verifying UCAN Invocations

Using a UCAN to authorize an action is called "invocation".

To verify invocations, you need to use the `verify` function.

```ts
import * as ucans from "@ucans/ucans"

const serviceDID = "did:key:zabcde..."

// Generate a UCAN on one machine
const ucan = ucans.build({ ... })

// encode the UCAN to send it over to another machine
const encoded = ucans.encode(ucan)

// verify an invocation of a UCAN on another machine (in this example a service)
const result = await ucans.verify(encoded, {
  // to make sure we're the intended recipient of this UCAN
  audience: serviceDID,
  // A callback for figuring out whether a UCAN is known to be revoked
  isRevoked: async ucan => false // as a stub. Should look up the UCAN CID in a DB.
  // capabilities required for this invocation & which owner we expect for each capability
  requiredCapabilities: [
    {
      capability: {
        with: { scheme: "mailto", hierPart: "boris@fission.codes" },
        can: { namespace: "msg", segments: [ "SEND" ] }
      },
      rootIssuer: borisDID, // check against a known owner of the boris@fission.codes email address
    }
  ],
)

if (result.ok) {
  // The UCAN authorized the user
} else {
  // Unauthorized
}
```


## Delegation Semantics

UCAN capabilities can have arbitrary semantics for delegation.
These semantics can be configured via a record of two functions:
- `canDelegateResource(parent: ResourcePointer, child: ResourcePointer): boolean` and
- `canDelegateAbility(parent: Ability, child: Ability): boolean`.
Which specify exactly which delegations are valid.

(This doesn't support rights amplification yet, where multiple capabilities
in combination may result in a delegation being possible. Please talk to us
with your use-case and ideas for how a good API for that may work.)

```ts
import * as ucans from "@ucans/ucans"

// Delegation semantics for path-like capabilities (e.g. "path:/home/abc/")
const PATH_SEMANTICS = {
  canDelegateResource: (parentRes, childRes) => {
    if (parentRes.with.scheme !== "path" || childRes.with.scheme !== "path") {
      // If this is not about the "path" capability, then
      // just use the normal equality delegation
      return ucans.equalCanDelegate.canDelegateResource(parentRes, childRes)
    }

    // we've got access to everything
    if (parentRes.hierPart === ucans.capability.superUser.SUPERUSER) {
      return true
    }

    // path must be the same or a path below
    if (`${childRes.hierPart}/`.startsWith(`${parentRes.hierPart}/`)) {
      return true
    }

    // 🚨 cannot delegate
    return false
  },

  // we're reusing equalCanDelegate's semantics for ability delegation
  canDelegateAbility: equalCanDelegate.canDelegateAbility
}
```

## Contributing

To get started working with this repository:

 - `git clone git@github.com:ucan-wg/ts-ucan.git`
 - `cd ts-ucan`
 - `yarn`

Note that usign npm with this repository will likely fail, please use yan instead.


## Sponsors

Sponsors that contribute developer time or resources to this implementation of UCANs:

- [Fission](https://fission.codes/)



## UCAN Toucan

![](https://ipfs.runfission.com/ipfs/QmcyAwK7AjvLXbGuL4cqG5nufEKJquFmFGo2SDsaAe939Z)
