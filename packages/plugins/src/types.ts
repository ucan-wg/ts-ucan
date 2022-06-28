export interface AvailableCryptoKeyPair {
  privateKey: CryptoKey
  publicKey: CryptoKey
}

export type PublicKeyJwk = {
  kty: string
  crv: string
  x: string
  y: string
}

export type KeyType =
  | "rsa"
  | "p256"
  | "ed25519"
  | "bls12-381"

export type PrivateKeyJwk = PublicKeyJwk & { d: string }


export function isAvailableCryptoKeyPair(keypair: CryptoKeyPair): keypair is AvailableCryptoKeyPair {
  return keypair.publicKey != null && keypair.privateKey != null
}