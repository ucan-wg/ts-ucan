export interface AvailableCryptoKeyPair {
  privateKey: CryptoKey
  publicKey: CryptoKey
}

export type PublicKeyJwk = {
  kty: string
  crv: string

  // For P256 curves
  x?: string
  y?: string

  // For RSA curves
  n?: string
  e?: string

}

export type PrivateKeyJwk = PublicKeyJwk & { d: string }


export function isAvailableCryptoKeyPair(keypair: CryptoKeyPair): keypair is AvailableCryptoKeyPair {
  return keypair.publicKey != null && keypair.privateKey != null
}