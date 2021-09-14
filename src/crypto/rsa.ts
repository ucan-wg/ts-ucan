import webcrypto  from "../webcrypto"

export const RSA_ALG = 'RSASSA-PKCS1-v1_5'
export const DEFAULT_KEY_SIZE = 2048
export const DEFAULT_HASH_ALG = 'SHA-256'
export const SALT_LEGNTH = 128

export const generateKeypair = async (size: number = DEFAULT_KEY_SIZE): Promise<CryptoKeyPair> => {
  return await webcrypto.generateKey(
    { 
      name: RSA_ALG,
      modulusLength: size,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: { name: DEFAULT_HASH_ALG }
    },
    false,
    ['sign', 'verify']
  )
}

export const exportKey = async (key: CryptoKey): Promise<Uint8Array> => {
  const buf = await webcrypto.exportKey('spki', key)
  return new Uint8Array(buf)
}

export const importKey = async (key: Uint8Array): Promise<CryptoKey> => {
  return await webcrypto.importKey(
    'spki',
    key.buffer,
    { name: RSA_ALG, hash: { name: DEFAULT_HASH_ALG }},
    true,
    ['sign', 'verify']
  )
}

export const sign = async (msg: Uint8Array, keypair: CryptoKeyPair): Promise<Uint8Array> => {
  const buf = await webcrypto.sign(
    { name: RSA_ALG, saltLength: SALT_LEGNTH },
    keypair.privateKey,
    msg.buffer
  )
  return new Uint8Array(buf)
}

export const verify = async (msg: Uint8Array, sig: Uint8Array, pubKey: Uint8Array): Promise<boolean> => {
  return await webcrypto.verify(
    { name: RSA_ALG, saltLength: SALT_LEGNTH },
    await importKey(pubKey),
    sig.buffer,
    msg.buffer
  )
}
