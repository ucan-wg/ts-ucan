import { Keypair, KeyType } from "../types"
import EdKeypair from "./ed25519"
import RsaKeypair from "./rsa"

export const create = async (type: KeyType, params?: { exportable: boolean }): Promise<Keypair> => {
  switch(type) {
    case KeyType.Edwards: return await EdKeypair.create(params)
    case KeyType.RSA: return await RsaKeypair.create(params)
    default: 
      throw new Error("Unsupported key type")
  }
}
