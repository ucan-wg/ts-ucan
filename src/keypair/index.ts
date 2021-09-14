import { Keypair, KeyType } from "../types"
import EdKeypair from "./ed25519"
import RsaKeypair from "./rsa"

export const create = async (type: KeyType): Promise<Keypair> => {
  switch(type) {
    case KeyType.Edwards: return await EdKeypair.create()
    case KeyType.RSA: return await RsaKeypair.create()
    default: 
      throw new Error("Unsupported key type")
  }
}
