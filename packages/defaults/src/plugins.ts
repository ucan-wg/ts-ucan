import { DidKeyPlugin } from '@ucans/core'
import { verifySignature } from './did'

export const edwards: DidKeyPlugin = {
  prefix: new Uint8Array([ 0xed, 0x01 ]),
  jwtAlg: 'EdDSA',
  checkSignature: async (did, data, sig): Promise<boolean> => {
    const isValid = await verifySignature(data, sig, did)
    return isValid
  }
}

export const rsa: DidKeyPlugin = {
  prefix: new Uint8Array([ 0x85, 0x24 ]),
  jwtAlg: 'RS256',
  checkSignature: async (did, data, sig): Promise<boolean> => {
    const isValid = await verifySignature(data, sig, did)
    return isValid
  }
}

export const rsaOld: DidKeyPlugin = {
  prefix: new Uint8Array([ 0x00, 0xf5, 0x02 ]),
  jwtAlg: 'RS256',
  checkSignature: async (did, data, sig): Promise<boolean> => {
    const isValid = await verifySignature(data, sig, did)
    return isValid
  }
}