const CHARS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

export const generateNonce = (len = 6): string => {
  let nonce = ''
  for (let i=0; i < len; i++) {
    nonce += CHARS[Math.floor(Math.random() * CHARS.length)]
  }
  return nonce
}
