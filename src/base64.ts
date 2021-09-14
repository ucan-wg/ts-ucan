import * as uint8arrays from "uint8arrays"
import { Encodings } from "./types"

export function decode(base64: string, encoding: Encodings = 'base64pad'): string {
  return uint8arrays.toString(uint8arrays.fromString(base64, encoding))
}

export function encode(str: string, encoding: Encodings = 'base64pad'): string {
  return uint8arrays.toString(uint8arrays.fromString(str), encoding)
}

export function urlDecode(base64: string): string {
  return decode(base64, 'base64urlpad')
}

export function urlEncode(str: string): string {
  return encode(str, 'base64urlpad')
}
