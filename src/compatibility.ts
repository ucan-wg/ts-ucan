// A module to hold all the ugly compatibility logic
// for getting from old UCANs to newer version UCANs.
import * as util from "./util"
import { UcanParts, isUcanHeader, isUcanPayload } from "./types"


type UcanHeader_0_0_1 = {
  alg: string
  typ: string
  uav: string
}

type UcanPayload_0_0_1 = {
  iss: string
  aud: string
  nbf?: number
  exp: number
  rsc: string
  ptc: string
  prf?: string
}

function isUcanHeader_0_0_1(obj: unknown): obj is UcanHeader_0_0_1 {
  return util.isRecord(obj)
    && util.hasProp(obj, "alg") && typeof obj.alg === "string"
    && util.hasProp(obj, "typ") && typeof obj.typ === "string"
    && util.hasProp(obj, "uav") && typeof obj.uav === "string"
}

function isUcanPayload_0_0_1(obj: unknown): obj is UcanPayload_0_0_1 {
  return util.isRecord(obj)
    && util.hasProp(obj, "iss") && typeof obj.iss === "string"
    && util.hasProp(obj, "aud") && typeof obj.aud === "string"
    && (!util.hasProp(obj, "nbf") || typeof obj.nbf === "number")
    && util.hasProp(obj, "exp") && typeof obj.exp === "number"
    && util.hasProp(obj, "rsc") && typeof obj.rsc === "string"
    && util.hasProp(obj, "ptc") && typeof obj.ptc === "string"
    && (!util.hasProp(obj, "prf") || typeof obj.prf === "string")
}


export function handleCompatibility(header: unknown, payload: unknown): UcanParts {
  const fail = (place: string, reason: string) => new Error(`Can't parse UCAN ${place}: ${reason}`)
  
  if (!util.isRecord(header)) throw fail("header", "Invalid format: Expected a record")

  // parse either the "ucv" or "uav" as a version in the header
  // we translate 'uav: 1.0.0' into 'ucv: 0.0.1'
  // we only support versions 0.7.0 and 0.0.1
  let version: "0.7.0" | "0.0.1" = "0.7.0"
  if (!util.hasProp(header, "ucv") || typeof header.ucv !== "string") {
    if (!util.hasProp(header, "uav") || typeof header.uav !== "string") {
      throw fail("header", "Invalid format: Missing version indicator")
    } else if (header.uav !== "1.0.0") {
      throw fail("header", `Unsupported version 'uav: ${header.uav}'`)
    }
    version = "0.0.1"
  } else if (header.ucv !== "0.7.0") {
    throw fail("header", `Unsupported version 'ucv: ${header.ucv}'`)
  }

  if (version === "0.7.0") {
    if (!isUcanHeader(header)) throw fail("header", "Invalid format")
    if (!isUcanPayload(payload)) throw fail("payload", "Invalid format")
    return { header, payload }
  }

  // we know it's version 0.0.1

  if (!isUcanHeader_0_0_1(header)) throw fail("header", "Invalid version 0.0.1 format")
  if (!isUcanPayload_0_0_1(payload)) throw fail("payload", "Invalid version 0.0.1 format")

  return {
    header: {
      alg: header.alg,
      typ: header.typ,
      ucv: "0.0.1",
    },
    payload: {
      iss: payload.iss,
      aud: payload.aud,
      nbf: payload.nbf,
      exp: payload.exp,
      att: [{
        rsc: payload.rsc,
        cap: payload.ptc,
      }],
      prf: payload.prf != null ? [payload.prf] : []
    },
  }
}

