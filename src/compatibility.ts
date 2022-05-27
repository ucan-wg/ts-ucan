// A module to hold all the ugly compatibility logic
// for getting from old UCANs to newer version UCANs.

import * as semver from "./semver.js"

import * as util from "./util.js"
import { SUPERUSER } from "./capability/super-user.js"
import { UcanParts, isUcanHeader, isUcanPayload } from "./types.js"
import { my } from "./capability/index.js"


const VERSION_0_3 = { major: 0, minor: 3, patch: 0 }

type UcanHeader_0_3_0 = {
  alg: string
  typ: string
  uav: string
}

type UcanPayload_0_3_0 = {
  iss: string
  aud: string
  nbf?: number
  exp: number
  rsc: string | Record<string, string>
  ptc: string
  prf?: string
}

function isUcanHeader_0_3_0(obj: unknown): obj is UcanHeader_0_3_0 {
  return util.isRecord(obj)
    && util.hasProp(obj, "alg") && typeof obj.alg === "string"
    && util.hasProp(obj, "typ") && typeof obj.typ === "string"
    && util.hasProp(obj, "uav") && typeof obj.uav === "string"
}

function isUcanPayload_0_3_0(obj: unknown): obj is UcanPayload_0_3_0 {
  return util.isRecord(obj)
    && util.hasProp(obj, "iss") && typeof obj.iss === "string"
    && util.hasProp(obj, "aud") && typeof obj.aud === "string"
    && (!util.hasProp(obj, "nbf") || typeof obj.nbf === "number")
    && util.hasProp(obj, "exp") && typeof obj.exp === "number"
    && util.hasProp(obj, "rsc") && (typeof obj.rsc === "string" || util.isRecord(obj))
    && util.hasProp(obj, "ptc") && typeof obj.ptc === "string"
    && (!util.hasProp(obj, "prf") || typeof obj.prf === "string")
}


export function handleCompatibility(header: unknown, payload: unknown): UcanParts {
  const fail = (place: string, reason: string) => new Error(`Can't parse UCAN ${place}: ${reason}`)

  if (!util.isRecord(header)) throw fail("header", "Invalid format: Expected a record")

  // parse either the "ucv" or "uav" as a version in the header
  // we translate 'uav: 1.0.0' into 'ucv: 0.3.0'
  let version: "0.8.1" | "0.3.0" = "0.8.1"
  if (!util.hasProp(header, "ucv") || typeof header.ucv !== "string") {
    if (!util.hasProp(header, "uav") || typeof header.uav !== "string") {
      throw fail("header", "Invalid format: Missing version indicator")
    } else if (header.uav !== "1.0.0") {
      throw fail("header", `Unsupported version 'uav: ${header.uav}'`)
    }
    version = "0.3.0"
  } else if (semver.lt(header.ucv, "0.8.0")) {
    throw fail("header", `Unsupported version 'ucv: ${header.ucv}'`)
  }

  if (semver.gte(version, "0.8.0")) {
    if (typeof header.ucv !== "string") {
      throw fail("header", "Invalid format: Missing 'ucv' key or 'ucv' is not a string")
    }
    header.ucv = semver.parse(header.ucv)
    if (header.ucv == null) {
      throw fail("header", "Invalid format: 'ucv' string cannot be parsed into a semantic version")
    }
    if (!isUcanHeader(header)) throw fail("header", "Invalid format")
    if (!isUcanPayload(payload)) throw fail("payload", "Invalid format")
    return { header, payload }
  }

  // we know it's version 0.3.0
  if (!isUcanHeader_0_3_0(header)) throw fail("header", "Invalid version 0.3.0 format")
  if (!isUcanPayload_0_3_0(payload)) throw fail("payload", "Invalid version 0.3.0 format")

  return {
    header: {
      alg: header.alg,
      typ: header.typ,
      ucv: VERSION_0_3,
    },
    payload: {
      iss: payload.iss,
      aud: payload.aud,
      nbf: payload.nbf,
      exp: payload.exp,
      att: (() => {
        if (payload.rsc === SUPERUSER || typeof payload.rsc === "string") return [
          my(SUPERUSER)
        ]

        const resources: Record<string, string> = payload.rsc
        return Object.keys(resources).map(rscKey => {
          return {
            with: { scheme: rscKey, hierPart: resources[ rscKey ] },
            can: payload.ptc === SUPERUSER
              ? SUPERUSER
              : { namespace: rscKey, segments: [ payload.ptc ] }
          }
        })
      })(),
      prf: payload.prf != null ? [ payload.prf ] : []
    },
  }
}
