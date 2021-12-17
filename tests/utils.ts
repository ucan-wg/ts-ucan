import { CapabilityInfo } from "../src/attenuation"
import { Ucan } from "../src/types"

export function maxNbf(parentNbf: number | undefined, childNbf: number | undefined): number | undefined {
  if (parentNbf == null && childNbf == null) return undefined
  if (parentNbf != null && childNbf != null) return Math.max(parentNbf, childNbf)
  if (parentNbf != null) return parentNbf
  return childNbf
}

export function combineTimeBounds(ucan: Ucan<unknown>, ...ucans: Ucan<unknown>[]): { expiresAt: number; notBefore?: number } {
  const expiresAt = ucans.map(u => u.payload.exp).reduce((a, b) => Math.min(a, b), ucan.payload.exp)
  const notBefore = ucans.map(u => u.payload.nbf).reduce(maxNbf, ucan.payload.nbf)
  if (notBefore != null) {
    return { expiresAt, notBefore }
  }
  return { expiresAt }
}

export function capabilityInfoFromChain(origin: Ucan<unknown>, ...ucans: Ucan<unknown>[]): CapabilityInfo {
  return {
    originator: origin.payload.iss,
    ...combineTimeBounds(origin, ...ucans),
  }
}
