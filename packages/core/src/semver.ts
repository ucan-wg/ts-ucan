import { hasProp, isRecord } from "./util.js"


// Types

export interface SemVer {
  major: number
  minor: number
  patch: number
}

export function isSemVer(obj: unknown): obj is SemVer {
  return isRecord(obj)
    && hasProp(obj, "major") && typeof obj.major === "number"
    && hasProp(obj, "minor") && typeof obj.minor === "number"
    && hasProp(obj, "patch") && typeof obj.patch === "number"
}


// Parsing

const NUM_REGEX = /^0|[1-9]\d*/

const matchesRegex = (regex: RegExp) => (str: string) => {
  const m = str.match(regex)
  if (!m) return false
  return m[0].length === str.length
}

export function parse(version: string): SemVer | null {
  const parts = version.split(".")
  
  if (parts.length !== 3) {
    return null
  }

  if (!parts.every(matchesRegex(NUM_REGEX))) {
    return null
  }
  
  const [ major, minor, patch ] = parts.map(part => parseInt(part, 10))
  
  if (!Number.isSafeInteger(major) || !Number.isSafeInteger(minor) || !Number.isSafeInteger(patch)) {
    return null
  }
  if (major < 0 || minor < 0 || patch < 0) {
    return null
  }

  return { major, minor, patch }
}


// Formatting/Prettyprinting

export function format(semver: SemVer): string {
  return `${semver.major}.${semver.minor}.${semver.patch}`
}


// Comparison

export const GT = 1
export const EQ = 0
export const LT = -1
export type GT = typeof GT
export type EQ = typeof EQ
export type LT = typeof LT

function comparePart(left?: number, right?: number): GT | EQ | LT {
  // when at least one of them is null
  if (left == null) {
    if (right == null) return EQ
    return LT
  } else if (right == null) {
    return GT
  }

  // when none of them are null
  if (left > right) return GT
  if (left < right) return LT
  return EQ
}

export function compare(left: SemVer | string, right: SemVer | string): GT | EQ | LT {
  const l = typeof left === "string" ? parse(left) : left
  const r = typeof right === "string" ? parse(right) : right
  return (
    comparePart(l?.major, r?.major) ||
    comparePart(l?.minor, r?.minor) ||
    comparePart(l?.patch, r?.patch)
  )
}

export function lt(left: SemVer | string, right: SemVer | string): boolean {
  return compare(left, right) === LT
}

export function gte(left: SemVer | string, right: SemVer | string): boolean {
  return !lt(left, right)
}

export function gt(left: SemVer | string, right: SemVer | string): boolean {
  return compare(left, right) === GT
}

export function lte(left: SemVer | string, right: SemVer | string): boolean {
  return !gt(left, right)
}

export function eq(left: SemVer | string, right: SemVer | string): boolean {
  return compare(left, right) === EQ
}

export function neq(left: SemVer | string, right: SemVer | string): boolean {
  return !eq(left, right)
}
