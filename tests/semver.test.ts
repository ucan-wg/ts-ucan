import * as fc from "fast-check"

import { SemVer, parse, format, compare, GT, EQ, LT } from "../src/semver"

const arbitrarySemVer = fc.record({
  major: fc.nat(100),
  minor: fc.nat(100),
  patch: fc.nat(100)
})

const toNum = (semVer: SemVer) =>
  100 * 100 * semVer.major
    + 100 * semVer.minor
    + semVer.patch

describe("SemVer", () => {

  it("has the property parse(format(x)) == x", () => {
    fc.property(arbitrarySemVer, semVer => {
      expect(parse(format(semVer))).toEqual(semVer)
    })
  })

  it("has the property compare(x, y) == flip(compare(y, x))", () => {
    fc.property(arbitrarySemVer, arbitrarySemVer, (l, r) => {
      expect(compare(l, r)).toEqual(flip(compare(r, l)))
    })
  })

  it("has the property compare(x, x) == EQ", () => {
    fc.property(arbitrarySemVer, semVer => {
      expect(compare(semVer, semVer)).toEqual(EQ)
    })
  })

  it("has the property compare(x, y) == compareNum(toNum(x), toNum(y))", () => {
    fc.property(arbitrarySemVer, arbitrarySemVer, (x, y) => {
      expect(compare(x, y)).toEqual(compareNum(toNum(x), toNum(y)))
    })
  })

})

function flip(sign: GT | EQ | LT): GT | EQ | LT {
  switch (sign) {
    case GT: return LT
    case LT: return GT
    default: return EQ
  }
}

function compareNum(l: number, r: number): LT | EQ | GT {
  if (l < r) return LT
  if (l > r) return GT
  return EQ
}
