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

  describe("parse", () => {

    it("parses 0.1.2", () => {
      expect(parse("0.1.2")).toEqual({
        major: 0,
        minor: 1,
        patch: 2,
      })
    })

    it("parses 11.22.33", () => {
      expect(parse("11.22.33")).toEqual({
        major: 11,
        minor: 22,
        patch: 33,
      })
    })

    it("doesn't parse negative integers", () => {
      expect(parse("0.-1.1")).toEqual(null)
    
    })

    it("doesn't parse octal integers", () => {
      expect(parse("0.010.0")).toEqual(null)
    })

    it("doesn't parse scientific integers", () => {
      expect(parse("1e5.0.0")).toEqual(null)
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
