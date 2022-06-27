import * as capability from "../src/capability"


describe("capability.isEqual", () => {

  it("is able to compare two equal capabilities", () => {
    const a = {
      with: { scheme: "scheme", hierPart: "hierPart" },
      can: { namespace: "namespace", segments: [ "a", "B" ] }
    }

    const b = {
      with: { scheme: "SCHEME", hierPart: "hierPart" },
      can: { namespace: "NAMESPACE", segments: [ "A", "b" ] }
    }

    expect(capability.isEqual(a, b)).toBe(true)
    expect(capability.resourcePointer.isEqual(a.with, b.with)).toBe(true)
    expect(capability.ability.isEqual(a.can, b.can)).toBe(true)
  })

})