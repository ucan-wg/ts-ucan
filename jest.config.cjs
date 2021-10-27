module.exports = { // eslint-disable-line
  resolver: "jest-ts-webcompat-resolver",
  transform: {
    ".(ts|tsx)": "ts-jest"
  },
  testEnvironment: "node",
  testRegex: "(/__tests__/.*|\\.(test|spec))\\.(ts|tsx|js)$",
  moduleFileExtensions: [
    "ts",
    "tsx",
    "js"
  ],
}
