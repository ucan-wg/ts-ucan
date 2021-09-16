module.exports = { // eslint-disable-line
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
