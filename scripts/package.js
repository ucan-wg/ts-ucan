const fs = require("fs")

const CJS = { type: "commonjs" }
const ESM = { type: "module" }

fs.writeFileSync("./dist/cjs/package.json", JSON.stringify(CJS))
fs.writeFileSync("./dist/esm/package.json", JSON.stringify(ESM))