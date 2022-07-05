import Plugins from "./plugins.js"
import * as token from "./token.js"
import * as verifyLib from "./verify.js"
import * as attenuation from "./attenuation.js"
import * as builder from "./builder.js"
import * as store from "./store.js"

export * from "./attenuation.js"
export * from "./builder.js"
export * from "./store.js"
export * from "./token.js"
export * from "./types.js"
export * from "./verify.js"
export * from "./plugins.js"

export * as capability from "./capability/index.js"
export * as ability from "./capability/ability.js"

export { Capability, EncodedCapability, isCapability } from "./capability/index.js"

export const injectPlugins = (plugins: Plugins) => {
  const build = token.build(plugins)
  const sign = token.sign(plugins)
  const signWithKeypair = token.signWithKeypair(plugins)
  const validate = token.validate(plugins)
  const validateProofs = token.validateProofs(plugins)
  const verify = verifyLib.verify(plugins)
  const createBuilder = builder.createBuilder(plugins)
  const storeFromTokens = store.storeFromTokens(plugins)
  const emptyStore = store.emptyStore(plugins)
  const delegationChains = attenuation.delegationChains(plugins)

  return {
    build,
    sign,
    signWithKeypair,
    validate,
    validateProofs,
    verify,
    createBuilder,
    storeFromTokens,
    emptyStore,
    delegationChains,
  }
}