import Plugins from "./plugins.js"
import * as token from "./token.js"
import * as verifyLib from "./verify.js"
import * as attenuation from "./attenuation.js"
import mkBuilderClass from "./builder.js"
import mkStoreClass from "./store.js"

export * from "./attenuation.js"
export * from "./builder.js"
export * from "./store.js"
export * from "./token.js"
export * from "./types.js"
export * from "./verify.js"
export * from "./plugins.js"
export * from "./util.js"

export * as capability from "./capability/index.js"
export * as ability from "./capability/ability.js"

export { ResourcePointer, isResourcePointer } from "./capability/resource-pointer.js"
export { Ability, isAbility, Superuser, SUPERUSER } from "./capability/ability.js"
export { Capability, EncodedCapability, isCapability } from "./capability/index.js"

export const getPluginInjectedApi = (plugins: Plugins) => {
  const build = token.build(plugins)
  const sign = token.sign(plugins)
  const signWithKeypair = token.signWithKeypair(plugins)
  const validate = token.validate(plugins)
  const validateProofs = token.validateProofs(plugins)
  const verify = verifyLib.verify(plugins)
  const delegationChains = attenuation.delegationChains(plugins)
  const Builder = mkBuilderClass(plugins)
  const Store = mkStoreClass(plugins)

  return {
    build,
    sign,
    signWithKeypair,
    validate,
    validateProofs,
    verify,
    delegationChains,
    Builder,
    Store
  }
}