import * as core from "../src"
import * as plugins from "@ucans/plugins"

export * from "../src"

const injected = core.getPluginInjectedApi(plugins.defaults)

export const build = injected.build
export const sign = injected.sign
export const signWithKeypair = injected.signWithKeypair
export const validate = injected.validate
export const validateProofs = injected.validateProofs
export const verify = injected.verify
export const createBuilder = injected.createBuilder
export const storeFromTokens = injected.storeFromTokens
export const emptyStore = injected.emptyStore
export const delegationChains = injected.delegationChains