import * as plugins from "@ucans/plugins"
import * as core from "@ucans/core"

export * from "@ucans/core"
export * from "@ucans/plugins"

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