import * as plugins from "@ucans/default-plugins"
import * as core from "@ucans/core"

export * from "@ucans/core"
export * from "@ucans/default-plugins"

const injected = core.getPluginInjectedApi(plugins.defaults)

export const build = injected.build
export const sign = injected.sign
export const signWithKeypair = injected.signWithKeypair
export const validate = injected.validate
export const validateProofs = injected.validateProofs
export const verify = injected.verify
export const Builder = injected.Builder
export const Store = injected.Store
export const delegationChains = injected.delegationChains
