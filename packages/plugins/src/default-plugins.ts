import { Plugins } from "@ucans/core"
import { ed25519Plugin } from "./ed25519/plugin.js"
import { p256Plugin } from "./p256/plugin.js"
import { rsaPlugin, rsaOldPlugin } from "./rsa/plugin.js"

export const defaults: Plugins = {
  keys: [ed25519Plugin, p256Plugin, rsaPlugin, rsaOldPlugin],
  methods: {},
}