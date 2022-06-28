import { plugins } from '@ucans/defaults'
import { loadPlugins } from '../src/plugins'

export const loadTestPlugins = () => {
  loadPlugins({
    keys: [plugins.edwards, plugins.rsa, plugins.rsaOld],
    methods: [],
  })
}