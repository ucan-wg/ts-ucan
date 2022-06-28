import * as plugins from '@ucans/plugins'
import { loadPlugins } from '../src/plugins'

export const loadTestPlugins = () => {
  loadPlugins(plugins.defaults)
}