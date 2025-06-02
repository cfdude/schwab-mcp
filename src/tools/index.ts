// Tool types
export * from './types'

// Auto-registration of tools
import * as market from './market'
import * as trader from './trader'

export const allToolSpecs = [...trader.toolSpecs, ...market.toolSpecs]
