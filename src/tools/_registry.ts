import * as market from './market'
import * as trader from './trader'

export const allToolSpecs = [...market.toolSpecs, ...trader.toolSpecs]
