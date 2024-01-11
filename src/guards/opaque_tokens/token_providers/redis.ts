/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { Connection } from '@adonisjs/redis/types'

import { OpaqueToken } from '../token.js'
import type { TokenProviderContract } from '../../../core/types.js'

export class RedisOpaqueTokenProvider implements TokenProviderContract<OpaqueToken> {
  constructor(protected redisConnection: Connection) {}

  /**
   * Persists the opaque token inside the redis database
   */
  async createToken(token: OpaqueToken): Promise<void> {
    const key = token.series
    const value = JSON.stringify({
      guard: token.guard,
      user_id: token.userId,
      hash: token.hash,
      meta_data: token.metaData,
    })

    const ttl = Math.ceil(Math.abs(token.expiresAt.getTime() - new Date().getTime()) / 1000)
    await this.redisConnection.setex(key, ttl, value)
  }

  /**
   * Finds a token by series inside the redis database and returns an
   * instance of it.
   *
   * Returns null if the token is missing or expired
   */
  async getTokenBySeries(series: string): Promise<OpaqueToken | null> {
    const value = await this.redisConnection.get(series)
    if (!value) {
      return null
    }

    const token = JSON.parse(value)
    const opaqueToken = new OpaqueToken(token.user_id, series, undefined, token.hash)
    opaqueToken.metaData = token.meta_data
    opaqueToken.guard = token.guard
    return opaqueToken
  }
}
