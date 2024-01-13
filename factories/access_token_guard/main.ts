/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Secret } from '@adonisjs/core/helpers'
import stringHelpers from '@adonisjs/core/helpers/string'

import { PROVIDER_REAL_USER } from '../../src/symbols.js'
import { AccessToken } from '../../modules/access_token_guard/access_token.js'
import {
  GuardUser,
  AccessTokenUserProviderContract,
} from '../../modules/access_token_guard/types.js'

/**
 * Representation of a fake user used to test
 * the access token guard.
 *
 * @note
 * Should not be exported to the outside world
 */
type AccessTokenFakeUser = {
  id: number
  email: string
  password: string
}

/**
 * Collection of dummy users
 */
const users: AccessTokenFakeUser[] = [
  {
    id: 1,
    email: 'virk@adonisjs.com',
    password: 'secret',
  },
  {
    id: 2,
    email: 'romain@adonisjs.com',
    password: 'secret',
  },
]

/**
 * Implementation of a user provider to be used by session guard for
 * authentication. Used for testing.
 *
 * @note
 * Should not be exported to the outside world
 */
export class AccessTokenFakeUserProvider
  implements AccessTokenUserProviderContract<AccessTokenFakeUser>
{
  declare [PROVIDER_REAL_USER]: AccessTokenFakeUser
  #tokens: {
    identifier: string
    userId: number
    hash: string
    createdAt: Date
    updatedAt: Date
    expiresAt: Date
  }[] = []

  findUser(id: number) {
    return users.find((user) => user.id === id) || null
  }

  /**
   * Creates an access token for a given user
   */
  async createToken(user: AccessTokenFakeUser): Promise<AccessToken> {
    const accessToken = AccessToken.create(stringHelpers.random(15), '20 mins', 'oat_')
    this.#tokens.push({
      identifier: accessToken.identifier,
      userId: user.id,
      hash: accessToken.hash,
      createdAt: accessToken.createdAt,
      updatedAt: accessToken.updatedAt,
      expiresAt: accessToken.expiresAt,
    })

    return accessToken
  }

  async deleteToken(token: Secret<string>): Promise<void> {
    const decodedToken = AccessToken.decode('oat_', token!.release())
    if (!decodedToken) {
      return
    }

    this.#tokens = this.#tokens.filter(({ identifier }) => {
      return identifier !== decodedToken.identifier
    })
  }

  /**
   * Returns a user for the given token
   */
  async findUserByToken(token: Secret<string>): Promise<GuardUser<AccessTokenFakeUser> | null> {
    const decodedToken = AccessToken.decode('oat_', token!.release())
    if (!decodedToken) {
      return null
    }

    const matchingToken = this.#tokens.find(
      ({ identifier }) => identifier === decodedToken.identifier
    )
    if (!matchingToken) {
      return null
    }

    const accessToken = new AccessToken({
      identifier: matchingToken.identifier,
      hash: matchingToken.hash,
      createdAt: matchingToken.createdAt,
      updatedAt: matchingToken.updatedAt,
      expiresAt: matchingToken.expiresAt,
    })

    if (accessToken.isExpired() || !accessToken.verify(decodedToken.seed)) {
      return null
    }

    const user = users.find(({ id }) => id === matchingToken.userId)
    return user
      ? {
          getId() {
            return user.id
          },
          getOriginal() {
            return user
          },
        }
      : null
  }
}
