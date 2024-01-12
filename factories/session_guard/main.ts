/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { RememberMeToken } from '../../modules/session_guard/remember_me_token.js'
import { GuardUser, SessionUserProviderContract } from '../../modules/session_guard/types.js'
import { PROVIDER_REAL_USER } from '../../src/symbols.js'

/**
 * Representation of a fake user used to test
 * the session guard.
 *
 * @note
 * Should not be exported to the outside world
 */
type SessionFakeUser = {
  id: number
  email: string
  password: string
}

/**
 * Collection of dummy users
 */
const users: SessionFakeUser[] = [
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
export class SessionFakeUserProvider implements SessionUserProviderContract<SessionFakeUser> {
  declare [PROVIDER_REAL_USER]: SessionFakeUser
  #token?: RememberMeToken

  /**
   * Provide a token to use for "findRememberMeTokenBySeries" method.
   */
  useToken(token: RememberMeToken) {
    this.#token = token
  }

  async createUserForGuard(user: SessionFakeUser): Promise<GuardUser<SessionFakeUser>> {
    return {
      getId() {
        return user.id
      },
      getOriginal() {
        return user
      },
    }
  }

  async findById(userId: string | number | BigInt): Promise<GuardUser<SessionFakeUser> | null> {
    const user = users.find(({ id }) => id === userId)
    if (!user) {
      return null
    }

    return this.createUserForGuard(user)
  }

  async findByUid(uid: string | number): Promise<GuardUser<SessionFakeUser> | null> {
    const user = users.find(({ email }) => email === uid)
    if (!user) {
      return null
    }

    return this.createUserForGuard(user)
  }

  async verifyCredentials(
    uid: string | number,
    password: string
  ): Promise<GuardUser<SessionFakeUser> | null> {
    const user = await this.findByUid(uid)
    if (!user) {
      return null
    }

    if (user.getOriginal().password !== password) {
      return null
    }

    return user
  }

  async findRememberMeTokenBySeries(series: string): Promise<RememberMeToken | null> {
    if (!this.#token) {
      return null
    }
    if (this.#token.series !== series) {
      return null
    }
    if (this.#token.isExpired() || this.#token.type !== 'remember_me_token') {
      return null
    }

    return this.#token
  }

  async recycleRememberMeToken(token: RememberMeToken): Promise<void> {
    this.#token = token
  }
}
