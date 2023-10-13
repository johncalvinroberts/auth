/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Hash } from '@adonisjs/core/hash'
import { BaseModel, column } from '@adonisjs/lucid/orm'
import { Scrypt } from '@adonisjs/core/hash/drivers/scrypt'
import { LucidUserProvider } from '../src/core/user_providers/lucid.js'
import { LucidAuthenticatable, LucidUserProviderOptions } from '../src/core/types.js'
import { PROVIDER_REAL_USER } from '../src/symbols.js'

export class FactoryUser extends BaseModel {
  static table = 'users'

  static createWithDefaults(attributes?: {
    email?: string
    password?: string | null
    username?: string
  }) {
    return this.create({
      email: 'foo@bar.com',
      username: 'foo',
      password: 'secret',
      ...attributes,
    })
  }

  @column()
  declare id: number

  @column()
  declare username: string

  @column()
  declare email: string

  @column()
  declare password: string | null

  async verifyPasswordForAuth(plainTextPassword: string) {
    return new Hash(new Scrypt({})).verify(this.password!, plainTextPassword)
  }
}

export class TestLucidUserProvider<
  UserModel extends LucidAuthenticatable,
> extends LucidUserProvider<UserModel> {
  declare [PROVIDER_REAL_USER]: InstanceType<UserModel>
}

/**
 * Creates an instance of the LucidUserProvider with sane
 * defaults for testing
 */
export class LucidUserProviderFactory {
  createForModel<Model extends LucidAuthenticatable>(
    model: Model,
    options: LucidUserProviderOptions<Model>
  ) {
    return new TestLucidUserProvider(
      async () => {
        return {
          default: model,
        }
      },
      {
        ...options,
      }
    )
  }

  create() {
    return this.createForModel(FactoryUser, { uids: ['email', 'username'] })
  }
}
