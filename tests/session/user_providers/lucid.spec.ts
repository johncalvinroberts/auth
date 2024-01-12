/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { compose } from '@poppinss/utils'
import convertHrtime from 'convert-hrtime'
import { BaseModel, column } from '@adonisjs/lucid/orm'

import { createDatabase, createTables, getHasher, timeTravel } from '../../helpers.js'
import { RememberMeToken } from '../../../modules/session_guard/remember_me_token.js'
import { SessionLucidUserProvider } from '../../../modules/session_guard/providers/lucid.js'
import { withRememberMeTokens } from '../../../modules/session_guard/models/remember_me_token.js'

class User extends BaseModel {
  @column()
  declare id: number

  @column()
  declare username: string

  @column()
  declare email: string

  @column()
  declare password: string | null
}

test.group('Session lucid user provider | findById', () => {
  test('return guard user instance', async ({ assert, expectTypeOf }) => {
    const db = await createDatabase()
    await createTables(db)

    const userProvider = new SessionLucidUserProvider(getHasher(), {
      model: async () => {
        return {
          default: User,
        }
      },
      uids: ['username', 'email'],
      passwordColumnName: 'password',
    })

    await User.create({ email: 'virk@adonisjs.com', password: 'secret', username: 'virk' })
    const user = await userProvider.findById(1)

    expectTypeOf(user!.getOriginal()).toEqualTypeOf<User>()
    assert.instanceOf(user!.getOriginal(), User)
    assert.equal(user!.getId(), 1)
  })

  test('return null when no user exists', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const userProvider = new SessionLucidUserProvider(getHasher(), {
      model: async () => {
        return {
          default: User,
        }
      },
      uids: ['username', 'email'],
      passwordColumnName: 'password',
    })

    const user = await userProvider.findById(1)
    assert.isNull(user)
  })
})

test.group('Session lucid user provider | findByUid', () => {
  test('return guard user instance', async ({ assert, expectTypeOf }) => {
    const db = await createDatabase()
    await createTables(db)

    const userProvider = new SessionLucidUserProvider(getHasher(), {
      model: async () => {
        return {
          default: User,
        }
      },
      uids: ['username', 'email'],
      passwordColumnName: 'password',
    })

    await User.create({ email: 'virk@adonisjs.com', password: 'secret', username: 'virk' })
    const user = await userProvider.findByUid('virk@adonisjs.com')

    expectTypeOf(user!.getOriginal()).toEqualTypeOf<User>()
    assert.instanceOf(user!.getOriginal(), User)
  })

  test('return null when no user exists', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const userProvider = new SessionLucidUserProvider(getHasher(), {
      model: async () => {
        return {
          default: User,
        }
      },
      uids: ['username', 'email'],
      passwordColumnName: 'password',
    })

    const user = await userProvider.findByUid(1)
    assert.isNull(user)
  })

  test('use custom lookup method when defined on the model', async ({ assert, expectTypeOf }) => {
    assert.plan(2)

    const db = await createDatabase()
    await createTables(db)

    class AuthUser extends User {
      static async getUserForAuth(uids: string[], value: string | number) {
        assert.deepEqual(uids, ['username', 'email'])

        const query = this.query()
        uids.forEach((uid) => query.orWhere(uid, value))
        return query.first()
      }
    }

    const userProvider = new SessionLucidUserProvider(getHasher(), {
      model: async () => {
        return {
          default: AuthUser,
        }
      },
      uids: ['username', 'email'],
      passwordColumnName: 'password',
    })

    await User.create({ email: 'virk@adonisjs.com', password: 'secret', username: 'virk' })
    const user = await userProvider.findByUid('virk@adonisjs.com')

    expectTypeOf(user!.getOriginal()).toEqualTypeOf<User>()
    assert.instanceOf(user!.getOriginal(), User)
  })

  test('return null when custom method does not return a user', async ({ assert }) => {
    assert.plan(2)

    const db = await createDatabase()
    await createTables(db)

    class AuthUser extends User {
      static async getUserForAuth(uids: string[], value: string | number) {
        assert.deepEqual(uids, ['username', 'email'])

        const query = this.query()
        uids.forEach((uid) => query.orWhere(uid, value))
        return query.first()
      }
    }

    const userProvider = new SessionLucidUserProvider(getHasher(), {
      model: async () => {
        return {
          default: AuthUser,
        }
      },
      uids: ['username', 'email'],
      passwordColumnName: 'password',
    })

    const user = await userProvider.findByUid('virk@adonisjs.com')
    assert.isNull(user)
  })
})

test.group('Session lucid user provider | verifyCredentials', () => {
  test('return guard user instance when credentials are valid', async ({
    assert,
    expectTypeOf,
  }) => {
    const db = await createDatabase()
    const hasher = getHasher()
    await createTables(db)

    const userProvider = new SessionLucidUserProvider(hasher, {
      model: async () => {
        return {
          default: User,
        }
      },
      uids: ['username', 'email'],
      passwordColumnName: 'password',
    })

    await User.create({
      email: 'virk@adonisjs.com',
      password: await hasher.make('secret'),
      username: 'virk',
    })
    const user = await userProvider.verifyCredentials('virk@adonisjs.com', 'secret')

    expectTypeOf(user!.getOriginal()).toEqualTypeOf<User>()
    assert.instanceOf(user!.getOriginal(), User)
  })

  test('return null when password is invalid', async ({ assert }) => {
    const db = await createDatabase()
    const hasher = getHasher()
    await createTables(db)

    const userProvider = new SessionLucidUserProvider(hasher, {
      model: async () => {
        return {
          default: User,
        }
      },
      uids: ['username', 'email'],
      passwordColumnName: 'password',
    })

    await User.create({
      email: 'virk@adonisjs.com',
      password: await hasher.make('secret'),
      username: 'virk',
    })

    const user = await userProvider.verifyCredentials('virk@adonisjs.com', 'supersecret')
    assert.isNull(user)
  })

  test('return null when unable to find user', async ({ assert }) => {
    const db = await createDatabase()
    const hasher = getHasher()
    await createTables(db)

    const userProvider = new SessionLucidUserProvider(hasher, {
      model: async () => {
        return {
          default: User,
        }
      },
      uids: ['username', 'email'],
      passwordColumnName: 'password',
    })

    const user = await userProvider.verifyCredentials('virk@adonisjs.com', 'secret')
    assert.isNull(user)
  })

  test('throw error when user does not have a password column', async ({ assert }) => {
    const db = await createDatabase()
    const hasher = getHasher()
    await createTables(db)

    const userProvider = new SessionLucidUserProvider(hasher, {
      model: async () => {
        return {
          default: User,
        }
      },
      uids: ['username', 'email'],
      passwordColumnName: 'password',
    })

    await User.create({
      email: 'virk@adonisjs.com',
      password: null,
      username: 'virk',
    })

    await assert.rejects(
      () => userProvider.verifyCredentials('virk@adonisjs.com', 'secret'),
      'Cannot verify password during login. The value of column "password" is undefined or null'
    )
  })

  test('prevent timing attacks', async ({ assert }) => {
    const db = await createDatabase()
    const hasher = getHasher()
    await createTables(db)

    const userProvider = new SessionLucidUserProvider(hasher, {
      model: async () => {
        return {
          default: User,
        }
      },
      uids: ['username', 'email'],
      passwordColumnName: 'password',
    })

    await User.create({
      email: 'virk@adonisjs.com',
      password: await hasher.make('secret'),
      username: 'virk',
    })

    let startTime = process.hrtime.bigint()
    await userProvider.verifyCredentials('foo@adonisjs.com', 'secret')
    const invalidEmailTime = convertHrtime(process.hrtime.bigint() - startTime)

    startTime = process.hrtime.bigint()
    await userProvider.verifyCredentials('virk@adonisjs.com', 'supersecret')
    const invalidPasswordTime = convertHrtime(process.hrtime.bigint() - startTime)

    /**
     * Same timing within the range of 10 milliseconds is acceptable
     */
    assert.isBelow(Math.abs(invalidPasswordTime.seconds - invalidEmailTime.seconds), 1)
    assert.isBelow(Math.abs(invalidPasswordTime.milliseconds - invalidEmailTime.milliseconds), 10)
  })
})

test.group('Session lucid user provider | guardUser', () => {
  test('create guard user from model instance', async ({ assert, expectTypeOf }) => {
    const db = await createDatabase()
    await createTables(db)

    const userProvider = new SessionLucidUserProvider(getHasher(), {
      model: async () => {
        return {
          default: User,
        }
      },
      uids: ['username', 'email'],
      passwordColumnName: 'password',
    })

    const user = await User.create({
      email: 'virk@adonisjs.com',
      password: 'secret',
      username: 'virk',
    })
    const guardUser = await userProvider.createUserForGuard(user)

    expectTypeOf(guardUser!.getOriginal()).toEqualTypeOf<User>()
    assert.instanceOf(guardUser!.getOriginal(), User)
    assert.strictEqual(guardUser!.getOriginal(), user)
  })

  test('throw error when user input is invalid', async () => {
    const db = await createDatabase()
    await createTables(db)

    const userProvider = new SessionLucidUserProvider(getHasher(), {
      model: async () => {
        return {
          default: User,
        }
      },
      uids: ['username', 'email'],
      passwordColumnName: 'password',
    })

    // @ts-expect-error
    await userProvider.createUserForGuard({})
  }).throws('Invalid user object. It must be an instance of the "User" model')

  test('throw error when user does not have an id', async () => {
    const db = await createDatabase()
    await createTables(db)

    const userProvider = new SessionLucidUserProvider(getHasher(), {
      model: async () => {
        return {
          default: User,
        }
      },
      uids: ['username', 'email'],
      passwordColumnName: 'password',
    })

    const user = await userProvider.createUserForGuard(new User())
    user.getId()
  }).throws(
    'Cannot use "User" model for authentication. The value of column "id" is undefined or null'
  )
})

test.group('Session lucid user provider | rememberTokens | create', () => {
  test('throw error when not using withRememberMeTokens mixin', async () => {
    const db = await createDatabase()
    await createTables(db)

    const userProvider = new SessionLucidUserProvider(getHasher(), {
      model: async () => {
        return {
          default: User,
        }
      },
      uids: ['username', 'email'],
      passwordColumnName: 'password',
    })

    const token = RememberMeToken.create(1, '20 mins')
    await userProvider.createRememberMeToken(token)
  }).throws(
    'Cannot perist remember me token using "User" model. Make sure to use "withRememberMeTokens" mixin'
  )

  test('create a token for the user', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    class AuthUser extends compose(User, withRememberMeTokens()) {}

    const userProvider = new SessionLucidUserProvider(getHasher(), {
      model: async () => {
        return {
          default: AuthUser,
        }
      },
      uids: ['username', 'email'],
      passwordColumnName: 'password',
    })

    await AuthUser.create({ email: 'virk@adonisjs.com', password: 'secret', username: 'virk' })
    const token = RememberMeToken.create(1, '20 mins')
    await userProvider.createRememberMeToken(token)

    const tokens = await AuthUser.rememberMeTokens.all()
    assert.deepEqual(tokens[0].$attributes, {
      userId: 1,
      createdAt: token.createdAt.getTime(),
      updatedAt: token.updatedAt.getTime(),
      expiresAt: token.expiresAt.getTime(),
      series: token.series,
      hash: token.hash,
    })
  })
})

test.group('Session lucid user provider | rememberTokens | find', () => {
  test('find token by series', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    class AuthUser extends compose(User, withRememberMeTokens()) {}

    const userProvider = new SessionLucidUserProvider(getHasher(), {
      model: async () => {
        return {
          default: AuthUser,
        }
      },
      uids: ['username', 'email'],
      passwordColumnName: 'password',
    })

    await AuthUser.create({ email: 'virk@adonisjs.com', password: 'secret', username: 'virk' })
    const token = RememberMeToken.create(1, '20 mins')
    await userProvider.createRememberMeToken(token)
    const rememberMeToken = await userProvider.findRememberMeTokenBySeries(token.series)

    assert.instanceOf(rememberMeToken, RememberMeToken)
    assert.equal(rememberMeToken!.expiresAt.getTime(), token.expiresAt.getTime())
    assert.equal(rememberMeToken!.updatedAt.getTime(), token.updatedAt.getTime())
    assert.equal(rememberMeToken!.createdAt.getTime(), token.createdAt.getTime())
    assert.equal(rememberMeToken!.hash, token.hash)
    assert.equal(rememberMeToken!.series, token.series)
  })

  test('return null when token is missing', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    class AuthUser extends compose(User, withRememberMeTokens()) {}

    const userProvider = new SessionLucidUserProvider(getHasher(), {
      model: async () => {
        return {
          default: AuthUser,
        }
      },
      uids: ['username', 'email'],
      passwordColumnName: 'password',
    })

    await AuthUser.create({ email: 'virk@adonisjs.com', password: 'secret', username: 'virk' })
    const token = RememberMeToken.create(1, '20 mins')

    const rememberMeToken = await userProvider.findRememberMeTokenBySeries(token.series)
    assert.isNull(rememberMeToken)
  })

  test('return null when token has been expired', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    class AuthUser extends compose(User, withRememberMeTokens()) {}

    const userProvider = new SessionLucidUserProvider(getHasher(), {
      model: async () => {
        return {
          default: AuthUser,
        }
      },
      uids: ['username', 'email'],
      passwordColumnName: 'password',
    })

    await AuthUser.create({ email: 'virk@adonisjs.com', password: 'secret', username: 'virk' })
    const token = RememberMeToken.create(1, '20 mins')
    await userProvider.createRememberMeToken(token)

    timeTravel(21 * 60)

    const rememberMeToken = await userProvider.findRememberMeTokenBySeries(token.series)
    assert.isNull(rememberMeToken)
  })
})

test.group('Session lucid user provider | rememberTokens | recycle', () => {
  test('update token hash and timestamps', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    class AuthUser extends compose(User, withRememberMeTokens()) {}

    const userProvider = new SessionLucidUserProvider(getHasher(), {
      model: async () => {
        return {
          default: AuthUser,
        }
      },
      uids: ['username', 'email'],
      passwordColumnName: 'password',
    })

    await AuthUser.create({ email: 'virk@adonisjs.com', password: 'secret', username: 'virk' })
    const token = RememberMeToken.create(1, '20 mins')
    const existingHash = token.hash
    const existingExpiresAt = token.expiresAt.getTime()
    const existingUpdateAt = token.updatedAt.getTime()

    await userProvider.createRememberMeToken(token)

    token.refresh('30 mins')
    await userProvider.recycleRememberMeToken(token)

    const tokens = await AuthUser.rememberMeTokens.all()
    assert.equal(tokens[0].hash, token.hash)
    assert.equal(tokens[0].expiresAt, token.expiresAt.getTime())
    assert.equal(tokens[0].updatedAt, token.updatedAt.getTime())
    assert.notEqual(tokens[0].expiresAt, existingExpiresAt)
    assert.notEqual(tokens[0].updatedAt, existingUpdateAt)
    assert.notEqual(tokens[0].hash, existingHash)
  })

  test('noop when no tokens exists in first place', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    class AuthUser extends compose(User, withRememberMeTokens()) {}

    const userProvider = new SessionLucidUserProvider(getHasher(), {
      model: async () => {
        return {
          default: AuthUser,
        }
      },
      uids: ['username', 'email'],
      passwordColumnName: 'password',
    })

    await AuthUser.create({ email: 'virk@adonisjs.com', password: 'secret', username: 'virk' })
    const token = RememberMeToken.create(1, '20 mins')
    token.refresh('30 mins')
    await userProvider.recycleRememberMeToken(token)

    const tokens = await AuthUser.rememberMeTokens.all()
    assert.lengthOf(tokens, 0)
  })
})

test.group('Session lucid user provider | rememberTokens | delete', () => {
  test('delete token by series', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    class AuthUser extends compose(User, withRememberMeTokens()) {}

    const userProvider = new SessionLucidUserProvider(getHasher(), {
      model: async () => {
        return {
          default: AuthUser,
        }
      },
      uids: ['username', 'email'],
      passwordColumnName: 'password',
    })

    await AuthUser.create({ email: 'virk@adonisjs.com', password: 'secret', username: 'virk' })
    const token = RememberMeToken.create(1, '20 mins')
    await userProvider.createRememberMeToken(token)
    await userProvider.deleteRememberMeTokenBySeries(token.series)

    const tokens = await AuthUser.rememberMeTokens.all()
    assert.lengthOf(tokens, 0)
  })

  test('noop when no tokens exists in first place', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    class AuthUser extends compose(User, withRememberMeTokens()) {}

    const userProvider = new SessionLucidUserProvider(getHasher(), {
      model: async () => {
        return {
          default: AuthUser,
        }
      },
      uids: ['username', 'email'],
      passwordColumnName: 'password',
    })

    await AuthUser.create({ email: 'virk@adonisjs.com', password: 'secret', username: 'virk' })
    const token = RememberMeToken.create(1, '20 mins')
    await userProvider.createRememberMeToken(token)
    await userProvider.deleteRememberMeTokenBySeries('foo')

    const tokens = await AuthUser.rememberMeTokens.all()
    assert.lengthOf(tokens, 1)
  })
})
