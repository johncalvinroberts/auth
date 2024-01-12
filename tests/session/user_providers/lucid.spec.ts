/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import convertHrtime from 'convert-hrtime'
import { BaseModel, column } from '@adonisjs/lucid/orm'
import { createDatabase, createTables, getHasher } from '../../helpers.js'
import { SessionLucidUserProvider } from '../../../modules/session_guard/user_providers/lucid.js'

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
