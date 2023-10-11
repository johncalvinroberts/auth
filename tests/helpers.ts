/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { join } from 'node:path'
import { Hash } from '@adonisjs/hash'
import { mkdir } from 'node:fs/promises'
import { getActiveTest } from '@japa/runner'
import { BaseModel } from '@adonisjs/lucid/orm'
import { Database } from '@adonisjs/lucid/database'
import { Scrypt } from '@adonisjs/hash/drivers/scrypt'
import { AppFactory } from '@adonisjs/core/factories/app'
import { LoggerFactory } from '@adonisjs/core/factories/logger'
import { EmitterFactory } from '@adonisjs/core/factories/events'

/**
 * Creates a fresh instance of AdonisJS hash module
 * with scrypt driver
 */
export function getHasher() {
  return new Hash(new Scrypt({}))
}

/**
 * Creates an instance of the database class for making queries
 */
export async function createDatabase() {
  const test = getActiveTest()
  if (!test) {
    throw new Error('Cannot use "createDatabase" outside of a Japa test')
  }

  await mkdir(test.context.fs.basePath)

  const app = new AppFactory().create(test.context.fs.baseUrl, () => {})
  const logger = new LoggerFactory().create()
  const emitter = new EmitterFactory().create(app)
  const db = new Database(
    {
      connection: 'primary',
      connections: {
        primary: {
          client: 'sqlite3',
          connection: {
            filename: join(test.context.fs.basePath, 'db.sqlite3'),
          },
        },
      },
    },
    logger,
    emitter
  )

  test.cleanup(() => db.manager.closeAll())
  BaseModel.useAdapter(db.modelAdapter())
  return db
}

/**
 * Creates needed database tables
 */
export async function createTables(db: Database) {
  const test = getActiveTest()
  if (!test) {
    throw new Error('Cannot use "createTables" outside of a Japa test')
  }

  test.cleanup(async () => {
    await db.connection().schema.dropTable('users')
    await db.connection().schema.dropTable('remember_me_tokens')
  })

  await db.connection().schema.createTable('users', (table) => {
    table.increments()
    table.string('username').unique().notNullable()
    table.string('email').unique().notNullable()
    table.string('password').nullable()
  })

  await db.connection().schema.createTable('remember_me_tokens', (table) => {
    table.string('series', 60).notNullable()
    table.integer('user_id').notNullable().unsigned()
    table.string('type').notNullable()
    table.string('token', 80).notNullable()
    table.datetime('created_at').notNullable()
    table.datetime('updated_at').notNullable()
    table.datetime('expires_at').notNullable()
  })
}
