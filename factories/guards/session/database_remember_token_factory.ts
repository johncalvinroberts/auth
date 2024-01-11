/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Database } from '@adonisjs/lucid/database'
import { DatabaseRememberTokenProvider } from '../../../src/guards/session/token_providers/database.js'

/**
 * Creates instance of the DatabaseRememberTokenProvider
 */
export class DatabaseRememberTokenFactory {
  create(db: Database) {
    return new DatabaseRememberTokenProvider(db, {
      table: 'remember_me_tokens',
    })
  }
}
