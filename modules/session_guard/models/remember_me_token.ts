/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { BaseModel, column } from '@adonisjs/lucid/orm'
import { NormalizeConstructor } from '@adonisjs/core/types/helpers'

export class RememberMeTokenModel extends BaseModel {
  /**
   * The series property is the primary key
   */
  static selfAssignPrimaryKey = true
  static table = 'remember_me_tokens'

  @column({ isPrimary: true })
  declare series: string

  @column()
  declare userId: number | string | BigInt

  @column()
  declare hash: string

  @column()
  declare type: string

  @column()
  declare guard: string

  @column()
  declare createdAt: Date

  @column()
  declare updatedAt: Date

  @column()
  declare expiresAt: Date
}

/**
 * Mixin to add support for remember me tokens on a
 * user model
 */
export function withRememberMeTokens() {
  return <T extends NormalizeConstructor<typeof BaseModel>>(superclass: T) => {
    return class extends superclass {
      static rememberMeTokens = RememberMeTokenModel
    }
  }
}
