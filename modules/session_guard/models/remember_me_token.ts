/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { BaseModel, column } from '@adonisjs/lucid/orm'

export class RememberMeTokenModel extends BaseModel {
  @column()
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
