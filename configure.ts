/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { presetAuth } from '@adonisjs/presets/auth'
import type Configure from '@adonisjs/core/commands/configure'

/**
 * Configures the auth package
 */
export async function configure(command: Configure) {
  const codemods = await command.createCodemods()
  // let guard: string | undefined = command.parsedFlags.guard

  await presetAuth(codemods, command.app, {
    guard: 'session',
    userProvider: 'lucid',
  })
}
