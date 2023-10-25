/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { stubsRoot } from './index.js'
import type Configure from '@adonisjs/core/commands/configure'

/**
 * Configures the user provider to use for finding
 * users
 */
async function configureProvider(command: Configure) {
  const provider = await command.prompt.choice('Select the user provider you want to use', [
    {
      name: 'lucid',
      message: 'Lucid models',
    },
    {
      name: 'db',
      message: 'Database query builder',
    },
  ])

  /**
   * Publish config file
   */
  await command.publishStub('config.stub', { provider })
}

/**
 * Configures the session guard and output its config
 * to the console
 */
async function configureSessionGuard(command: Configure) {
  const tokens = await command.prompt.confirm('Do you want to use remember me tokens?')

  const stubs = await command.app.stubs.create()
  const stub = await stubs.build('guards/session.stub', { source: stubsRoot })
  const { contents } = await stub.prepare({ tokens })

  command.logger.log(contents)
}

/**
 * Configures the auth package
 */
export async function configure(command: Configure) {
  if (command.parsedFlags && command.parsedFlags.guard === 'session') {
    return configureSessionGuard(command)
  }

  await configureProvider(command)
  const codemods = await command.createCodemods()

  /**
   * Register provider
   */
  await codemods.updateRcFile((rcFile) => {
    rcFile.addProvider('@adonisjs/auth/auth_provider')
  })

  /**
   * Register middleware
   */
  await codemods.registerMiddleware('router', [
    {
      path: '@adonisjs/auth/initialize_auth_middleware',
    },
  ])
  await codemods.registerMiddleware('named', [
    {
      name: 'auth',
      path: '@adonisjs/auth/auth_middleware',
    },
  ])
}
