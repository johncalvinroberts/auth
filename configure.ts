/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

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
 * Configures the auth package
 */
export async function configure(command: Configure) {
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
