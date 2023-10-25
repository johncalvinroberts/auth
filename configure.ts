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
 * Configures the auth package
 */
export async function configure(command: Configure) {
  const codemods = await command.createCodemods()

  /**
   * Publish middleware to user application
   */
  await command.publishStub('middleware/auth_middleware.stub', {
    entity: command.app.generators.createEntity('auth'),
  })
  await command.publishStub('middleware/guest_middleware.stub', {
    entity: command.app.generators.createEntity('guest'),
  })

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
      path: '#middleware/auth_middleware',
    },
    {
      name: 'guest',
      path: '#middleware/guest_middleware',
    },
  ])
}
