/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { fileURLToPath } from 'node:url'
import { IgnitorFactory } from '@adonisjs/core/factories'
import Configure from '@adonisjs/core/commands/configure'

const BASE_URL = new URL('./tmp/', import.meta.url)

test.group('Configure', (group) => {
  group.each.setup(({ context }) => {
    context.fs.baseUrl = BASE_URL
    context.fs.basePath = fileURLToPath(BASE_URL)
  })

  group.each.disableTimeout()

  test('register provider and middleware', async ({ fs, assert }) => {
    const ignitor = new IgnitorFactory()
      .withCoreProviders()
      .withCoreConfig()
      .create(BASE_URL, {
        importer: (filePath) => {
          if (filePath.startsWith('./') || filePath.startsWith('../')) {
            return import(new URL(filePath, BASE_URL).href)
          }

          return import(filePath)
        },
      })

    await fs.create(
      'start/kernel.ts',
      `router.use([])
    export const { middleware } = router.named({
    })`
    )
    await fs.createJson('tsconfig.json', {})
    await fs.create('adonisrc.ts', `export default defineConfig({}) {}`)

    const app = ignitor.createApp('web')
    await app.init()
    await app.boot()

    const ace = await app.container.make('ace')
    const command = await ace.create(Configure, ['../../../index.js', '--guard=session'])
    await command.exec()

    await assert.fileContains('adonisrc.ts', '@adonisjs/auth/auth_provider')
    await assert.fileExists('app/middleware/auth_middleware.ts')
    await assert.fileExists('app/middleware/guest_middleware.ts')

    await assert.fileContains(
      'start/kernel.ts',
      `export const { middleware } = router.named({
  guest: () => import('#middleware/guest_middleware'),
  auth: () => import('#middleware/auth_middleware')
})`
    )
    await assert.fileContains(
      'start/kernel.ts',
      `router.use([() => import('@adonisjs/auth/initialize_auth_middleware')])`
    )
  })
})
