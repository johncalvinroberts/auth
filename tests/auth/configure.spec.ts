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

  test('create config file and register provider', async ({ fs, assert }) => {
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

    await fs.create('start/kernel.ts', `router.use([])`)
    await fs.createJson('tsconfig.json', {})
    await fs.create('adonisrc.ts', `export default defineConfig({}) {}`)

    const app = ignitor.createApp('web')
    await app.init()
    await app.boot()

    const ace = await app.container.make('ace')
    const command = await ace.create(Configure, ['../../../index.js'])
    command.prompt.trap('Select the user provider you want to use').replyWith('lucid')
    await command.exec()

    await assert.fileExists('config/auth.ts')
    await assert.fileExists('adonisrc.ts')
    await assert.fileContains('adonisrc.ts', '@adonisjs/auth/auth_provider')
    await assert.fileContains(
      'config/auth.ts',
      `const userProvider = providers.lucid({
  model: () => import('#models/user'),
  uids: ['email'],
})`
    )
    await assert.fileContains(
      'config/auth.ts',
      `declare module '@adonisjs/auth/types' {
  interface Authenticators extends InferAuthenticators<typeof authConfig> {}
}`
    )
  }).timeout(60 * 1000)

  test('create config file with db user provider', async ({ fs, assert }) => {
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

    await fs.create('start/kernel.ts', `router.use([])`)
    await fs.createJson('tsconfig.json', {})
    await fs.create('adonisrc.ts', `export default defineConfig({}) {}`)

    const app = ignitor.createApp('web')
    await app.init()
    await app.boot()

    const ace = await app.container.make('ace')
    const command = await ace.create(Configure, ['../../../index.js'])
    command.prompt.trap('Select the user provider you want to use').replyWith('db')
    await command.exec()

    await assert.fileExists('config/auth.ts')
    await assert.fileExists('adonisrc.ts')
    await assert.fileContains('adonisrc.ts', '@adonisjs/auth/auth_provider')
    await assert.fileContains(
      'config/auth.ts',
      `const userProvider = providers.db({
  table: 'users',
  passwordColumnName: 'password',
  id: 'id',
  uids: ['email'],
})`
    )
    await assert.fileContains(
      'config/auth.ts',
      `declare module '@adonisjs/auth/types' {
  interface Authenticators extends InferAuthenticators<typeof authConfig> {}
}`
    )
  }).timeout(60 * 1000)

  test('register middleware', async ({ fs, assert }) => {
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
      `
    router.use([])
    export const { middleware } = router.named({
    })
    `
    )
    await fs.createJson('tsconfig.json', {})
    await fs.create('adonisrc.ts', `export default defineConfig({}) {}`)

    const app = ignitor.createApp('web')
    await app.init()
    await app.boot()

    const ace = await app.container.make('ace')
    const command = await ace.create(Configure, ['../../../index.js'])
    command.prompt.trap('Select the user provider you want to use').replyWith('db')
    await command.exec()

    await assert.fileExists('config/auth.ts')
    await assert.fileExists('adonisrc.ts')
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
  }).timeout(60 * 1000)
})
