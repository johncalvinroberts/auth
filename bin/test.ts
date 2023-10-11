import { assert } from '@japa/assert'
import { snapshot } from '@japa/snapshot'
import { fileSystem } from '@japa/file-system'
import { expectTypeOf } from '@japa/expect-type'
import { configure, processCLIArgs, run } from '@japa/runner'

processCLIArgs(process.argv.splice(2))
configure({
  suites: [
    {
      name: 'session',
      files: ['tests/modules/session/**/*.spec.ts'],
    },
    {
      name: 'core',
      files: ['tests/core/**/*.spec.ts'],
    },
  ],
  plugins: [assert(), fileSystem(), expectTypeOf(), snapshot()],
})

run()
