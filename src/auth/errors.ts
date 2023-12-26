/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { I18n } from '@adonisjs/i18n'
import { Exception } from '@poppinss/utils'
import { HttpContext } from '@adonisjs/core/http'

/**
 * Authentication exception is raised when an attempt is
 * made to authenticate an HTTP request
 */
export class AuthenticationException extends Exception {
  static status?: number | undefined = 401
  static code?: string | undefined = 'E_UNAUTHORIZED_ACCESS'

  /**
   * Raises authentication exception when session guard
   * is unable to authenticate the request
   */
  static E_INVALID_AUTH_SESSION() {
    return new AuthenticationException('Invalid or expired authentication session', {
      code: 'E_INVALID_AUTH_SESSION',
      status: 401,
      guardDriverName: 'session',
    })
  }

  /**
   * Raises authentication exception when session guard
   * is unable to authenticate the request
   */
  static E_INVALID_BASIC_AUTH_CREDENTIALS() {
    return new AuthenticationException('Invalid basic auth credentials', {
      code: 'E_INVALID_BASIC_AUTH_CREDENTIALS',
      status: 401,
      guardDriverName: 'basic_auth',
    })
  }

  guardDriverName: string
  redirectTo?: string
  identifier = 'auth.authenticate'

  constructor(
    message: string,
    options: ErrorOptions & {
      guardDriverName: string
      redirectTo?: string
      code?: string
      status?: number
    }
  ) {
    super(message, options)
    this.guardDriverName = options.guardDriverName
    this.redirectTo = options.redirectTo
  }

  /**
   * Returns the message to be sent in the HTTP response.
   * Feel free to override this method and return a custom
   * response.
   */
  getResponseMessage(error: AuthenticationException, ctx: HttpContext) {
    if ('i18n' in ctx) {
      return (ctx.i18n as I18n).t(error.identifier, {}, error.message)
    }
    return error.message
  }

  /**
   * A collection of authentication exception
   * renderers to render the exception to a
   * response.
   *
   * The collection is a key-value pair, where the
   * key is the guard driver name and value is
   * a factory function to respond to the
   * request.
   */
  renderers: Record<
    string,
    (message: string, error: AuthenticationException, ctx: HttpContext) => Promise<void> | void
  > = {
    session: (message, error, ctx) => {
      switch (ctx.request.accepts(['html', 'application/vnd.api+json', 'json'])) {
        case 'html':
        case null:
          ctx.session.flashExcept(['_csrf'])
          ctx.session.flashErrors({ [error.identifier]: [message] })
          ctx.response.redirect(error.redirectTo || '/', true)
          break
        case 'json':
          ctx.response.status(error.status).send({
            errors: [
              {
                message,
              },
            ],
          })
          break
        case 'application/vnd.api+json':
          ctx.response.status(error.status).send({
            errors: [
              {
                code: error.identifier,
                title: message,
              },
            ],
          })
          break
      }
    },
    basic_auth: (message, _, ctx) => {
      ctx.response
        .status(this.status)
        .header('WWW-Authenticate', `Basic realm="Authenticate", charset="UTF-8"`)
        .send(message)
    },
  }

  /**
   * Self handles the auth exception and converts it to an
   * HTTP response
   */
  async handle(error: AuthenticationException, ctx: HttpContext) {
    const renderer = this.renderers[this.guardDriverName]
    const message = error.getResponseMessage(error, ctx)

    if (!renderer) {
      return ctx.response.status(error.status).send(message)
    }

    return renderer(message, error, ctx)
  }
}

/**
 * Invalid credentials exception is raised when unable
 * to verify user credentials during login
 */
export class InvalidCredentialsException extends Exception {
  static message: string = 'Invalid credentials'
  static code: string = 'E_INVALID_CREDENTIALS'
  static status?: number | undefined = 400

  static E_INVALID_CREDENTIALS(guardDriverName: string) {
    return new InvalidCredentialsException(InvalidCredentialsException.message, {
      guardDriverName,
    })
  }

  guardDriverName: string
  identifier = 'auth.login'

  constructor(
    message: string,
    options: ErrorOptions & {
      guardDriverName: string
      code?: string
      status?: number
    }
  ) {
    super(message, options)
    this.guardDriverName = options.guardDriverName
  }

  /**
   * Returns the message to be sent in the HTTP response.
   * Feel free to override this method and return a custom
   * response.
   */
  getResponseMessage(error: InvalidCredentialsException, ctx: HttpContext) {
    if ('i18n' in ctx) {
      return (ctx.i18n as I18n).t(this.identifier, {}, error.message)
    }
    return error.message
  }

  /**
   * A collection of authentication exception
   * renderers to render the exception to a
   * response.
   *
   * The collection is a key-value pair, where the
   * key is the guard driver name and value is
   * a factory function to respond to the
   * request.
   */
  renderers: Record<
    string,
    (message: string, error: InvalidCredentialsException, ctx: HttpContext) => Promise<void> | void
  > = {
    session: (message, error, ctx) => {
      switch (ctx.request.accepts(['html', 'application/vnd.api+json', 'json'])) {
        case 'html':
        case null:
          ctx.session.flashExcept(['_csrf'])
          ctx.session.flashErrors({ [this.identifier]: [message] })
          ctx.response.redirect().withQs().back()
          break
        case 'json':
          ctx.response.status(error.status).send({
            errors: [
              {
                message: message,
              },
            ],
          })
          break
        case 'application/vnd.api+json':
          ctx.response.status(error.status).send({
            errors: [
              {
                code: this.identifier,
                title: message,
              },
            ],
          })
          break
      }
    },
  }

  /**
   * Self handles the auth exception and converts it to an
   * HTTP response
   */
  async handle(error: InvalidCredentialsException, ctx: HttpContext) {
    const renderer = this.renderers[this.guardDriverName]
    const message = this.getResponseMessage(error, ctx)

    if (!renderer) {
      return ctx.response.status(error.status).send(message)
    }

    return renderer(message, error, ctx)
  }
}
