/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * Guard user represents a user independent of the storage
 * provider. It contains a standard set of properties
 * used by authentication guards to interact with
 * a user.
 *
 * Think of it as a bridge between a user and the authentication
 * guard.
 */
export abstract class GuardUser<RealUser> {
  protected realUser: RealUser
  constructor(realUser: RealUser) {
    this.realUser = realUser
  }

  /**
   * Verifies the plain text password against the user password
   * hash
   */
  abstract verifyPassword(plainTextPassword: string): Promise<boolean>

  /**
   * Returns a value to uniquely identify the user.
   */
  abstract getId(): number | string

  /**
   * Returns the original provider specific user object.
   */
  getOriginal(): RealUser {
    return this.realUser
  }
}
