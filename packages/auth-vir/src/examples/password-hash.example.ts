import {hashPassword} from '../index.js';

/** When a user creates or resets their password, hash it before storing it in your database. */

const hashedPassword = await hashPassword('user input password');

if (!hashedPassword) {
    /** This happens if the user password is too long for the bcrypt algorithm. */
    throw new Error('Password too long.');
}
/** Now store `hashedPassword` in your database. */
