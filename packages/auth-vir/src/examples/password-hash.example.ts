import {hashPassword} from '../index.js';

/** When a user creates or resets their password, hash it before storing it in your database. */

const hashedPassword = await hashPassword('user input password');
/** Store `hashedPassword` in your database. */
