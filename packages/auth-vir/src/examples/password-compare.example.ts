import {doesPasswordMatchHash} from '../index.js';

if (
    !(await doesPasswordMatchHash({
        hash: 'hash from database',
        password: 'user input password for login',
    }))
) {
    throw new Error('Login failure.');
}
