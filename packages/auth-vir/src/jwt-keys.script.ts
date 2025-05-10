import {stringifyWithJson5} from '@augment-vir/common';
import {generateNewJwtKeys} from './jwt-keys.js';

console.info(stringifyWithJson5(await generateNewJwtKeys()));
