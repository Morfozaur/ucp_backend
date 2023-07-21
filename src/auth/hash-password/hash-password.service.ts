import { Injectable } from '@nestjs/common';
import * as crypto from 'crypto';

@Injectable()
export class HashPasswordService {
  hash(password) {
    // console.log('PASS', password, `${process.env.PASS_SALT}`);

    return crypto
      .createHmac('sha512', `${process.env.PASS_SALT}`)
      .update(password)
      .digest('hex');
  }

  hashToken(guid) {
    return crypto
      .createHmac('sha512', `${process.env.PASS_SALT}`)
      .update(guid)
      .digest('hex');
  }

  hashEmail(id) {
    return crypto
      .createHmac('sha512', `${process.env.EMAIL_SALT}`)
      .update(id)
      .digest('hex');
  }

  hashResetEmail(userToken) {
    return crypto
      .createHmac('sha512', `${process.env.EMAIL_SALT}`)
      .update(userToken)
      .digest('hex');
  }
}
