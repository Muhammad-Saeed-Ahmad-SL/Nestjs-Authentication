import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getHello(req) {
    return { message: 'Hello World!', userId: req.userId };
  }
}
