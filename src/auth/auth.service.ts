import { Injectable } from '@nestjs/common';
import { SignupDto } from './dto/signup.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schema';
import { Model } from 'mongoose';

@Injectable()
export class AuthService {
  constructor(@InjectModel(User.name) private userModel: Model<User>) {}
  async signup(signUpDto: SignupDto) {
    // TODO: check if email is in use
    // TODO: Hash password
    // TODO: Create user document and save in mongodb
  }
}
