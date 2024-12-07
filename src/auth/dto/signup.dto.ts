import {
  IsEmail,
  IsNotEmpty,
  IsString,
  Matches,
  MinLength,
} from 'class-validator';

export class SignupDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsEmail()
  email: string;

  @IsString()
  @MinLength(6)
  @IsString()
  @Matches(/^(?=.*\d)/, {
    message: 'Password must contain at least one number',
  })
  password: string;
}
