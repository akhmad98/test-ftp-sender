import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({
      usernameField: 'login',
    });
  }
  async validate(login: string, password: string) {
    const user = await this.authService.getAuthenticatedUser(login, password);
    if (!user) {
      throw new HttpException(
        `Предоставлены неверные учетные данные`,
        HttpStatus.FORBIDDEN,
      );
    }
    const { id: userId, email: email } = user;
    return { userId, email };
  }
}
