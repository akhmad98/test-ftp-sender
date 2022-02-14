import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth-dto';
import { Tokens } from './interfaces/tokens.interface';
import { LocalAuthGuard } from '../common/guards/local.auth.guard';
import { GetCurrentUserId } from '../common/decorators/get-current-user-id.decorator';
import { GetCurrrentUser } from '../common/decorators/get-current-user.decorator';

@Controller('auth/api')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('/signup')
  signUp(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.register(dto);
  }

  @UseGuards(LocalAuthGuard)
  @Post('/signin')
  signIn(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.login(dto);
  }

  @Post('/logout')
  logout(@GetCurrentUserId() userId: number): Promise<boolean> {
    return this.authService.logout(userId);
  }

  @Post('/refresh')
  refresh(
    @GetCurrentUserId() userId: number,
    @GetCurrrentUser('refreshToken') refreshToken: string,
  ): Promise<Tokens> {
    return this.authService.refreshTokens(userId, refreshToken);
  }
}
