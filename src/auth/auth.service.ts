import {
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { AuthDto } from './dto/auth-dto';
import { Tokens } from './interfaces/tokens.interface';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtPayload } from './types/jwtPayload.type';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private config: ConfigService,
    private jwtService: JwtService,
  ) {}

  public async getAuthenticatedUser(login: string, pass: string) {
    try {
      const user = await this.prisma.user.findUnique({
        where: {
          email: login,
        },
      });
      await this.verifyPassword(pass, user.password);
      return user;
    } catch (error) {
      throw new HttpException(
        'Предоставлены неверные учетные данные',
        HttpStatus.FORBIDDEN,
      );
    }
  }

  private async verifyPassword(pass: string, hashedPass: string) {
    const isPasswordMatching = await argon.verify(hashedPass, pass);
    if (!isPasswordMatching) {
      throw new HttpException(
        'Предоставлены неверные учетные данные',
        HttpStatus.FORBIDDEN,
      );
    }
  }
  async register(dto: AuthDto): Promise<Tokens> {
    const hash = await argon.hash(dto.password);

    const newUser = await this.prisma.user
      .create({
        data: {
          email: dto.login,
          hash,
        },
      })
      .catch((error) => {
        if (error instanceof PrismaClientKnownRequestError) {
          if (error.code === 'P2002') {
            throw new ForbiddenException('Credentials Incorrect');
          }
        }
        throw error;
      });

    const tokens = await this.generateTokens(newUser.id, newUser.email);
    await this.updateRtHash(newUser.id, tokens.refresh_token);

    return tokens;
  }

  async login(dto: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.login,
      },
    });

    if (!user) throw new ForbiddenException('Acccess Denied');
    const tokens = await this.generateTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }

  async updateRtHash(userId: number, rt: string): Promise<void> {
    const hash = await argon.hash(rt);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRt: hash,
      },
    });
  }

  async logout(userId: number) {
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashedRt: {
          not: null,
        },
      },
      data: {
        hashedRt: null,
      },
    });
    return true;
  }
  async refreshTokens(userId: number, rt: string): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });
    if (!user || !user.hashedRt) throw new ForbiddenException('Access Denied');

    const rtMatches = await argon.verify(user.hashedRt, rt);
    if (!rtMatches) throw new ForbiddenException('Access Denied');

    const tokens = await this.generateTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }

  async generateTokens(userId: number, email: string): Promise<Tokens> {
    const jwtPayload: JwtPayload = {
      sub: userId,
      email: email,
    };

    const [access_token, refresh_token] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: 'ac-toekn',
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: 'rt-token',
      }),
    ]);

    return {
      access_token: access_token,
      refresh_token: refresh_token,
    };
  }
}
