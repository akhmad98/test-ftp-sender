import { Injectable, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { PrismaService } from '../prisma/prisma.service';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService, private config: ConfigService) {}
  async create(createUserDto: CreateUserDto) {
    const user = await this.prisma.user.create({
      data: {
        email: createUserDto.email,
        hash: createUserDto.hash,
        hashedRt: createUserDto.hashedRt || null,
      },
    });
    return user;
  }

  async findAll() {
    return await this.prisma.user.findMany({});
  }

  async findOne(id: number) {
    return await this.prisma.user.findUnique({
      where: {
        id: id,
      },
    });
  }

  async findOneByEmail(email: string) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: email,
      },
    });
    if (!user) {
      throw new UnauthorizedException();
    }
  }

  async update(id: number, updateUserDto: UpdateUserDto) {
    await this.prisma.user.updateMany({
      where: {
        id: id,
      },
      data: {
        hash: updateUserDto.hash,
      },
    });
    return this.prisma.user.findUnique({
      where: {
        id: id,
      },
    });
  }

  async remove(id: number) {
    await this.prisma.user.delete({
      where: {
        id: id,
      },
    });
  }
}
