import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';

import * as bycrypt from 'bcrypt';
import { envs } from 'src/config';

import { LoginUserDto, RegisterUserDto } from 'src/dto';
import { JwtPayload } from 'src/interface/jwt-payload.interface';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');

  constructor(private readonly jwtService: JwtService) {
    super();
  }

  async signJwt(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  async verifyToken(token: string) {
    try {
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });

      return {
        user: user,
        token: await this.signJwt(user),
      };
    } catch (error) {
      throw new RpcException({
        status: 401,
        message: 'Invalid token',
      });
    }
  }

  onModuleInit() {
    this.$connect();
    this.logger.log('MongoDB connected');
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    const { email, name, password } = registerUserDto;

    try {
      const user = await this.user.findUnique({
        where: {
          email: email,
        },
      });
      if (user) {
        throw new RpcException({
          status: 400,
          message: 'User already exists',
        });
      }
      const newUser = await this.user.create({
        data: {
          email: email,
          name: name,
          password: bycrypt.hashSync(password, 10),
        },
      });

      const { password: __, ...rest } = newUser;

      return {
        user: rest,
        token: await this.signJwt(rest),
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;

    try {
      const user = await this.user.findUnique({
        where: { email },
      });

      if (!user) {
        throw new RpcException({
          status: 400,
          message: 'User or password is incorrect',
        });
      }

      const validPassword = bycrypt.compareSync(password, user.password);

      if (!validPassword) {
        throw new RpcException({
          status: 400,
          message: 'User or password is incorrect',
        });
      }

      const { password: __, ...rest } = user;

      return {
        user: rest,
        token: await this.signJwt(rest),
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }
}
