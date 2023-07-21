import { forwardRef, Inject, Injectable } from "@nestjs/common";
import { HashPasswordService } from 'src/auth/hash-password/hash-password.service';
import { UserService } from 'src/user/user.service';
import * as jwt from 'jsonwebtoken';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { handleExceptions } from '../utils/errorHandlers';
import { User } from '../user/entities/user.entity';
import { DataSource } from 'typeorm';

@Injectable()
export class AuthService {
  constructor(
    private dataSource: DataSource,
    @Inject(forwardRef(() => UserService))
    private userService: UserService,
    @Inject(HashPasswordService)
    private hashService: HashPasswordService,
    @Inject(ConfigService)
    private readonly configService: ConfigService,
    @Inject(JwtService)
    private jwtService: JwtService,
  ) {}

  async validateUser(email: string, pass: string): Promise<any> {
    const user = await this.userService.findOneByEmail(email);
    const password = this.hashService.hash(pass);

    if (user && user.password === password) {
      const currentToken = await this.signRefreshToken({
        user: user.id,
        email: user.email,
        role: user.role,
      });
      const tokensList =
        user?.tokens?.length > 0 ? this.filterOldTokens(user?.tokens) : [];
      await this.updateTokens(
        email,
        user.tokens ? [...tokensList, currentToken] : [currentToken],
      );
      return {
        id: user.id,
        role: user.role,
        refreshToken: currentToken,
        email: user.email,
        username: user.username,
      };
    }
    return null;
  }

  filterOldTokens(tokens: string[]) {
    const filteredTokens = [];
    const now = Date.now();
    tokens.forEach((t) => {
      const token: any = jwt.decode(t);
      if (token?.exp * 1000 > now) {
        filteredTokens.push(t);
      }
    });
    return filteredTokens;
  }

  async updateTokens(email: string, tokens: string[]) {
    try {
      await this.dataSource
        .createQueryBuilder()
        .update(User)
        .set({
          tokens: tokens,
        })
        .where('email = :email', { email: email })
        .execute();
    } catch (error) {
      handleExceptions(error);
    }
  }

  async signAccessToken(payload: any) {
    const jwtTime = this.configService.get<string>('JWT_TIME');
    return this.jwtService.sign(payload, {
      expiresIn: parseInt(jwtTime),
    });
  }

  async signRefreshToken(payload: any) {
    const jwtRefreshTime = this.configService.get<string>('JWT_REFRESH_TIME');
    return this.jwtService.sign(payload, {
      expiresIn: parseInt(jwtRefreshTime),
    });
  }
}
