import { Strategy, ExtractJwt } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { UserService } from '../user/user.service';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/user/entities/user.entity';
import * as jwt from 'jsonwebtoken';
import { ConfigService } from '@nestjs/config';
import { errorMessages, handleExceptions } from '../utils/errorHandlers';
import { AuthService } from './auth.service';

@Injectable()
export class JwtCookieStrategy extends PassportStrategy(
  Strategy,
  'jwt-cookie',
) {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @Inject(ConfigService)
    private readonly configService: ConfigService,
    @Inject(UserService)
    private readonly userService: UserService,
    @Inject(AuthService)
    private readonly authService: AuthService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req) => req?.cookies?.jwt,
        (req) => req?.cookies?.refresh_jwt,
      ]),
      ignoreExpiration: true,
      secretOrKey: process.env.JWT_SECRET,
      passReqToCallback: true,
    });
  }

  async validate(req, payload: any) {
    try {
      const now = Date.now();
      const refreshToken = req?.cookies?.refresh_jwt;
      const refreshDecoded: any = refreshToken ? jwt.decode(refreshToken) : null;

      // Get csrfToken from cookie and header
      const accessToken = req?.cookies?.jwt;
      const accessDecoded: any = accessToken ? jwt.decode(accessToken) : null;
      const csrfToken = accessDecoded?.csrfToken;
      const headerCSRFToken = req?.headers?.['x-csrf-token'];

      const accessExpired = now > payload.exp * 1000;
      const refreshExpired = now > refreshDecoded.exp * 1000;

      if (!headerCSRFToken) {
        req.res.status(401);
        throw new UnauthorizedException(errorMessages.NO_CSRF);
      }
      console.log('req?.cookies', req?.cookies);
      console.log('refreshToken', refreshDecoded);
      console.log('csrfToken', csrfToken);
      console.log('headerCSRFToken', headerCSRFToken);
      if (csrfToken !== headerCSRFToken) {
        req.res.status(401);
        throw new UnauthorizedException(errorMessages.INVALID_CSRF);
      }

      const user = await this.userRepository.findOneBy({
        id: refreshDecoded.user,
      });

      // Get access cookies expired time
      const jwtTime = this.configService.get<string>('JWT_TIME');
      const jwtAge = parseInt(jwtTime);

      // Get refresh cookies expired time
      const jwtRefreshTime = this.configService.get<string>('JWT_REFRESH_TIME');
      const refreshAge = parseInt(jwtRefreshTime);

      const createNewRefresh = refreshDecoded.exp - now / 1000 < jwtAge;
      const refreshExists = user?.tokens?.includes(refreshToken);

      // If access token and refresh token expired
      if ((accessExpired && refreshExpired) || !refreshExists) {
        req.res.clearCookie('jwt');
        req.res.clearCookie('refresh_jwt');
        req.res.status(401);
        throw new UnauthorizedException(errorMessages.UNAUTHORIZED);
      }

      // If access token expired, but refresh is still valid
      if (accessExpired) {
        const newToken = await this.authService.signAccessToken({
          user: user.id,
          email: user.email,
          role: user.role,
        });
        req.res.cookie('jwt', newToken, {
          maxAge: jwtAge * 1000,
          secure: true,
          httpOnly: true,
          sameSite: 'none',
        });
      }

      // If refresh token is near to expiring
      if (createNewRefresh) {
        const newRefresh = await this.authService.signRefreshToken({
          user: user.id,
          email: user.email,
          role: user.role,
        });
        const filteredTokens = user?.tokens?.filter((x) => {
          return x !== refreshToken;
        });
        await this.authService.updateTokens(user.email, [
          ...filteredTokens,
          newRefresh,
        ]);
        req.res.cookie('refresh_jwt', newRefresh, {
          maxAge: refreshAge * 1000,
          secure: true,
          httpOnly: true,
          sameSite: 'none',
        });
      }
      return {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
      };
    } catch (error) {
      handleExceptions(error);
    }
  }
}
