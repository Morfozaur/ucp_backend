import { forwardRef, Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { HashPasswordService } from 'src/auth/hash-password/hash-password.service';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { LocalStrategy } from 'src/auth/local.strategy';
import { JwtStrategy } from 'src/auth/jwt.strategy';
import { UserModule } from 'src/user/user.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/user/entities/user.entity';
import { JwtCookieStrategy } from 'src/auth/jwt-cookie.strategy';

@Module({
  controllers: [AuthController],
  exports: [HashPasswordService, JwtModule, AuthService],
  providers: [
    AuthService,
    HashPasswordService,
    LocalStrategy,
    JwtStrategy,
    JwtCookieStrategy,
  ],
  imports: [
    forwardRef(() => TypeOrmModule.forFeature([User])),
    forwardRef(() => UserModule),
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (config: ConfigService) => {
        return {
          secret: config.get('JWT_SECRET'),
          jwtTime: config.get('JWT_TIME'),
          jwtTimeRefresh: config.get('JWT_REFRESH_TIME'),
        };
      },
      inject: [ConfigService],
      // secret: `${process.env.JWT_SECRET}`,
      // signOptions: { expiresIn: '600s' },
    }),
  ],
})
export class AuthModule {}
