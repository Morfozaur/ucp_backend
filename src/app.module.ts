import { forwardRef, Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { dataSourceOptions } from './typeorm.config';
@Module({
  imports: [
    UserModule,
    AuthModule,
    forwardRef(() =>
      TypeOrmModule.forRootAsync({
        imports: [ConfigModule],
        useFactory: async () => dataSourceOptions,
        inject: [ConfigService],
      }),
    ),
    forwardRef(() =>
      ConfigModule.forRoot({
        isGlobal: true,
      }),
    ),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
