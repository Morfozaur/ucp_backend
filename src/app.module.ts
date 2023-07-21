import { forwardRef, Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import { User } from 'src/user/entities/user.entity';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
@Module({
  imports: [
    UserModule,
    AuthModule,
    forwardRef(() =>
      TypeOrmModule.forRootAsync({
        imports: [ConfigModule],
        useFactory: async (configService: ConfigService) => ({
          type: 'mysql',
          host: 'localhost',
          port: 3306,
          username: configService.get('MYSQL_USER'),
          password: configService.get('MYSQL_PASS'),
          database: configService.get('MYSQL_DB'),
          logging: false,
          entities: [User],
          migrationsTableName: 'migrations',
          migrations: ['dist/migration/*.js'],
          subscribers: [],
        }),
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
