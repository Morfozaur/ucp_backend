import { forwardRef, Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/user/entities/user.entity';
import { AuthModule } from 'src/auth/auth.module';
import { HashPasswordService } from "../auth/hash-password/hash-password.service";

@Module({
  controllers: [UserController],
  exports: [UserService, HashPasswordService],
  imports: [
    forwardRef(() => TypeOrmModule.forFeature([User])),
    forwardRef(() => AuthModule),
  ],
  providers: [UserService, HashPasswordService],
})
export class UserModule {}
