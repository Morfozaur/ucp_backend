import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Inject, Injectable } from '@nestjs/common';
import { UserService } from '../user/user.service';
import { DataSource, Repository } from 'typeorm';
import dataSource from 'src/typeorm.config';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/user/entities/user.entity';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    // @Inject(UserService) private readonly userService: UserService,
    @InjectRepository(User) private readonly userRepository : Repository<User>,
    private dataSource: DataSource
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET,
    });
  }


  async validate(payload: any) {

    try {

      const user = await this.userRepository.findOneBy({username: payload.username})

      return { ...user, password: '', tokens: null }
      
    } catch (error) {
      throw new Error(error)
    }
  }
}