import {
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Response } from 'express';
import { HashPasswordService } from 'src/auth/hash-password/hash-password.service';
import { User } from 'src/user/entities/user.entity';
import { DataSource, Repository } from 'typeorm';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { errorMessages, handleExceptions } from '../utils/errorHandlers';
import { LoginUserDto } from './dto/login-user.dto';
import { AuthService } from '../auth/auth.service';
import { ConfigService } from '@nestjs/config';
import { v4 as uuid } from 'uuid';

@Injectable()
export class UserService {
  constructor(
    private dataSource: DataSource,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @Inject(HashPasswordService)
    private readonly hashPassword: any,
    @Inject(JwtService)
    private readonly jwtService: any,
    @Inject(AuthService)
    private readonly authService: AuthService,
    @Inject(ConfigService)
    private readonly configService: ConfigService,
  ) {}

  async userExists(email: string) {
    return await this.userRepository.exist({ where: { email: email } });
  }

  async create(createUserDto: CreateUserDto, res) {
    try {
      const exists = await this.userExists(createUserDto.email);
      if (exists) {
        res.status(422).json({
          success: false,
          error: 'User with this e-mail already exists',
        });
        return;
      }
      const password = this.hashPassword.hash(createUserDto.password);
      await this.userRepository.save({
        email: createUserDto.email,
        password: password,
        username: createUserDto.username,
      });
      const loginData = {
        email: createUserDto.email,
        password: createUserDto.password,
      };
      return await this.login(loginData, res);
    } catch (error) {
      handleExceptions(error);
    }
  }

  async login(loginUser: LoginUserDto, res: Response) {
    try {
      const auth = await this.authService.validateUser(
        loginUser.email,
        loginUser.password,
      );

      if (!auth) {
        res.status(401).json({ error: true, message: 'Invalid login data' });
        return;
      }
      const csrfToken = uuid();
      const accessToken = await this.authService.signAccessToken({
        csrfToken,
        user: auth.id,
        username: auth.username,
        role: auth.role,
      });
      const jwtTime = this.configService.get<string>('JWT_TIME');
      const jwtRefreshTime = this.configService.get<string>('JWT_REFRESH_TIME');

      const data = {
        id: auth.id,
        email: auth.email,
        username: auth.username,
        exp: new Date(new Date().getTime() + parseInt(jwtTime) * 1000),
      };
      res
        .cookie('jwt', accessToken, {
          maxAge: parseInt(jwtTime) * 1000,
          secure: true,
          httpOnly: true,
          sameSite: 'none',
        })
        .cookie('refresh_jwt', auth.refreshToken, {
          maxAge: parseInt(jwtRefreshTime) * 1000,
          secure: true,
          httpOnly: true,
          sameSite: 'none',
        })
        .set({ 'x-csrf-token': csrfToken })
        .status(200)
        .json(data);
    } catch (error) {
      handleExceptions(error);
    }
  }

  async logout(cookies, res) {
    try {
      const decode = this.jwtService.verify(cookies.refresh_jwt);
      const user = await this.dataSource
        .getRepository(User)
        .createQueryBuilder('user')
        .select('user')
        .where('user.id = :id', { id: decode.user })
        .getOne();

      if (!user) {
        throw new NotFoundException(errorMessages.NO_USER);
      }

      const tokens = user?.tokens?.filter((x) => {
        return x !== cookies.refresh_jwt;
      });

      await this.userRepository.save({ ...user, tokens: tokens });
      return res
        .clearCookie('jwt', {
          secure: true,
          httpOnly: true,
          sameSite: 'none',
        })
        .clearCookie('refresh_jwt', {
          secure: true,
          httpOnly: true,
          sameSite: 'none',
        })
        .json({ logout: true, user: user.id });
    } catch (error) {
      handleExceptions(error);
    }
  }

  async autologin(cookies, res) {
    try {
      const decode = this.jwtService.verify(cookies.refresh_jwt);
      const user = await this.dataSource
        .getRepository(User)
        .createQueryBuilder('user')
        .select('user')
        .where('user.id = :id', { id: decode.user })
        .getOne();
      const csrfToken = uuid();
      const accessToken = await this.authService.signAccessToken({
        csrfToken,
        user: user.id,
        email: user.email,
        role: user.role,
      });
      const jwtTime = this.configService.get<string>('JWT_TIME');
      const jwtRefreshTime = this.configService.get<string>('JWT_REFRESH_TIME');

      const data = {
        id: user.id,
        username: user.username,
        email: user.email,
        exp: new Date(new Date().getTime() + parseInt(jwtTime) * 1000),
      };
      const currentToken = await this.authService.signRefreshToken({
        user: user.id,
        email: user.email,
        role: user.role,
      });
      const tokensList = this.authService.filterOldTokens(user.tokens);
      await this.authService.updateTokens(
        user.email,
        user.tokens ? [...tokensList, currentToken] : [currentToken],
      );
      res
        .cookie('jwt', accessToken, {
          maxAge: parseInt(jwtTime) * 1000,
          secure: true,
          httpOnly: true,
          sameSite: 'none',
        })
        .cookie('refresh_jwt', currentToken, {
          maxAge: parseInt(jwtRefreshTime) * 1000,
          secure: true,
          httpOnly: true,
          sameSite: 'none',
        })
        .set({ 'x-csrf-token': csrfToken })
        .status(200)
        .json(data);
    } catch (error) {
      handleExceptions(error);
    }
  }

  findAll() {
    return `This action returns all user`;
  }

  findOne(id: number) {
    return `This action returns a #${id} user`;
  }

  async findOneByEmail(email: string) {
    try {
      const user = await this.userRepository.findOneBy({ email: email });
      if (!user) {
        throw new UnauthorizedException(errorMessages.NO_USER);
      }
      return user;
    } catch (error) {
      handleExceptions(error);
    }
  }

  update(id: number, updateUserDto: UpdateUserDto) {
    return `This action updates a #${id} user`;
  }

  remove(id: number) {
    return `This action removes a #${id} user`;
  }
}
