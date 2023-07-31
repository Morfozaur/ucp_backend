import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
  Request,
  Req,
  Response,
  Res,
} from '@nestjs/common';
import { UserService } from './user.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { LocalAuthGuard } from 'src/auth/local-auth.guard';
import { JwtAuthGuard } from 'src/auth/jwt-auth.guard';
import {
  Request as ExpressRequest,
  Response as ExpressResponse,
} from 'express';
import { JwtCookieAuthGuard } from 'src/auth/jwt-cookie-auth.guard';
import { ApiOperation } from '@nestjs/swagger';
import { LoginUserDto } from './dto/login-user.dto';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post('/register')
  @ApiOperation({
    summary: 'Add user',
    description: 'Send mail and password to register new user',
  })
  create(@Body() createUserDto: CreateUserDto, @Res() res: ExpressResponse) {
    // return this.userService.create(createUserDto, res);
    return {route: 'POST: /user/register'}
  }

  @Post('/login')
  @ApiOperation({
    summary: 'Login',
    description: 'Send mail and password to validate user',
  })
  login(@Body() loginUser: LoginUserDto, @Res() res: ExpressResponse) {
    // return this.userService.login(loginUser, res);
    return {route: 'POST: /user/login'}
  }

  @Get('/logout')
  @UseGuards(JwtCookieAuthGuard)
  @ApiOperation({
    summary: 'Logout',
    description: 'Logout user and remove tokens',
  })
  async logout(@Req() req: ExpressRequest, @Res() res: ExpressResponse) {
    // return this.userService.logout(req.cookies, res);
    return {route: 'GET: /user/logout'}
  }

  @Get('/autologin')
  @ApiOperation({
    summary: 'Autologin',
    description: 'Use cookies to validate user',
  })
  async autologin(@Req() req: ExpressRequest, @Res() res: ExpressResponse) {
    // return this.userService.autologin(req.cookies, res);
    return {route: 'GET: /user/autologin'}
  }

  @UseGuards(JwtCookieAuthGuard)
  @Get('/test-cookie')
  testCookie(@Req() req: ExpressRequest) {
    // return { success: 'jwt works', cookies: req.cookies };
    return {route: 'GET: /user/test-cookie'}
  }

  @Get('')
  findAll() {
    return this.userService.findAll()
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.userService.findOne(+id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.userService.update(+id, updateUserDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.userService.remove(+id);
  }
}
