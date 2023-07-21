import {
  BadRequestException,
  ConflictException,
  HttpException,
  HttpStatus,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';

const exceptions = [
  UnauthorizedException,
  NotFoundException,
  ConflictException,
  BadRequestException,
];

export const handleExceptions = (error: any) => {
  if (exceptions.some((e) => error instanceof e)) {
    throw error;
  } else {
    throw new HttpException(
      error.message,
      error.status || HttpStatus.BAD_REQUEST,
    );
  }
};

export const errorMessages = {
  NO_USER: 'User does not exists',
  NO_CSRF: 'CSRF token required',
  INVALID_CSRF: 'Bad CSRF token',
  UNAUTHORIZED: 'Access denied',
};
