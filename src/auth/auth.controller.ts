import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpStatus,
  Post,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { LoginDto, RegisterDto } from './dto';
import { AuthService } from './auth.service';
import { Tokens } from './interfaces';
import { Response } from 'express';
import { ConfigService } from '@nestjs/config';

const REFRESH_TOKEN = 'refreshtoken';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
  ) {}
  @Post('register')
  async register(@Body() dto: RegisterDto) {
    const user = await this.authService.register(dto);
    if (!user) {
      throw new BadRequestException(`CANT REG USER ${JSON.stringify(dto)}`);
    }
  }

  @Post('login')
  async login(@Body() dto: LoginDto, @Res() res: Response) {
    const tokens = await this.authService.login(dto);
    if (!tokens) {
      throw new BadRequestException(`LOGIN ERROR`);
    }
    this.setRefreshTokenToCookies(tokens, res);
    return { accessToken: tokens.accessToken };
  }

  @Get('refresh')
  refreshToken() {}

  private setRefreshTokenToCookies(tokens: Tokens, res: Response) {
    if (!tokens) {
      throw new UnauthorizedException('TOKEN OOOPS');
    }
    res.cookie(REFRESH_TOKEN, tokens.refreshtoken.token, {
      httpOnly: true,
      sameSite: 'lax',
      expires: new Date(tokens.refreshtoken.exp),
      secure: false,
      path: '/',
    });
    res.status(HttpStatus.CREATED).json(tokens);
  }
}
