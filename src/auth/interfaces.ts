import { Token } from '@prisma/client';

export interface Tokens {
  accessToken: string;
  refreshtoken: Token;
}

export interface JwtPayload {
  id: string;
  email: string;
  roles: string[];
}
