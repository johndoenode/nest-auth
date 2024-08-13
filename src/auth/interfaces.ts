import { Token } from '@prisma/client';

export interface Tokens {
  accessToken: string;
  refreshtoken: Token;
}
