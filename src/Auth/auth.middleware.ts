import { Injectable, NestMiddleware } from '@nestjs/common';
import { AuthService } from './auth.service';

@Injectable()
export class AuthMiddleware implements NestMiddleware {
  constructor(private authService: AuthService) {}

  async use(req: any, res: any, next: () => void) {
    const cookie = req.headers.cookie;
    if (!cookie) return res.status(401).send('Not authenticated');

    try {
      const session = await this.authService.getSession(cookie);
      req.user = session.identity; // attach Kratos identity to request
      next();
    } catch (err) {
      console.error(err); // now it's used
      res.status(401).send('Not authenticated');
    }
  }
}
