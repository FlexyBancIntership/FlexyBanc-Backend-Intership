import { Injectable, NestMiddleware } from '@nestjs/common';
import { AuthService } from './auth.service';

@Injectable()
export class AuthMiddleware implements NestMiddleware {
  constructor(private authService: AuthService) {}

  async use(req: any, res: any, next: () => void) {
    const cookie = req.headers.cookie;
    if (!cookie) return res.status(401).send('Not authenticated');

    try {
      const sessionData = await this.authService.validateSession(cookie);
      if (sessionData.valid) {
        if (sessionData.source === 'kratos' && sessionData.session) {
          req.user = sessionData.session.identity; // Attach Kratos identity
        } else if (sessionData.source === 'local' && sessionData.user) {
          req.user = sessionData.user; // Attach local user
        } else {
          throw new Error('Invalid session data');
        }
        next();
      } else {
        res.status(401).send('Not authenticated');
      }
    } catch (err) {
      console.error(err);
      res.status(401).send('Not authenticated');
    }
  }
}
