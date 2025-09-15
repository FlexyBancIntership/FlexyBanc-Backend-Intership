import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  // ===========================
  // Signup
  // ===========================
  @Post('signup')
  async signup(@Body() body: any) {
    // Appelle le service Auth qui crée l'utilisateur local et dans Ory Kratos
    return this.authService.signup(body);
  }

  // ===========================
  // Login
  // ===========================
  @Post('login')
  async login(@Body() body: any) {
    // Authentifie via Ory Kratos
    return this.authService.login(body.email, body.password);
  }

  // ===========================
  // Logout
  // ===========================
  @Post('logout')
  async logout(@Body('cookie') cookie: string) {
    return this.authService.logout(cookie);
  }
}
