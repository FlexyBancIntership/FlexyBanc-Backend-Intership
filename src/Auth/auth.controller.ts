import {
  Controller,
  Post,
  Get,
  Put,
  Delete,
  Body,
  Param,
  Headers,
  HttpException,
  HttpStatus,
  BadRequestException,
  UnauthorizedException,
  Query,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import {
  SignupDto,
  LoginDto,
  SubmitVerificationDto,
  RecoveryDto,
  SubmitRecoveryDto,
} from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  // ===========================
  // REGISTRATION & LOGIN
  // ===========================

  @Post('register')
  async signup(@Body() body: SignupDto) {
    try {
      const result = await this.authService.signup(body);
      return {
        status: 'success',
        message: result.message || 'Registration successful',
        data: {
          user: result.user,
          kratosIdentity: result.kratosIdentity,
          hasKratosAccount: result.hasKratosAccount,
        },
      };
    } catch (err) {
      if (err instanceof BadRequestException) {
        throw new HttpException(
          {
            status: 'error',
            statusCode: HttpStatus.BAD_REQUEST,
            message: err.message,
          },
          HttpStatus.BAD_REQUEST,
        );
      }
      console.error('Signup error:', err);
      throw new HttpException(
        {
          status: 'error',
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: err.message || 'Internal server error',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Post('login')
  async login(@Body() body: LoginDto) {
    try {
      const result = await this.authService.login(body);
      return {
        status: 'success',
        message: result.message || 'Login successful',
        data: {
          user: result.user,
          session: result.session,
          sessionToken: result.sessionToken,
          method: result.method,
        },
      };
    } catch (err) {
      if (
        err instanceof BadRequestException ||
        err instanceof UnauthorizedException
      ) {
        throw new HttpException(
          {
            status: 'error',
            statusCode:
              err instanceof UnauthorizedException
                ? HttpStatus.UNAUTHORIZED
                : HttpStatus.BAD_REQUEST,
            message: err.message,
          },
          err instanceof UnauthorizedException
            ? HttpStatus.UNAUTHORIZED
            : HttpStatus.BAD_REQUEST,
        );
      }
      console.error('Login error:', err);
      throw new HttpException(
        {
          status: 'error',
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: err.message || 'Internal server error',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Post('logout')
  async logout(@Headers('authorization') sessionToken: string) {
    try {
      const token = sessionToken?.startsWith('Bearer ')
        ? sessionToken.replace('Bearer ', '')
        : sessionToken;

      const result = await this.authService.logout(token);
      return {
        status: 'success',
        message: result.message || 'Logout successful',
        data: {},
      };
    } catch (err) {
      console.error('Logout error:', err);
      throw new HttpException(
        {
          status: 'error',
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: err.message || 'Logout failed',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  // ===========================
  // EMAIL VERIFICATION
  // ===========================

  @Post('initiate-verification')
  async initiateVerification() {
    try {
      const flow = await this.authService.initVerificationFlow(
        'http://localhost:4455/verification',
      );
      return {
        status: 'success',
        message: 'Verification flow initialized',
        data: {
          flowId: flow.id,
          verificationData: flow,
        },
      };
    } catch (err) {
      if (err instanceof BadRequestException) {
        throw new HttpException(
          {
            status: 'error',
            statusCode: HttpStatus.BAD_REQUEST,
            message: err.message,
          },
          HttpStatus.BAD_REQUEST,
        );
      }
      console.error('Verification initiation error:', err);
      throw new HttpException(
        {
          status: 'error',
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: err.message || 'Internal server error',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Post('submit-verification')
  async submitVerification(@Body() body: SubmitVerificationDto) {
    try {
      const result = await this.authService.submitVerification(body);
      return {
        status: 'success',
        message: result.message || 'Email verified successfully',
        data: {
          verificationData: result.data,
        },
      };
    } catch (err) {
      if (err instanceof BadRequestException) {
        throw new HttpException(
          {
            status: 'error',
            statusCode: HttpStatus.BAD_REQUEST,
            message: err.message,
          },
          HttpStatus.BAD_REQUEST,
        );
      }
      console.error('Verification submission error:', err);
      throw new HttpException(
        {
          status: 'error',
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: err.message || 'Internal server error',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  // ===========================
  // PASSWORD RECOVERY
  // ===========================

  @Post('initiate-recovery')
  async initiateRecovery(@Body() body: RecoveryDto) {
    try {
      const result = await this.authService.initiateRecovery(body);
      return {
        status: 'success',
        message: result.message || 'Recovery email sent successfully',
        data: {
          flowId: result.flowId,
          recoveryData: result.data,
        },
      };
    } catch (err) {
      if (err instanceof BadRequestException) {
        throw new HttpException(
          {
            status: 'error',
            statusCode: HttpStatus.BAD_REQUEST,
            message: err.message,
          },
          HttpStatus.BAD_REQUEST,
        );
      }
      console.error('Recovery initiation error:', err);
      throw new HttpException(
        {
          status: 'error',
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: err.message || 'Internal server error',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Post('submit-recovery')
  async submitRecovery(@Body() body: SubmitRecoveryDto) {
    try {
      const result = await this.authService.submitRecovery(body);
      return {
        status: 'success',
        message: result.message || 'Account recovery successful',
        data: {
          recoveryData: result.data,
        },
      };
    } catch (err) {
      if (err instanceof BadRequestException) {
        throw new HttpException(
          {
            status: 'error',
            statusCode: HttpStatus.BAD_REQUEST,
            message: err.message,
          },
          HttpStatus.BAD_REQUEST,
        );
      }
      console.error('Recovery submission error:', err);
      throw new HttpException(
        {
          status: 'error',
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: err.message || 'Internal server error',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  // ===========================
  // SESSION MANAGEMENT
  // ===========================

  @Get('session/validate')
  async validateSession(@Headers('authorization') sessionToken: string) {
    try {
      if (!sessionToken) {
        throw new UnauthorizedException('Session token is required');
      }

      const token = sessionToken.startsWith('Bearer ')
        ? sessionToken.replace('Bearer ', '')
        : sessionToken;

      const session = await this.authService.validateSession(token);
      return {
        status: 'success',
        message: 'Session is valid',
        data: {
          session,
        },
      };
    } catch (err) {
      if (err instanceof UnauthorizedException) {
        throw new HttpException(
          {
            status: 'error',
            statusCode: HttpStatus.UNAUTHORIZED,
            message: err.message,
          },
          HttpStatus.UNAUTHORIZED,
        );
      }
      console.error('Session validation error:', err);
      throw new HttpException(
        {
          status: 'error',
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: 'Session validation failed',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('session')
  async getSession(@Headers('cookie') cookie: string) {
    try {
      if (!cookie) {
        throw new UnauthorizedException('Cookie is required');
      }

      const session = await this.authService.getSession(cookie);
      return {
        status: 'success',
        message: 'Session retrieved successfully',
        data: {
          session,
        },
      };
    } catch (err) {
      if (err instanceof UnauthorizedException) {
        throw new HttpException(
          {
            status: 'error',
            statusCode: HttpStatus.UNAUTHORIZED,
            message: err.message,
          },
          HttpStatus.UNAUTHORIZED,
        );
      }
      console.error('Get session error:', err);
      throw new HttpException(
        {
          status: 'error',
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: 'Failed to retrieve session',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  // ===========================
  // USER PROFILE MANAGEMENT
  // ===========================

  @Get('profile')
  async getUserProfile(@Headers('authorization') sessionToken: string) {
    try {
      if (!sessionToken) {
        throw new UnauthorizedException('Session token is required');
      }

      const token = sessionToken.startsWith('Bearer ')
        ? sessionToken.replace('Bearer ', '')
        : sessionToken;

      const session = await this.authService.validateSession(token);
      const user = await this.authService.getUserProfile(session);

      if (!user) {
        throw new BadRequestException('User not found');
      }

      return {
        status: 'success',
        message: 'Profile retrieved successfully',
        data: {
          user,
        },
      };
    } catch (err) {
      if (
        err instanceof UnauthorizedException ||
        err instanceof BadRequestException
      ) {
        throw new HttpException(
          {
            status: 'error',
            statusCode:
              err instanceof UnauthorizedException
                ? HttpStatus.UNAUTHORIZED
                : HttpStatus.BAD_REQUEST,
            message: err.message,
          },
          err instanceof UnauthorizedException
            ? HttpStatus.UNAUTHORIZED
            : HttpStatus.BAD_REQUEST,
        );
      }
      console.error('Get profile error:', err);
      throw new HttpException(
        {
          status: 'error',
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: 'Failed to retrieve profile',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Put('profile/:userId')
  async updateProfile(
    @Param('userId') userId: number,
    @Body() updateData: Partial<SignupDto>,
    @Headers('authorization') sessionToken: string,
  ) {
    try {
      if (!sessionToken) {
        throw new UnauthorizedException('Session token is required');
      }

      const token = sessionToken.startsWith('Bearer ')
        ? sessionToken.replace('Bearer ', '')
        : sessionToken;

      await this.authService.validateSession(token);

      const updatedUser = await this.authService.updateProfile(
        userId,
        updateData,
      );
      return {
        status: 'success',
        message: 'Profile updated successfully',
        data: {
          user: updatedUser,
        },
      };
    } catch (err) {
      if (
        err instanceof UnauthorizedException ||
        err instanceof BadRequestException
      ) {
        throw new HttpException(
          {
            status: 'error',
            statusCode:
              err instanceof UnauthorizedException
                ? HttpStatus.UNAUTHORIZED
                : HttpStatus.BAD_REQUEST,
            message: err.message,
          },
          err instanceof UnauthorizedException
            ? HttpStatus.UNAUTHORIZED
            : HttpStatus.BAD_REQUEST,
        );
      }
      console.error('Update profile error:', err);
      throw new HttpException(
        {
          status: 'error',
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: 'Failed to update profile',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Delete('profile/:userId')
  async deleteUser(
    @Param('userId') userId: number,
    @Headers('authorization') sessionToken: string,
  ) {
    try {
      if (!sessionToken) {
        throw new UnauthorizedException('Session token is required');
      }

      const token = sessionToken.startsWith('Bearer ')
        ? sessionToken.replace('Bearer ', '')
        : sessionToken;

      await this.authService.validateSession(token);

      await this.authService.deleteUser(userId);
      return {
        status: 'success',
        message: 'User deleted successfully',
        data: {},
      };
    } catch (err) {
      if (
        err instanceof UnauthorizedException ||
        err instanceof BadRequestException
      ) {
        throw new HttpException(
          {
            status: 'error',
            statusCode:
              err instanceof UnauthorizedException
                ? HttpStatus.UNAUTHORIZED
                : HttpStatus.BAD_REQUEST,
            message: err.message,
          },
          err instanceof UnauthorizedException
            ? HttpStatus.UNAUTHORIZED
            : HttpStatus.BAD_REQUEST,
        );
      }
      console.error('Delete user error:', err);
      throw new HttpException(
        {
          status: 'error',
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: 'Failed to delete user',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  // ===========================
  // FLOW INITIALIZATION ROUTES
  // ===========================

  @Get('flows/registration')
  async initRegistrationFlow(@Query('return_to') returnTo?: string) {
    try {
      const flow = await this.authService.initRegistrationFlow(returnTo);
      return {
        status: 'success',
        message: 'Registration flow initialized',
        data: {
          flow,
        },
      };
    } catch (err) {
      console.error('Registration flow init error:', err);
      throw new HttpException(
        {
          status: 'error',
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: 'Failed to initialize registration flow',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('flows/login')
  async initLoginFlow(@Query('return_to') returnTo?: string) {
    try {
      const flow = await this.authService.initLoginFlow(returnTo);
      return {
        status: 'success',
        message: 'Login flow initialized',
        data: {
          flow,
        },
      };
    } catch (err) {
      console.error('Login flow init error:', err);
      throw new HttpException(
        {
          status: 'error',
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: 'Failed to initialize login flow',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('flows/verification')
  async initVerificationFlow(@Query('return_to') returnTo?: string) {
    try {
      const flow = await this.authService.initVerificationFlow(returnTo);
      return {
        status: 'success',
        message: 'Verification flow initialized',
        data: {
          flow,
        },
      };
    } catch (err) {
      console.error('Verification flow init error:', err);
      throw new HttpException(
        {
          status: 'error',
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: 'Failed to initialize verification flow',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('flows/recovery')
  async initRecoveryFlow(@Query('return_to') returnTo?: string) {
    try {
      const flow = await this.authService.initRecoveryFlow(returnTo);
      return {
        status: 'success',
        message: 'Recovery flow initialized',
        data: {
          flow,
        },
      };
    } catch (err) {
      console.error('Recovery flow init error:', err);
      throw new HttpException(
        {
          status: 'error',
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: 'Failed to initialize recovery flow',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  // ===========================
  // KRATOS IDENTITY MANAGEMENT
  // ===========================

  @Get('kratos/identity/:identityId')
  async getKratosIdentity(
    @Param('identityId') identityId: string,
    @Headers('authorization') sessionToken: string,
  ) {
    try {
      if (!sessionToken) {
        throw new UnauthorizedException('Session token is required');
      }

      const identity = await this.authService.getKratosIdentity(identityId);
      return {
        status: 'success',
        message: 'Kratos identity retrieved',
        data: {
          identity,
        },
      };
    } catch (err) {
      if (
        err instanceof UnauthorizedException ||
        err instanceof BadRequestException
      ) {
        throw new HttpException(
          {
            status: 'error',
            statusCode:
              err instanceof UnauthorizedException
                ? HttpStatus.UNAUTHORIZED
                : HttpStatus.BAD_REQUEST,
            message: err.message,
          },
          err instanceof UnauthorizedException
            ? HttpStatus.UNAUTHORIZED
            : HttpStatus.BAD_REQUEST,
        );
      }
      console.error('Get Kratos identity error:', err);
      throw new HttpException(
        {
          status: 'error',
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: 'Failed to retrieve identity',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Put('kratos/identity/:identityId')
  async updateKratosIdentity(
    @Param('identityId') identityId: string,
    @Body() traits: any,
    @Headers('authorization') sessionToken: string,
  ) {
    try {
      if (!sessionToken) {
        throw new UnauthorizedException('Session token is required');
      }

      const identity = await this.authService.updateKratosIdentity(
        identityId,
        traits,
      );
      return {
        status: 'success',
        message: 'Kratos identity updated',
        data: {
          identity,
        },
      };
    } catch (err) {
      if (
        err instanceof UnauthorizedException ||
        err instanceof BadRequestException
      ) {
        throw new HttpException(
          {
            status: 'error',
            statusCode:
              err instanceof UnauthorizedException
                ? HttpStatus.UNAUTHORIZED
                : HttpStatus.BAD_REQUEST,
            message: err.message,
          },
          err instanceof UnauthorizedException
            ? HttpStatus.UNAUTHORIZED
            : HttpStatus.BAD_REQUEST,
        );
      }
      console.error('Update Kratos identity error:', err);
      throw new HttpException(
        {
          status: 'error',
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: 'Failed to update identity',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Delete('kratos/identity/:identityId')
  async deleteKratosIdentity(
    @Param('identityId') identityId: string,
    @Headers('authorization') sessionToken: string,
  ) {
    try {
      if (!sessionToken) {
        throw new UnauthorizedException('Session token is required');
      }

      await this.authService.deleteKratosIdentity(identityId);
      return {
        status: 'success',
        message: 'Kratos identity deleted',
        data: {},
      };
    } catch (err) {
      if (
        err instanceof UnauthorizedException ||
        err instanceof BadRequestException
      ) {
        throw new HttpException(
          {
            status: 'error',
            statusCode:
              err instanceof UnauthorizedException
                ? HttpStatus.UNAUTHORIZED
                : HttpStatus.BAD_REQUEST,
            message: err.message,
          },
          err instanceof UnauthorizedException
            ? HttpStatus.UNAUTHORIZED
            : HttpStatus.BAD_REQUEST,
        );
      }
      console.error('Delete Kratos identity error:', err);
      throw new HttpException(
        {
          status: 'error',
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: 'Failed to delete identity',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  // ===========================
  // SYSTEM STATUS
  // ===========================

  @Get('status')
  async getAuthStats() {
    try {
      const stats = await this.authService.getAuthStats();
      return {
        status: 'success',
        message: 'Auth statistics retrieved',
        data: stats,
      };
    } catch (err) {
      console.error('Get auth stats error:', err);
      throw new HttpException(
        {
          status: 'error',
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: 'Failed to retrieve statistics',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('health')
  async healthCheck() {
    try {
      const kratosAvailable = await this.authService.isKratosAvailable();
      return {
        status: 'success',
        message: 'Health check completed',
        data: {
          service: 'auth',
          healthy: true,
          kratos: {
            available: kratosAvailable,
            status: kratosAvailable ? 'healthy' : 'unavailable',
          },
          timestamp: new Date().toISOString(),
        },
      };
    } catch (err) {
      console.error('Health check error:', err);
      throw new HttpException(
        {
          status: 'error',
          statusCode: HttpStatus.SERVICE_UNAVAILABLE,
          message: 'Service unhealthy',
        },
        HttpStatus.SERVICE_UNAVAILABLE,
      );
    }
  }
  // ===========================
  // KRATOS WEBHOOK
  // ===========================

  @Post('sync/user/:email')
  async syncUserByEmail(
    @Param('email') email: string,
    @Headers('authorization') sessionToken: string,
  ) {
    try {
      if (!sessionToken) {
        throw new UnauthorizedException('Session token is required');
      }

      const user = await this.authService.syncUserByEmail(email);
      return {
        status: 'success',
        message: 'User synchronized successfully',
        data: { user },
      };
    } catch (err) {
      if (
        err instanceof UnauthorizedException ||
        err instanceof BadRequestException
      ) {
        throw new HttpException(
          {
            status: 'error',
            statusCode:
              err instanceof UnauthorizedException
                ? HttpStatus.UNAUTHORIZED
                : HttpStatus.BAD_REQUEST,
            message: err.message,
          },
          err instanceof UnauthorizedException
            ? HttpStatus.UNAUTHORIZED
            : HttpStatus.BAD_REQUEST,
        );
      }
      console.error('Sync user error:', err);
      throw new HttpException(
        {
          status: 'error',
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: 'Failed to sync user',
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}
