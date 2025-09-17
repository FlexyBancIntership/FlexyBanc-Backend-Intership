import {
  Controller,
  Post,
  Body,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Logger,
  BadRequestException,
  UseInterceptors,
  ClassSerializerInterceptor,
} from '@nestjs/common';
import {
  AuthService,
  SignupDto,
  LoginDto,
  SubmitVerificationDto,
  RecoveryDto,
  SubmitRecoveryDto,
  KratosWebhookData,
} from './auth.service';

@Controller('auth')
@UseInterceptors(ClassSerializerInterceptor)
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(private readonly authService: AuthService) {}

  // ===========================
  // ENDPOINTS D'AUTHENTIFICATION
  // ===========================

  /**
   * Endpoint d'inscription
   */
  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  async signup(@Body() signupDto: SignupDto) {
    try {
      this.logger.log(`Signup request for email: ${signupDto.email}`);

      // Validation basique
      if (!signupDto.email || !signupDto.password) {
        throw new BadRequestException('Email and password are required');
      }

      if (!signupDto.firstName || !signupDto.lastName) {
        throw new BadRequestException('First name and last name are required');
      }

      const result = await this.authService.signup(signupDto);

      this.logger.log(`Signup successful for: ${signupDto.email}`);
      return {
        success: true,
        message: result.message,
        data: {
          user: {
            id: result.user.id,
            email: result.user.email,
            firstName: result.user.firstName,
            lastName: result.user.lastName,
            pack: result.user.pack,
            emailVerified: result.user.emailVerified,
            createdAt: result.user.createdAt,
          },
          kratosIdentity: result.kratosIdentity,
          hasKratosAccount: result.hasKratosAccount,
          method: result.method,
        },
      };
    } catch (error) {
      this.logger.error(`Signup failed for ${signupDto.email}:`, error.message);
      throw error;
    }
  }

  /**
   * Endpoint de connexion
   */
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() loginDto: LoginDto) {
    try {
      this.logger.log(`Login request for email: ${loginDto.email}`);

      const result = await this.authService.login(loginDto);

      this.logger.log(
        `Login successful for: ${loginDto.email} via ${result.method}`,
      );
      return {
        success: true,
        message: result.message,
        data: {
          user: {
            id: result.user.id,
            email: result.user.email,
            firstName: result.user.firstName,
            lastName: result.user.lastName,
            pack: result.user.pack,
            emailVerified: result.user.emailVerified,
            lastLogin: result.user.lastLogin,
          },
          sessionToken: result.sessionToken,
          method: result.method,
          kratosAvailable: result.kratosAvailable,
        },
      };
    } catch (error) {
      this.logger.error(`Login failed for ${loginDto.email}:`, error.message);
      throw error;
    }
  }

  /**
   * Endpoint de déconnexion
   */
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(@Headers('authorization') authHeader?: string) {
    try {
      const sessionToken = authHeader?.replace('Bearer ', '');
      const result = await this.authService.logout(sessionToken);

      return {
        success: true,
        message: result.message,
      };
    } catch (error) {
      this.logger.error('Logout failed:', error.message);
      return {
        success: true,
        message: 'Logout completed (with warnings)',
        warning: error.message,
      };
    }
  }

  // ===========================
  // VERIFICATION ET RECOVERY
  // ===========================

  /**
   * Initier un flow de vérification
   */
  @Post('verification/init')
  @HttpCode(HttpStatus.OK)
  async initVerification() {
    try {
      const flow = await this.authService.initVerificationFlow();

      return {
        success: true,
        message: 'Verification flow initialized',
        data: {
          flowId: flow.id,
          ui: flow.ui,
        },
      };
    } catch (error) {
      this.logger.error('Verification init failed:', error.message);
      throw error;
    }
  }

  /**
   * Soumettre le code de vérification
   */
  @Post('verification/submit')
  @HttpCode(HttpStatus.OK)
  async submitVerification(@Body() submitDto: SubmitVerificationDto) {
    try {
      const result = await this.authService.submitVerification(submitDto);

      return {
        success: true,
        message: result.message,
        data: result.data,
      };
    } catch (error) {
      this.logger.error('Verification submission failed:', error.message);
      throw error;
    }
  }

  /**
   * Initier la récupération de compte
   */
  @Post('recovery/init')
  @HttpCode(HttpStatus.OK)
  async initRecovery(@Body() recoveryDto: RecoveryDto) {
    try {
      const result = await this.authService.initiateRecovery(recoveryDto);

      return {
        success: true,
        message: result.message,
        data: {
          flowId: result.flowId,
          email: result.email,
        },
      };
    } catch (error) {
      this.logger.error('Recovery init failed:', error.message);
      throw error;
    }
  }

  /**
   * Soumettre le code de récupération
   */
  @Post('recovery/submit')
  @HttpCode(HttpStatus.OK)
  async submitRecovery(@Body() submitDto: SubmitRecoveryDto) {
    try {
      const result = await this.authService.submitRecovery(submitDto);

      return {
        success: true,
        message: result.message,
        data: result.data,
      };
    } catch (error) {
      this.logger.error('Recovery submission failed:', error.message);
      throw error;
    }
  }

  // ===========================
  // SESSION ET PROFIL
  // ===========================

  /**
   * Validation de session
   */
  @Get('validate')
  async validateSession(@Headers('authorization') authHeader: string) {
    try {
      if (!authHeader) {
        throw new BadRequestException('Authorization header is required');
      }

      const sessionToken = authHeader.replace('Bearer ', '');
      const result = await this.authService.validateSession(sessionToken);

      return {
        success: true,
        message: 'Session is valid',
        data: {
          valid: result.valid,
          source: result.source,
          user: result.user
            ? {
                id: result.user.id,
                email: result.user.email,
                firstName: result.user.firstName,
                lastName: result.user.lastName,
                emailVerified: result.user.emailVerified,
              }
            : null,
          session: result.session || null,
        },
      };
    } catch (error) {
      this.logger.error('Session validation failed:', error.message);
      throw error;
    }
  }

  /**
   * Récupération du profil utilisateur
   */
  @Get('profile')
  async getProfile(@Headers('authorization') authHeader: string) {
    try {
      if (!authHeader) {
        throw new BadRequestException('Authorization header is required');
      }

      const sessionToken = authHeader.replace('Bearer ', '');
      const sessionData = await this.authService.validateSession(sessionToken);

      if (!sessionData.valid || !sessionData.user) {
        throw new BadRequestException('Invalid session or user not found');
      }

      return {
        success: true,
        message: 'Profile retrieved successfully',
        data: {
          user: sessionData.user,
          sessionSource: sessionData.source,
        },
      };
    } catch (error) {
      this.logger.error('Profile retrieval failed:', error.message);
      throw error;
    }
  }

  // ===========================
  // WEBHOOK KRATOS
  // ===========================

  /**
   * Endpoint pour les webhooks Kratos
   */
  @Post('webhook')
  @HttpCode(HttpStatus.OK)
  async handleWebhook(
    @Body() webhookData: KratosWebhookData,
    @Headers('x-webhook-secret') webhookSecret?: string,
  ) {
    try {
      // Vérification du secret de webhook
      const expectedSecret =
        process.env.WEBHOOK_SECRET || 'your-webhook-secret-here';
      if (webhookSecret !== expectedSecret) {
        this.logger.error('Invalid webhook secret received');
        throw new BadRequestException('Invalid webhook secret');
      }

      this.logger.log(`Processing Kratos webhook: ${webhookData.type}`);

      await this.authService.handleKratosWebhook(webhookData);

      return {
        success: true,
        message: 'Webhook processed successfully',
        type: webhookData.type,
      };
    } catch (error) {
      this.logger.error('Webhook processing failed:', error.message);
      throw error;
    }
  }

  // ===========================
  // ADMINISTRATION ET MONITORING
  // ===========================

  /**
   * Santé du système d'authentification
   */
  @Get('health')
  async getHealth() {
    try {
      const health = await this.authService.getHealthReport();

      return {
        success: true,
        message: 'Health report retrieved',
        data: health,
      };
    } catch (error) {
      this.logger.error('Health check failed:', error.message);
      return {
        success: false,
        message: 'Health check failed',
        error: error.message,
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Statistiques du système
   */
  @Get('stats')
  async getStats() {
    try {
      const stats = await this.authService.getAuthStats();

      return {
        success: true,
        message: 'Statistics retrieved',
        data: stats,
      };
    } catch (error) {
      this.logger.error('Stats retrieval failed:', error.message);
      throw error;
    }
  }

  /**
   * Synchronisation manuelle des identités
   */
  @Post('sync')
  @HttpCode(HttpStatus.OK)
  async syncIdentities() {
    try {
      this.logger.log('Manual sync requested');
      const result = await this.authService.syncAllKratosIdentities();

      return {
        success: true,
        message: 'Synchronization completed',
        data: result,
      };
    } catch (error) {
      this.logger.error('Manual sync failed:', error.message);
      throw error;
    }
  }

  /**
   * Synchronisation bidirectionnelle
   */
  @Post('sync/full')
  @HttpCode(HttpStatus.OK)
  async fullSync() {
    try {
      this.logger.log('Full bidirectional sync requested');
      const result = await this.authService.performFullSync();

      return {
        success: true,
        message: 'Full synchronization completed',
        data: result,
      };
    } catch (error) {
      this.logger.error('Full sync failed:', error.message);
      throw error;
    }
  }

  /**
   * Nettoyage des données orphelines
   */
  @Post('cleanup')
  @HttpCode(HttpStatus.OK)
  async cleanup() {
    try {
      this.logger.log('Cleanup requested');
      const result = await this.authService.cleanupOrphanedData();

      return {
        success: true,
        message: 'Cleanup completed',
        data: result,
      };
    } catch (error) {
      this.logger.error('Cleanup failed:', error.message);
      throw error;
    }
  }

  // ===========================
  // ENDPOINTS DE DEBUG (à supprimer en production)
  // ===========================

  /**
   * Test de connectivité Kratos
   */
  @Get('debug/kratos-status')
  async getKratosStatus() {
    try {
      const isAvailable = await this.authService.isKratosAvailable();

      return {
        success: true,
        data: {
          available: isAvailable,
          publicUrl:
            process.env.NODE_ENV === 'docker'
              ? 'http://kratos:4433'
              : 'http://localhost:4433',
          adminUrl:
            process.env.NODE_ENV === 'docker'
              ? 'http://kratos:4434'
              : 'http://localhost:4434',
          environment: process.env.NODE_ENV,
          timestamp: new Date().toISOString(),
        },
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Synchronisation d'un utilisateur spécifique
   */
  @Post('debug/sync-user')
  @HttpCode(HttpStatus.OK)
  async syncSpecificUser(@Body() { email }: { email: string }) {
    try {
      if (!email) {
        throw new BadRequestException('Email is required');
      }

      const user = await this.authService.syncUserByEmail(email);

      return {
        success: true,
        message: user ? 'User synchronized' : 'User not found',
        data: { user },
      };
    } catch (error) {
      this.logger.error(`Sync user failed for ${email}:`, error.message);
      throw error;
    }
  }
}
