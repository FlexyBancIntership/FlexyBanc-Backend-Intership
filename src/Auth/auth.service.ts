import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
  Logger,
  InternalServerErrorException,
} from '@nestjs/common';
import {
  Configuration,
  FrontendApi,
  IdentityApi,
  Session,
  UpdateLoginFlowBody,
  UpdateRegistrationFlowBody,
  Identity,
  RegistrationFlow,
  LoginFlow,
  VerificationFlow,
  RecoveryFlow,
  UpdateRecoveryFlowBody,
  SettingsFlow,
  UpdateSettingsFlowBody,
} from '@ory/kratos-client';
import axios, { AxiosResponse } from 'axios';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { UserNeeds } from './entities/userNeeds.entity';
import { Appointment } from './entities/appointment.entity';
import * as bcrypt from 'bcrypt';

export interface SignupDto {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  phone: string;
  birthDate: string;
  cinNumber: string;
  countryCode?: string;
  domainActivity?: string;
  pack?: string;
  needs?: string[];
  appointmentDate?: string;
  messageToExpert?: string;
}

export interface LoginDto {
  email: string;
  password: string;
}

export interface VerificationDto {
  email: string;
}

export interface SubmitVerificationDto {
  flowId: string;
  code: string;
}

export interface RecoveryDto {
  email: string;
}

export interface SubmitRecoveryDto {
  flowId: string;
  code: string;
  password?: string;
}

export interface KratosWebhookData {
  type: string;
  data: {
    identity: Identity;
    session?: Session;
  };
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  private readonly kratosPublicUrl =
    process.env.NODE_ENV === 'docker'
      ? 'http://kratos:4433'
      : 'http://localhost:4433';

  private readonly kratosAdminUrl =
    process.env.NODE_ENV === 'docker'
      ? 'http://kratos:4434'
      : 'http://localhost:4434';

  private readonly kratosPublicApi: FrontendApi;
  private readonly kratosAdminApi: IdentityApi;

  constructor(
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
    @InjectRepository(UserNeeds)
    private readonly needsRepo: Repository<UserNeeds>,
    @InjectRepository(Appointment)
    private readonly appointmentRepo: Repository<Appointment>,
  ) {
    const kratosPublicConfig = new Configuration({
      basePath: this.kratosPublicUrl,
    });

    const kratosAdminConfig = new Configuration({
      basePath: this.kratosAdminUrl,
    });

    this.kratosPublicApi = new FrontendApi(
      kratosPublicConfig,
      undefined,
      axios.create({
        timeout: 10000,
      }) as any,
    );

    this.kratosAdminApi = new IdentityApi(
      kratosAdminConfig,
      undefined,
      axios.create({
        timeout: 10000,
      }) as any,
    );

    this.logger.log(`Kratos Public URL: ${this.kratosPublicUrl}`);
    this.logger.log(`Kratos Admin URL: ${this.kratosAdminUrl}`);
  }

  async handleKratosWebhook(webhookData: KratosWebhookData): Promise<void> {
    this.logger.log(`Received Kratos webhook: ${webhookData.type}`);

    if (!webhookData.data || !webhookData.data.identity) {
      this.logger.error('Invalid webhook data received');
      throw new BadRequestException('Invalid webhook data');
    }

    try {
      switch (webhookData.type) {
        case 'registration':
          await this.handleRegistrationWebhook(webhookData.data.identity);
          break;
        case 'login':
          await this.handleLoginWebhook(webhookData.data.identity);
          break;
        case 'verification':
          await this.handleVerificationWebhook(webhookData.data.identity);
          break;
        default:
          this.logger.warn(`Unknown webhook type: ${webhookData.type}`);
      }
    } catch (error) {
      this.logger.error('Webhook handler error:', error.message);
      throw new InternalServerErrorException('Failed to process webhook');
    }
  }

  private async handleRegistrationWebhook(identity: Identity): Promise<void> {
    const traits = identity.traits as any;

    if (!traits || !traits.email) {
      this.logger.error('Invalid identity traits received in webhook');
      return;
    }

    try {
      await this.userRepo.manager.transaction(
        async (transactionalEntityManager) => {
          const existingUser = await transactionalEntityManager.findOne(User, {
            where: { email: traits.email },
          });

          if (existingUser) {
            existingUser.kratosIdentityId = identity.id;
            existingUser.updatedAt = new Date();
            await transactionalEntityManager.save(existingUser);
            this.logger.log(
              `Updated existing user ${traits.email} with Kratos ID`,
            );
            return;
          }

          const user = new User();
          user.email = traits.email;
          user.firstName = traits.firstName || 'N/A';
          user.lastName = traits.lastName || 'N/A';
          user.phone = traits.phone || '';
          user.birthDate = traits.birthDate
            ? new Date(traits.birthDate)
            : new Date();
          user.cinNumber = traits.cinNumber || '';
          user.countryCode = traits.countryCode || 'TN';
          user.domainActivity = traits.domainActivity || null;
          user.pack = traits.pack || 'basic';
          user.kratosIdentityId = identity.id;
          user.password = await bcrypt.hash('kratos-managed', 12);
          user.createdAt = new Date();
          user.updatedAt = new Date();

          const savedUser = await transactionalEntityManager.save(user);
          this.logger.log(
            `User ${traits.email} synchronized to local DB with ID ${savedUser.id}`,
          );
        },
      );
    } catch (error) {
      this.logger.error(
        `Failed to sync user ${traits.email} to local DB:`,
        error.message,
      );
      throw error;
    }
  }

  private async handleLoginWebhook(identity: Identity): Promise<void> {
    const traits = identity.traits as any;

    if (!traits || !traits.email) {
      this.logger.error('Invalid identity traits received in login webhook');
      return;
    }

    try {
      const user = await this.userRepo.findOne({
        where: { email: traits.email },
      });

      if (user) {
        user.lastLogin = new Date();
        user.updatedAt = new Date();
        if (!user.kratosIdentityId) {
          user.kratosIdentityId = identity.id;
        }
        await this.userRepo.save(user);
        this.logger.log(`Updated last login for user ${traits.email}`);
      } else {
        await this.handleRegistrationWebhook(identity);
      }
    } catch (error) {
      this.logger.error(
        `Failed to update login for user ${traits.email}:`,
        error.message,
      );
      throw error;
    }
  }

  private async handleVerificationWebhook(identity: Identity): Promise<void> {
    const traits = identity.traits as any;

    if (!traits || !traits.email) {
      this.logger.error(
        'Invalid identity traits received in verification webhook',
      );
      return;
    }

    try {
      const user = await this.userRepo.findOne({
        where: { email: traits.email },
      });

      if (user) {
        user.emailVerified = true;
        user.emailVerifiedAt = new Date();
        user.updatedAt = new Date();
        if (!user.kratosIdentityId) {
          user.kratosIdentityId = identity.id;
        }
        await this.userRepo.save(user);
        this.logger.log(`Email verified for user ${traits.email}`);
      } else {
        await this.handleRegistrationWebhook(identity);
        const newUser = await this.userRepo.findOne({
          where: { email: traits.email },
        });
        if (newUser) {
          newUser.emailVerified = true;
          newUser.emailVerifiedAt = new Date();
          await this.userRepo.save(newUser);
        }
      }
    } catch (error) {
      this.logger.error(
        `Failed to update verification status for user ${traits.email}:`,
        error.message,
      );
      throw error;
    }
  }

  async isKratosAvailable(): Promise<boolean> {
    try {
      await axios.get(`${this.kratosPublicUrl}/health/ready`, {
        timeout: 5000,
      });
      this.logger.log('Kratos is available');
      return true;
    } catch {
      this.logger.warn('Kratos health check failed');
      return false;
    }
  }

  async signup(data: SignupDto): Promise<any> {
    try {
      if (!data.email || !data.password) {
        throw new BadRequestException('Email and password are required');
      }

      this.logger.log(`Starting signup process for email: ${data.email}`);

      const kratosAvailable = await this.isKratosAvailable();
      const localUser = await this.createLocalUser(data);

      let kratosResult = null;

      if (kratosAvailable) {
        try {
          kratosResult = await this.createKratosIdentity(data);

          if (kratosResult) {
            localUser.kratosIdentityId = kratosResult.id;
            await this.userRepo.save(localUser);
            this.logger.log(
              `Kratos identity created successfully for: ${data.email}`,
            );
          }
        } catch (kratosError) {
          this.logger.warn(
            `Kratos registration failed for ${data.email}:`,
            kratosError.message,
          );
        }
      } else {
        this.logger.warn(
          'Kratos unavailable during signup, using local DB only',
        );
      }

      const userWithRelations = await this.userRepo.findOne({
        where: { id: localUser.id },
        relations: ['needs', 'appointments'],
      });

      return {
        message: 'User created successfully',
        user: userWithRelations,
        kratosIdentity: kratosResult ? kratosResult.id : null,
        hasKratosAccount: !!kratosResult,
        method: kratosResult ? 'hybrid' : 'local_only',
      };
    } catch (error) {
      this.logger.error('Signup error:', error);

      if (error instanceof BadRequestException) {
        throw error;
      }

      if (error.response?.status === 400) {
        const kratosError =
          error.response.data?.ui?.messages?.[0]?.text || 'Invalid input';
        throw new BadRequestException(kratosError);
      }

      throw new InternalServerErrorException(
        error.message || 'Registration failed',
      );
    }
  }

  private async createLocalUser(data: SignupDto): Promise<User> {
    try {
      const existingUser = await this.userRepo.findOne({
        where: { email: data.email },
      });
      if (existingUser) {
        throw new BadRequestException('User with this email already exists');
      }

      return await this.userRepo.manager.transaction(
        async (transactionalEntityManager) => {
          const user = new User();
          user.email = data.email;
          user.firstName = data.firstName || '';
          user.lastName = data.lastName || '';
          user.phone = data.phone || '';
          user.password = await bcrypt.hash(data.password, 12);

          try {
            user.birthDate = data.birthDate
              ? new Date(data.birthDate)
              : new Date();
          } catch {
            user.birthDate = new Date();
          }

          user.cinNumber = data.cinNumber || '';
          user.countryCode = data.countryCode || 'TN';
          user.domainActivity = data.domainActivity || null;
          user.pack = data.pack || 'basic';
          user.createdAt = new Date();
          user.updatedAt = new Date();
          user.emailVerified = false;

          const savedUser = await transactionalEntityManager.save(User, user);

          if (
            data.needs &&
            Array.isArray(data.needs) &&
            data.needs.length > 0
          ) {
            const needsEntities = data.needs.map((type: string) => {
              const need = new UserNeeds();
              need.type = type;
              need.user = savedUser;
              return need;
            });
            await transactionalEntityManager.save(UserNeeds, needsEntities);
          }

          if (data.appointmentDate || data.messageToExpert) {
            const appointment = new Appointment();
            appointment.date = data.appointmentDate
              ? new Date(data.appointmentDate)
              : null;
            appointment.message = data.messageToExpert || null;
            appointment.user = savedUser;
            await transactionalEntityManager.save(Appointment, appointment);
          }

          return savedUser;
        },
      );
    } catch (error) {
      this.logger.error('Failed to create local user:', error.message);
      throw error;
    }
  }

  private async createKratosIdentity(data: SignupDto): Promise<any> {
    try {
      if (!(await this.isKratosAvailable())) {
        throw new Error('Kratos service is not available');
      }

      const flow = (await Promise.race([
        this.kratosPublicApi.createBrowserRegistrationFlow({}),
        new Promise((_, reject) =>
          setTimeout(
            () => reject(new Error('Registration flow timeout')),
            10000,
          ),
        ),
      ])) as AxiosResponse<RegistrationFlow>;

      if (!flow || !flow.data) {
        throw new Error('Failed to initialize registration flow');
      }

      const submitBody: UpdateRegistrationFlowBody = {
        method: 'password',
        password: data.password,
        traits: {
          email: data.email,
          firstName: data.firstName,
          lastName: data.lastName,
          phone: data.phone,
          birthDate: data.birthDate,
          cinNumber: data.cinNumber,
          countryCode: data.countryCode || 'TN',
          domainActivity: data.domainActivity || null,
          pack: data.pack || 'basic',
        },
      };

      const response = (await Promise.race([
        this.kratosPublicApi.updateRegistrationFlow({
          flow: flow.data.id,
          updateRegistrationFlowBody: submitBody,
        }),
        new Promise((_, reject) =>
          setTimeout(
            () => reject(new Error('Registration submission timeout')),
            10000,
          ),
        ),
      ])) as AxiosResponse<{ identity: Identity }>;

      return response.data.identity;
    } catch (error) {
      this.logger.error('Kratos identity creation failed:', error);

      if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
        throw new Error('Cannot connect to Kratos service');
      }

      if (error.response?.status === 400) {
        throw new Error(
          error.response.data?.ui?.messages?.[0]?.text ||
            'Invalid registration data',
        );
      }

      throw error;
    }
  }

  async login(credentials: LoginDto): Promise<any> {
    const { email, password } = credentials;

    if (!email || !password) {
      throw new BadRequestException('Email and password are required');
    }

    this.logger.log(`Login attempt for email: ${email}`);

    const localUser = await this.userRepo.findOne({
      where: { email },
      relations: ['needs', 'appointments'],
    });

    if (!localUser) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const isPasswordValid = await bcrypt.compare(password, localUser.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const kratosAvailable = await this.isKratosAvailable();
    let kratosResult = null;

    if (kratosAvailable && localUser.kratosIdentityId) {
      try {
        kratosResult = await this.loginWithKratos(email, password);
        this.logger.log(`Kratos login successful for ${email}`);
      } catch {
        this.logger.warn(`Kratos login failed for ${email}, using local auth`);
      }
    }

    localUser.lastLogin = new Date();
    localUser.updatedAt = new Date();
    await this.userRepo.save(localUser);

    const sessionToken =
      kratosResult?.session_token ||
      Buffer.from(`${localUser.id}:${Date.now()}`).toString('base64');

    return {
      message: 'Login successful',
      session: kratosResult?.session || null,
      sessionToken,
      user: localUser,
      method: kratosResult ? 'kratos' : 'local',
      kratosAvailable,
    };
  }

  private async loginWithKratos(email: string, password: string): Promise<any> {
    try {
      const flow = (await Promise.race([
        this.kratosPublicApi.createBrowserLoginFlow({}),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Login flow timeout')), 10000),
        ),
      ])) as AxiosResponse<LoginFlow>;

      if (!flow || !flow.data) {
        throw new Error('Failed to initialize login flow');
      }

      const submitBody: UpdateLoginFlowBody = {
        method: 'password',
        identifier: email,
        password,
      };

      const response = (await Promise.race([
        this.kratosPublicApi.updateLoginFlow({
          flow: flow.data.id,
          updateLoginFlowBody: submitBody,
        }),
        new Promise((_, reject) =>
          setTimeout(
            () => reject(new Error('Login submission timeout')),
            10000,
          ),
        ),
      ])) as AxiosResponse<{ session: Session; session_token: string }>;

      return response.data;
    } catch {
      this.logger.error('Kratos login error');
      throw new UnauthorizedException(
        'Invalid credentials or Kratos unavailable',
      );
    }
  }

  async logout(sessionToken: string | undefined): Promise<{ message: string }> {
    if (!sessionToken) {
      throw new BadRequestException('Session token is required');
    }

    this.logger.log('Logout attempt');

    if (await this.isKratosAvailable()) {
      try {
        await axios.post(
          `${this.kratosPublicUrl}/self-service/logout/browser`,
          { session_token: sessionToken },
          {
            headers: {
              'Content-Type': 'application/json',
            },
          },
        );
        this.logger.log('Kratos session invalidated');
        return { message: 'Logout successful' };
      } catch (error) {
        this.logger.warn('Kratos logout failed:', error.message);
      }
    }

    // For local sessions, we rely on client-side token invalidation
    return { message: 'Logout successful (local session)' };
  }

  async initVerificationFlow(): Promise<VerificationFlow> {
    try {
      if (!(await this.isKratosAvailable())) {
        throw new Error('Kratos service is not available');
      }

      const response = (await Promise.race([
        this.kratosPublicApi.createBrowserVerificationFlow({}),
        new Promise((_, reject) =>
          setTimeout(
            () => reject(new Error('Verification flow timeout')),
            10000,
          ),
        ),
      ])) as AxiosResponse<VerificationFlow>;

      if (!response || !response.data) {
        throw new Error('Failed to initialize verification flow');
      }

      this.logger.log('Verification flow initialized');
      return response.data;
    } catch (error) {
      this.logger.error('Verification flow initialization failed:', error);
      throw new InternalServerErrorException(
        error.message || 'Failed to initialize verification flow',
      );
    }
  }

  async submitVerification(
    submitDto: SubmitVerificationDto,
  ): Promise<{ message: string; data: any }> {
    try {
      if (!submitDto.flowId || !submitDto.code) {
        throw new BadRequestException('Flow ID and code are required');
      }

      if (!(await this.isKratosAvailable())) {
        throw new Error('Kratos service is not available');
      }

      const submitBody = {
        method: 'code',
        code: submitDto.code,
      } as any; // Type assertion to bypass strict type checking

      const response = (await Promise.race([
        this.kratosPublicApi.updateVerificationFlow({
          flow: submitDto.flowId,
          updateVerificationFlowBody: submitBody,
        }),
        new Promise((_, reject) =>
          setTimeout(
            () => reject(new Error('Verification submission timeout')),
            10000,
          ),
        ),
      ])) as AxiosResponse<{ identity: Identity }>;

      const identity = response.data.identity;
      await this.handleVerificationWebhook(identity);

      this.logger.log(`Verification successful for ${identity.traits.email}`);
      return {
        message: 'Verification successful',
        data: { identityId: identity.id },
      };
    } catch (error) {
      this.logger.error('Verification submission failed:', error);

      if (error.response?.status === 400) {
        throw new BadRequestException(
          error.response.data?.ui?.messages?.[0]?.text ||
            'Invalid verification code',
        );
      }

      throw new InternalServerErrorException(
        error.message || 'Verification failed',
      );
    }
  }

  async initiateRecovery(recoveryDto: RecoveryDto): Promise<{
    message: string;
    flowId: string;
    email: string;
  }> {
    try {
      if (!recoveryDto.email) {
        throw new BadRequestException('Email is required');
      }

      if (!(await this.isKratosAvailable())) {
        throw new Error('Kratos service is not available');
      }

      const response = (await Promise.race([
        this.kratosPublicApi.createBrowserRecoveryFlow({}),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Recovery flow timeout')), 10000),
        ),
      ])) as AxiosResponse<RecoveryFlow>;

      if (!response || !response.data) {
        throw new Error('Failed to initialize recovery flow');
      }

      const submitBody: UpdateRecoveryFlowBody = {
        method: 'code',
        email: recoveryDto.email,
      };

      await this.kratosPublicApi.updateRecoveryFlow({
        flow: response.data.id,
        updateRecoveryFlowBody: submitBody,
      });

      this.logger.log(`Recovery flow initiated for ${recoveryDto.email}`);
      return {
        message: 'Recovery flow initiated',
        flowId: response.data.id,
        email: recoveryDto.email,
      };
    } catch (error) {
      this.logger.error('Recovery initiation failed:', error);

      if (error.response?.status === 400) {
        throw new BadRequestException(
          error.response.data?.ui?.messages?.[0]?.text ||
            'Invalid recovery data',
        );
      }

      throw new InternalServerErrorException(
        error.message || 'Failed to initiate recovery',
      );
    }
  }

  async submitRecovery(
    submitDto: SubmitRecoveryDto,
  ): Promise<{ message: string; data: any }> {
    try {
      if (!submitDto.flowId || !submitDto.code) {
        throw new BadRequestException('Flow ID and code are required');
      }

      if (!(await this.isKratosAvailable())) {
        throw new Error('Kratos service is not available');
      }

      // Step 1: Submit recovery code
      const submitBody: UpdateRecoveryFlowBody = {
        method: 'code',
        code: submitDto.code,
      };

      const recoveryResponse = (await Promise.race([
        this.kratosPublicApi.updateRecoveryFlow({
          flow: submitDto.flowId,
          updateRecoveryFlowBody: submitBody,
        }),
        new Promise((_, reject) =>
          setTimeout(
            () => reject(new Error('Recovery submission timeout')),
            10000,
          ),
        ),
      ])) as AxiosResponse<{ identity: Identity; session_token: string }>;

      const identity = recoveryResponse.data.identity;
      const sessionToken = recoveryResponse.data.session_token;

      // Step 2: Update password if provided
      if (submitDto.password) {
        const settingsFlow = (await Promise.race([
          this.kratosPublicApi.createBrowserSettingsFlow({
            cookie: `ory_kratos_session=${sessionToken}`,
          }),
          new Promise((_, reject) => {
            setTimeout(
              () => reject(new Error('Recovery submission timeout')),
              10000,
            );
          }),
        ])) as AxiosResponse<SettingsFlow>;

        const settingsBody: UpdateSettingsFlowBody = {
          method: 'password',
          password: submitDto.password,
        };

        await this.kratosPublicApi.updateSettingsFlow({
          flow: settingsFlow.data.id,
          updateSettingsFlowBody: settingsBody,
        });

        const localUser = await this.userRepo.findOne({
          where: { kratosIdentityId: identity.id },
        });
        if (localUser) {
          localUser.password = await bcrypt.hash(submitDto.password, 12);
          await this.userRepo.save(localUser);
          this.logger.log(
            `Password updated for user ${identity.traits.email} in local DB`,
          );
        }
      }

      this.logger.log(`Recovery successful for ${identity.traits.email}`);
      return {
        message: 'Recovery successful',
        data: { identityId: identity.id },
      };
    } catch (error) {
      this.logger.error('Recovery submission failed:', error);

      if (error.response?.status === 400) {
        throw new BadRequestException(
          error.response.data?.ui?.messages?.[0]?.text ||
            'Invalid recovery code or password',
        );
      }

      throw new InternalServerErrorException(
        error.message || 'Recovery failed',
      );
    }
  }

  async syncAllKratosIdentities(): Promise<{
    synced: number;
    errors: number;
    skipped: number;
  }> {
    this.logger.log('Starting full sync of Kratos identities to local DB');

    let synced = 0;
    let errors = 0;
    let skipped = 0;
    let page = 1;
    const perPage = 50;

    try {
      if (!(await this.isKratosAvailable())) {
        throw new Error('Kratos service is not available for sync');
      }

      while (true) {
        try {
          const response = (await Promise.race([
            this.kratosAdminApi.listIdentities({
              perPage,
              page,
            }),
            new Promise((_, reject) =>
              setTimeout(
                () => reject(new Error('List identities timeout')),
                15000,
              ),
            ),
          ])) as AxiosResponse<Identity[]>;

          const identities = response.data;

          if (!identities || identities.length === 0) {
            break;
          }

          for (const identity of identities) {
            try {
              const traits = identity.traits as any;

              if (!traits || !traits.email) {
                this.logger.warn(
                  `Skipping identity ${identity.id} - invalid traits`,
                );
                skipped++;
                continue;
              }

              const existingUser = await this.userRepo.findOne({
                where: { email: traits.email },
              });

              if (existingUser) {
                if (!existingUser.kratosIdentityId) {
                  existingUser.kratosIdentityId = identity.id;
                  existingUser.updatedAt = new Date();
                  await this.userRepo.save(existingUser);
                  synced++;
                } else {
                  skipped++;
                }
              } else {
                await this.handleRegistrationWebhook(identity);
                synced++;
              }
            } catch (error) {
              this.logger.error(
                `Failed to sync identity ${identity.id}:`,
                error.message,
              );
              errors++;
            }
          }

          if (identities.length < perPage) {
            break;
          }

          page++;
          await new Promise((resolve) => setTimeout(resolve, 100));
        } catch (pageError) {
          this.logger.error(
            `Failed to process page ${page}:`,
            pageError.message,
          );
          errors++;
          break;
        }
      }

      this.logger.log(
        `Sync completed: ${synced} synced, ${skipped} skipped, ${errors} errors`,
      );
      return { synced, errors, skipped };
    } catch (error) {
      this.logger.error('Failed to sync Kratos identities:', error.message);
      throw new BadRequestException(
        'Failed to sync identities: ' + error.message,
      );
    }
  }

  async performFullSync(): Promise<{
    syncedToKratos: number;
    syncedToLocal: number;
    errors: number;
  }> {
    this.logger.log('Starting full bidirectional sync');

    let syncedToKratos = 0;
    let syncedToLocal = 0;
    let errors = 0;

    try {
      if (!(await this.isKratosAvailable())) {
        throw new Error('Kratos service is not available for sync');
      }

      // Sync Kratos to local DB
      const kratosSyncResult = await this.syncAllKratosIdentities();
      syncedToLocal += kratosSyncResult.synced;
      errors += kratosSyncResult.errors;

      // Sync local DB to Kratos
      const localUsers = await this.userRepo.find({
        where: { kratosIdentityId: null },
      });

      for (const user of localUsers) {
        try {
          const signupDto: SignupDto = {
            email: user.email,
            password: user.password,
            firstName: user.firstName,
            lastName: user.lastName,
            phone: user.phone,
            birthDate: user.birthDate.toISOString(),
            cinNumber: user.cinNumber,
            countryCode: user.countryCode,
            domainActivity: user.domainActivity,
            pack: user.pack,
          };

          const kratosIdentity = await this.createKratosIdentity(signupDto);
          user.kratosIdentityId = kratosIdentity.id;
          user.updatedAt = new Date();
          await this.userRepo.save(user);
          syncedToKratos++;
          this.logger.log(
            `Synced local user ${user.email} to Kratos with ID ${kratosIdentity.id}`,
          );
        } catch (error) {
          this.logger.error(
            `Failed to sync local user ${user.email} to Kratos:`,
            error.message,
          );
          errors++;
        }
      }

      this.logger.log(
        `Full sync completed: ${syncedToKratos} to Kratos, ${syncedToLocal} to local, ${errors} errors`,
      );
      return { syncedToKratos, syncedToLocal, errors };
    } catch (error) {
      this.logger.error('Full sync failed:', error.message);
      throw new InternalServerErrorException(
        error.message || 'Full sync failed',
      );
    }
  }

  async getHealthReport(): Promise<any> {
    const startTime = Date.now();
    const kratosAvailable = await this.isKratosAvailable();
    let databaseAvailable = true;
    let totalUsers = 0;
    let verifiedUsers = 0;

    try {
      totalUsers = await this.userRepo.count();
      verifiedUsers = await this.userRepo.count({
        where: { emailVerified: true },
      });
    } catch {
      databaseAvailable = false;
      this.logger.error('Database health check failed');
    }

    let kratosIdentities = 0;
    let kratosError = null;

    if (kratosAvailable) {
      try {
        const response = (await Promise.race([
          this.kratosAdminApi.listIdentities({ perPage: 1, page: 1 }),
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Kratos list timeout')), 5000),
          ),
        ])) as AxiosResponse<Identity[]>;
        kratosIdentities = parseInt(response.headers['x-total-count']) || 0;
      } catch (error) {
        kratosError = error.message;
        this.logger.warn(
          'Failed to get Kratos identities count:',
          error.message,
        );
      }
    }

    const responseTime = Date.now() - startTime;
    const syncNeeded = kratosIdentities !== totalUsers && kratosAvailable;

    return {
      timestamp: new Date().toISOString(),
      responseTime: `${responseTime}ms`,
      status: kratosAvailable && databaseAvailable ? 'healthy' : 'degraded',
      services: {
        kratos: {
          available: kratosAvailable,
          publicUrl: this.kratosPublicUrl,
          adminUrl: this.kratosAdminUrl,
          identities: kratosIdentities,
          error: kratosError,
        },
        database: {
          available: databaseAvailable,
          totalUsers,
          verifiedUsers,
        },
      },
      synchronization: {
        kratosIdentities,
        localUsers: totalUsers,
        syncNeeded,
        lastSync: new Date().toISOString(),
      },
      environment: {
        nodeEnv: process.env.NODE_ENV,
        kratosMode: process.env.NODE_ENV === 'docker' ? 'container' : 'local',
      },
    };
  }

  async syncUserByEmail(email: string): Promise<User | null> {
    if (!email) {
      throw new BadRequestException('Email is required');
    }

    try {
      if (!(await this.isKratosAvailable())) {
        this.logger.warn('Kratos unavailable for sync, checking local DB only');
        return await this.userRepo.findOne({
          where: { email },
          relations: ['needs', 'appointments'],
        });
      }

      const identitiesResponse = (await Promise.race([
        this.kratosAdminApi.listIdentities({
          perPage: 100,
          page: 1,
        }),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Search timeout')), 10000),
        ),
      ])) as AxiosResponse<Identity[]>;

      const kratosIdentity = identitiesResponse.data.find(
        (id) => (id.traits as any)?.email === email,
      );

      if (!kratosIdentity) {
        this.logger.warn(`User with email ${email} not found in Kratos`);
        return await this.userRepo.findOne({
          where: { email },
          relations: ['needs', 'appointments'],
        });
      }

      await this.handleRegistrationWebhook(kratosIdentity);

      return await this.userRepo.findOne({
        where: { email },
        relations: ['needs', 'appointments'],
      });
    } catch {
      this.logger.error(`Failed to sync user ${email}`);

      try {
        return await this.userRepo.findOne({
          where: { email },
          relations: ['needs', 'appointments'],
        });
      } catch {
        this.logger.error('Failed to get user from local DB');
        throw new BadRequestException(`Failed to sync user`);
      }
    }
  }

  async validateSession(sessionToken: string): Promise<any> {
    if (!sessionToken) {
      throw new UnauthorizedException('Session token is required');
    }

    if (!sessionToken.includes(':') && (await this.isKratosAvailable())) {
      try {
        const response = await this.kratosPublicApi.toSession({
          cookie: `ory_kratos_session=${sessionToken}`,
        });
        return {
          valid: true,
          session: response.data,
          source: 'kratos',
        };
      } catch {
        this.logger.warn(
          'Kratos session validation failed, trying local validation',
        );
      }
    }

    try {
      const decodedToken = Buffer.from(sessionToken, 'base64').toString(
        'utf-8',
      );
      const [userIdStr, timestampStr] = decodedToken.split(':');

      const userId = parseInt(userIdStr);
      const timestamp = parseInt(timestampStr);

      if (isNaN(userId) || isNaN(timestamp)) {
        throw new Error('Invalid token format');
      }

      if (Date.now() - timestamp > 24 * 60 * 60 * 1000) {
        throw new Error('Token expired');
      }

      const user = await this.userRepo.findOne({
        where: { id: userId },
        relations: ['needs', 'appointments'],
      });

      if (!user) {
        throw new Error('User not found');
      }

      return {
        valid: true,
        user,
        source: 'local',
      };
    } catch {
      throw new UnauthorizedException('Invalid or expired session');
    }
  }

  async getAuthStats(): Promise<any> {
    try {
      const totalUsers = await this.userRepo.count();
      const verifiedUsers = await this.userRepo.count({
        where: { emailVerified: true },
      });
      const usersWithKratos = await this.userRepo.count({
        where: { kratosIdentityId: null },
      });
      const kratosAvailable = await this.isKratosAvailable();

      let kratosIdentities = 0;
      if (kratosAvailable) {
        try {
          const response = (await this.kratosAdminApi.listIdentities({
            perPage: 1,
            page: 1,
          })) as AxiosResponse<Identity[]>;
          kratosIdentities = parseInt(response.headers['x-total-count']) || 0;
        } catch (error) {
          this.logger.warn(
            'Failed to get Kratos identities count:',
            error.message,
          );
        }
      }

      return {
        totalUsers,
        verifiedUsers,
        usersWithKratos: totalUsers - usersWithKratos,
        usersWithoutKratos: usersWithKratos,
        kratosIdentities,
        kratosAvailable,
        syncStatus: kratosIdentities === totalUsers ? 'synced' : 'needs_sync',
        lastCheck: new Date().toISOString(),
      };
    } catch {
      this.logger.error('Failed to get auth stats');
      throw new InternalServerErrorException('Failed to get statistics');
    }
  }

  async cleanupOrphanedData(): Promise<{ cleaned: number; errors: number }> {
    let cleaned = 0;
    let errors = 0;

    try {
      const orphanedNeeds = await this.needsRepo
        .createQueryBuilder('need')
        .leftJoinAndSelect('need.user', 'user')
        .where('user.id IS NULL')
        .getMany();

      for (const need of orphanedNeeds) {
        try {
          await this.needsRepo.remove(need);
          cleaned++;
        } catch {
          errors++;
        }
      }

      const orphanedAppointments = await this.appointmentRepo
        .createQueryBuilder('appointment')
        .leftJoinAndSelect('appointment.user', 'user')
        .where('user.id IS NULL')
        .getMany();

      for (const appointment of orphanedAppointments) {
        try {
          await this.appointmentRepo.remove(appointment);
          cleaned++;
        } catch {
          errors++;
        }
      }

      this.logger.log(
        `Cleanup completed: ${cleaned} items cleaned, ${errors} errors`,
      );
      return { cleaned, errors };
    } catch {
      this.logger.error('Cleanup failed');
      throw new InternalServerErrorException('Cleanup failed');
    }
  }
}
