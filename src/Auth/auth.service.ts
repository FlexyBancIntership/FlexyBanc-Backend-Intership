import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import {
  Configuration,
  FrontendApi,
  IdentityApi,
  Session,
  LoginFlow,
  RegistrationFlow,
  UpdateLoginFlowBody,
  UpdateRegistrationFlowBody,
  VerificationFlow,
  RecoveryFlow,
  UpdateRecoveryFlowBody,
  UpdateVerificationFlowBody,
  IdentityState,
  Identity,
  CreateIdentityBody,
  UiNodeInputAttributes,
} from '@ory/kratos-client';
import axios from 'axios';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, Like } from 'typeorm';
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

// Interface pour les webhooks Kratos
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

  // Configuration dynamique selon l'environnement
  private readonly kratosPublicUrl =
    process.env.NODE_ENV === 'development'
      ? 'http://localhost:4433'
      : 'http://kratos:4433';

  private readonly kratosAdminUrl =
    process.env.NODE_ENV === 'development'
      ? 'http://localhost:4434'
      : 'http://kratos:4434';

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
    // Configuration des clients Kratos
    const kratosPublicConfig = new Configuration({
      basePath: this.kratosPublicUrl,
    });

    const kratosAdminConfig = new Configuration({
      basePath: this.kratosAdminUrl,
    });

    this.kratosPublicApi = new FrontendApi(kratosPublicConfig);
    this.kratosAdminApi = new IdentityApi(kratosAdminConfig);
  }

  // ===========================
  // WEBHOOK HANDLERS
  // ===========================

  /**
   * Handler pour les webhooks Kratos - synchronise les identités avec la DB locale
   */
  async handleKratosWebhook(webhookData: KratosWebhookData): Promise<void> {
    this.logger.log(`Received Kratos webhook: ${webhookData.type}`);

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
    }
  }

  /**
   * Synchronise une nouvelle inscription depuis Kratos vers la DB locale
   */
  private async handleRegistrationWebhook(identity: Identity): Promise<void> {
    const traits = identity.traits as any;

    try {
      // Vérifier si l'utilisateur existe déjà
      const existingUser = await this.userRepo.findOne({
        where: { email: traits.email },
      });

      if (existingUser) {
        this.logger.log(`User ${traits.email} already exists in local DB`);
        return;
      }

      // Créer l'utilisateur dans la DB locale
      const user = new User();
      user.email = traits.email;
      user.firstName = traits.firstName;
      user.lastName = traits.lastName;
      user.phone = traits.phone;
      user.birthDate = new Date(traits.birthDate);
      user.cinNumber = traits.cinNumber;
      user.countryCode = traits.countryCode || 'TN';
      user.domainActivity = traits.domainActivity || null;
      user.pack = traits.pack || 'basic';
      user.kratosIdentityId = identity.id; // Lien vers l'identité Kratos

      // Mot de passe factice car géré par Kratos
      user.password = await bcrypt.hash('kratos-managed', 12);

      const savedUser = await this.userRepo.save(user);
      this.logger.log(
        `User ${traits.email} synchronized to local DB with ID ${savedUser.id}`,
      );
    } catch (error) {
      this.logger.error(
        `Failed to sync user ${traits.email} to local DB:`,
        error.message,
      );
    }
  }

  /**
   * Met à jour la dernière connexion lors du login
   */
  private async handleLoginWebhook(identity: Identity): Promise<void> {
    const traits = identity.traits as any;

    try {
      const user = await this.userRepo.findOne({
        where: { email: traits.email },
      });

      if (user) {
        user.lastLogin = new Date();
        await this.userRepo.save(user);
        this.logger.log(`Updated last login for user ${traits.email}`);
      } else {
        // Si l'utilisateur n'existe pas dans la DB locale, le créer
        await this.handleRegistrationWebhook(identity);
      }
    } catch (error) {
      this.logger.error(
        `Failed to update login for user ${traits.email}:`,
        error.message,
      );
    }
  }

  /**
   * Met à jour le statut de vérification de l'email
   */
  private async handleVerificationWebhook(identity: Identity): Promise<void> {
    const traits = identity.traits as any;

    try {
      const user = await this.userRepo.findOne({
        where: { email: traits.email },
      });

      if (user) {
        user.emailVerified = true;
        user.emailVerifiedAt = new Date();
        await this.userRepo.save(user);
        this.logger.log(`Email verified for user ${traits.email}`);
      }
    } catch (error) {
      this.logger.error(
        `Failed to update verification status for user ${traits.email}:`,
        error.message,
      );
    }
  }

  // ===========================
  // SYNCHRONISATION MANUELLE
  // ===========================

  /**
   * Synchronise toutes les identités Kratos avec la DB locale
   */
  async syncAllKratosIdentities(): Promise<{ synced: number; errors: number }> {
    this.logger.log('Starting full sync of Kratos identities to local DB');

    let synced = 0;
    let errors = 0;
    let page = 1;
    const perPage = 100;

    try {
      while (true) {
        const response = await this.kratosAdminApi.listIdentities({
          perPage,
          page,
        });

        const identities = response.data;

        if (!identities || identities.length === 0) {
          break;
        }

        for (const identity of identities) {
          try {
            await this.handleRegistrationWebhook(identity);
            synced++;
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
      }

      this.logger.log(`Sync completed: ${synced} synced, ${errors} errors`);
      return { synced, errors };
    } catch (error) {
      this.logger.error('Failed to sync Kratos identities:', error.message);
      throw new BadRequestException('Failed to sync identities');
    }
  }

  /**
   * Synchronise une identité spécifique par email
   */
  async syncUserByEmail(email: string): Promise<User | null> {
    try {
      // Rechercher l'identité dans Kratos
      const identities = await this.kratosAdminApi.listIdentities({
        perPage: 100,
        page: 1,
      });
      const kratosIdentity = identities.data.find(
        (id) => (id.traits as any).email === email,
      );

      if (!kratosIdentity) {
        throw new NotFoundException(
          `User with email ${email} not found in Kratos`,
        );
      }

      // Synchroniser avec la DB locale
      await this.handleRegistrationWebhook(kratosIdentity);

      // Retourner l'utilisateur de la DB locale
      return await this.userRepo.findOne({
        where: { email },
        relations: ['needs', 'appointments'],
      });
    } catch (error) {
      this.logger.error(`Failed to sync user ${email}:`, error.message);
      throw new BadRequestException(`Failed to sync user: ${error.message}`);
    }
  }

  // ===========================
  // FLOWS INITIALIZATION
  // ===========================

  /**
   * Initialise un flow de registration
   */
  async initRegistrationFlow(returnTo?: string): Promise<RegistrationFlow> {
    try {
      const response = await this.kratosPublicApi.createBrowserRegistrationFlow(
        {
          returnTo,
        },
      );
      return response.data;
    } catch (error) {
      this.logger.error(
        'Failed to initialize registration flow:',
        error.message,
      );
      throw new BadRequestException('Unable to initialize registration flow');
    }
  }

  /**
   * Initialise un flow de login
   */
  async initLoginFlow(returnTo?: string): Promise<LoginFlow> {
    try {
      const response = await this.kratosPublicApi.createBrowserLoginFlow({
        returnTo,
      });
      return response.data;
    } catch (error) {
      this.logger.error('Failed to initialize login flow:', error.message);
      throw new BadRequestException('Unable to initialize login flow');
    }
  }

  /**
   * Initialise un flow de vérification
   */
  async initVerificationFlow(returnTo?: string): Promise<VerificationFlow> {
    try {
      const response = await this.kratosPublicApi.createBrowserVerificationFlow(
        {
          returnTo,
        },
      );
      return response.data;
    } catch (error) {
      this.logger.error(
        'Failed to initialize verification flow:',
        error.message,
      );
      throw new BadRequestException('Unable to initialize verification flow');
    }
  }

  /**
   * Initialise un flow de récupération
   */
  async initRecoveryFlow(returnTo?: string): Promise<RecoveryFlow> {
    try {
      const response = await this.kratosPublicApi.createBrowserRecoveryFlow({
        returnTo,
      });
      return response.data;
    } catch (error) {
      this.logger.error('Failed to initialize recovery flow:', error.message);
      throw new BadRequestException('Unable to initialize recovery flow');
    }
  }

  // ===========================
  // SIGNUP
  // ===========================

  /**
   * Inscription d'un utilisateur avec Kratos + DB locale
   */
  async signup(data: SignupDto): Promise<any> {
    try {
      // Validation des données requises
      if (!data.email || !data.password) {
        throw new BadRequestException('Email and password are required');
      }

      this.logger.log(`Starting signup process for email: ${data.email}`);

      // 1. Création de l'utilisateur dans notre DB locale d'abord
      const localUser = await this.createLocalUser(data);

      // 2. Tentative de création dans Kratos
      let kratosIdentity = null;
      try {
        kratosIdentity = await this.createKratosIdentity(data);

        // Mettre à jour l'utilisateur local avec l'ID Kratos
        localUser.kratosIdentityId = kratosIdentity.id;
        await this.userRepo.save(localUser);

        this.logger.log(
          `Kratos identity created successfully for: ${data.email}`,
        );
      } catch (kratosError) {
        this.logger.warn(
          `Kratos registration failed for ${data.email}:`,
          kratosError.message,
        );
        // On continue même si Kratos échoue, l'utilisateur existe dans notre DB
      }

      // 3. Récupération de l'utilisateur avec toutes ses relations
      const userWithRelations = await this.userRepo.findOne({
        where: { id: localUser.id },
        relations: ['needs', 'appointments'],
      });

      return {
        message: 'User created successfully',
        user: userWithRelations,
        kratosIdentity: kratosIdentity ? kratosIdentity.id : null,
        hasKratosAccount: !!kratosIdentity,
      };
    } catch (error) {
      this.logger.error('Signup error:', error);

      if (error instanceof BadRequestException) {
        throw error;
      }

      throw new BadRequestException(
        error.response?.data?.ui?.messages?.[0]?.text ||
          error.message ||
          'Registration failed',
      );
    }
  }

  /**
   * Crée un utilisateur dans notre base de données locale
   */
  private async createLocalUser(data: SignupDto): Promise<User> {
    // Vérifier si l'utilisateur existe déjà
    const existingUser = await this.userRepo.findOne({
      where: { email: data.email },
    });
    if (existingUser) {
      throw new BadRequestException('User with this email already exists');
    }

    // Création de l'entité User
    const user = new User();
    user.email = data.email;
    user.firstName = data.firstName;
    user.lastName = data.lastName;
    user.phone = data.phone;
    user.password = await bcrypt.hash(data.password, 12);
    user.birthDate = new Date(data.birthDate);
    user.cinNumber = data.cinNumber;
    user.countryCode = data.countryCode || 'TN';
    user.domainActivity = data.domainActivity || null;
    user.pack = data.pack || 'basic';
    user.createdAt = new Date();
    user.updatedAt = new Date();

    const savedUser = await this.userRepo.save(user);

    // Sauvegarde des besoins si fournis
    if (data.needs && Array.isArray(data.needs) && data.needs.length > 0) {
      const needsEntities = data.needs.map((type: string) => {
        const need = new UserNeeds();
        need.type = type;
        need.user = savedUser;
        return need;
      });
      await this.needsRepo.save(needsEntities);
    }

    // Sauvegarde du rendez-vous si fourni
    if (data.appointmentDate || data.messageToExpert) {
      const appointment = new Appointment();
      appointment.date = data.appointmentDate
        ? new Date(data.appointmentDate)
        : null;
      appointment.message = data.messageToExpert || null;
      appointment.user = savedUser;
      await this.appointmentRepo.save(appointment);
    }

    return savedUser;
  }

  /**
   * Crée une identité dans Kratos
   */
  private async createKratosIdentity(data: SignupDto): Promise<any> {
    try {
      // Initialisation du flow de registration
      const flow = await this.initRegistrationFlow();

      // Préparation du body pour la soumission
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

      // Soumission du formulaire de registration
      const response = await this.kratosPublicApi.updateRegistrationFlow({
        flow: flow.id,
        updateRegistrationFlowBody: submitBody,
      });

      return response.data.identity;
    } catch (error) {
      this.logger.error('Kratos identity creation failed:', error);
      throw error;
    }
  }

  // ===========================
  // LOGIN
  // ===========================

  /**
   * Connexion d'un utilisateur avec Kratos + fallback DB
   */
  async login(credentials: LoginDto): Promise<any> {
    const { email, password } = credentials;

    if (!email || !password) {
      throw new BadRequestException('Email and password are required');
    }

    this.logger.log(`Login attempt for email: ${email}`);

    try {
      // 1. Tentative de connexion via Kratos
      const kratosResult = await this.loginWithKratos(email, password);

      // 2. Récupération des données utilisateur depuis notre DB
      let localUser = await this.userRepo.findOne({
        where: { email },
        relations: ['needs', 'appointments'],
      });

      // 3. Si l'utilisateur n'existe pas dans notre DB, le synchroniser
      if (!localUser) {
        this.logger.log(
          `User ${email} not found in local DB, syncing from Kratos`,
        );
        localUser = await this.syncUserByEmail(email);
      }

      return {
        message: 'Login successful via Kratos',
        session: kratosResult.session,
        sessionToken: kratosResult.session_token,
        user: localUser,
        method: 'kratos',
      };
    } catch (kratosError) {
      this.logger.warn(
        `Kratos login failed for ${email}:`,
        kratosError.message,
      );

      // Fallback: connexion via DB locale uniquement
      return await this.loginWithDatabase(email, password);
    }
  }

  /**
   * Connexion via Kratos
   */
  private async loginWithKratos(email: string, password: string): Promise<any> {
    try {
      // Initialisation du flow de login
      const flow = await this.initLoginFlow();

      // Préparation du body pour la soumission
      const submitBody: UpdateLoginFlowBody = {
        method: 'password',
        identifier: email,
        password,
      };

      // Soumission des credentials
      const response = await this.kratosPublicApi.updateLoginFlow({
        flow: flow.id,
        updateLoginFlowBody: submitBody,
      });

      return response.data;
    } catch (error) {
      this.logger.error('Kratos login error:', error);
      throw new UnauthorizedException(
        'Invalid credentials or Kratos unavailable',
      );
    }
  }

  /**
   * Connexion fallback via base de données locale
   */
  private async loginWithDatabase(
    email: string,
    password: string,
  ): Promise<any> {
    const user = await this.userRepo.findOne({
      where: { email },
      relations: ['needs', 'appointments'],
    });

    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid email or password');
    }

    // Mise à jour de la dernière connexion
    user.lastLogin = new Date();
    await this.userRepo.save(user);

    // Génération d'un token simple pour le fallback
    const sessionToken = Buffer.from(`${user.id}:${Date.now()}`).toString(
      'base64',
    );

    return {
      message: 'Login successful via database fallback',
      user,
      sessionToken,
      method: 'database',
    };
  }

  // ===========================
  // VERIFICATION
  // ===========================

  /**
   * Soumet un code de vérification
   */
  /**
   * Soumet un code de vérification
   */
  async submitVerification(data: SubmitVerificationDto): Promise<any> {
    try {
      if (!data.flowId || !data.code) {
        throw new BadRequestException(
          'Flow ID and verification code are required',
        );
      }

      this.logger.log(`Submitting verification code for flow: ${data.flowId}`);

      // Define local interface if UpdateVerificationFlowWithCodeMethodBody is unavailable
      interface UpdateVerificationFlowWithCodeMethodBody {
        method: 'code';
        code: string;
      }

      const submitBody = {
        method: 'code',
        code: data.code,
      } as UpdateVerificationFlowWithCodeMethodBody;

      const response = await this.kratosPublicApi.updateVerificationFlow({
        flow: data.flowId,
        updateVerificationFlowBody:
          submitBody as unknown as UpdateVerificationFlowBody,
      });
      // Mettre à jour le statut de vérification dans la DB locale
      const flow = await this.kratosPublicApi.getVerificationFlow({
        id: data.flowId,
      });
      const emailNode = flow.data.ui?.nodes?.find(
        (node) => (node.attributes as UiNodeInputAttributes)?.name === 'email',
      )?.attributes as UiNodeInputAttributes | undefined;

      const email = emailNode?.value;

      if (email) {
        const user = await this.userRepo.findOne({ where: { email } });
        if (user) {
          user.emailVerified = true;
          user.emailVerifiedAt = new Date();
          await this.userRepo.save(user);
        }
      }

      return {
        message: 'Email verified successfully',
        data: response.data,
      };
    } catch (error) {
      this.logger.error('Verification submission failed:', error.message);
      throw new BadRequestException(
        error.response?.data?.ui?.messages?.[0]?.text ||
          error.message ||
          'Failed to verify email',
      );
    }
  }

  // ===========================
  // RECOVERY
  // ===========================

  /**
   * Lance un flux de récupération pour un email
   */
  async initiateRecovery(data: RecoveryDto): Promise<any> {
    try {
      if (!data.email) {
        throw new BadRequestException('Email is required');
      }

      this.logger.log(`Starting recovery process for email: ${data.email}`);

      const flow = await this.initRecoveryFlow(
        'http://localhost:4455/recovery',
      );

      // Préparation du body pour la soumission
      const submitBody: UpdateRecoveryFlowBody = {
        method: 'code',
        email: data.email,
      };

      const response = await this.kratosPublicApi.updateRecoveryFlow({
        flow: flow.id,
        updateRecoveryFlowBody: submitBody,
      });

      return {
        message: 'Recovery email sent successfully',
        flowId: flow.id,
        email: data.email, // Store email for use in submitRecovery
        data: response.data,
      };
    } catch (error) {
      this.logger.error('Recovery initiation failed:', error.message);
      throw new BadRequestException(
        error.response?.data?.ui?.messages?.[0]?.text ||
          error.message ||
          'Failed to initiate recovery',
      );
    }
  }

  /**
   * Soumet un code de récupération et met à jour le mot de passe localement
   */
  async submitRecovery(data: SubmitRecoveryDto): Promise<any> {
    try {
      if (!data.flowId || !data.code) {
        throw new BadRequestException('Flow ID and recovery code are required');
      }

      this.logger.log(`Submitting recovery code for flow: ${data.flowId}`);

      // Submit the recovery code
      const submitBody: UpdateRecoveryFlowBody = {
        method: 'code',
        code: data.code,
      };

      const response = await this.kratosPublicApi.updateRecoveryFlow({
        flow: data.flowId,
        updateRecoveryFlowBody: submitBody,
      });

      // If a new password is provided, update it in the local database
      if (data.password) {
        // Fetch the recovery flow to get the email
        const flow = await this.kratosPublicApi.getRecoveryFlow({
          id: data.flowId,
        });
        const emailNode = flow.data.ui?.nodes?.find(
          (node) =>
            (node.attributes as UiNodeInputAttributes)?.name === 'email',
        )?.attributes as UiNodeInputAttributes | undefined;

        const email = emailNode?.value;

        if (!email) {
          throw new BadRequestException(
            'Could not retrieve email from recovery flow',
          );
        }

        const user = await this.userRepo.findOne({
          where: { email },
        });
        if (user) {
          user.password = await bcrypt.hash(data.password, 12);
          user.updatedAt = new Date();
          await this.userRepo.save(user);

          // Update password in Kratos if user has a Kratos identity
          if (user.kratosIdentityId) {
            try {
              await this.kratosAdminApi.updateIdentity({
                id: user.kratosIdentityId,
                updateIdentityBody: {
                  schema_id: 'default',
                  traits: (await this.getKratosIdentity(user.kratosIdentityId))
                    .traits,
                  state: IdentityState.Active,
                  credentials: {
                    password: {
                      config: {
                        password: data.password,
                      },
                    },
                  },
                },
              });
              this.logger.log(
                `Updated Kratos identity password for user ${email}`,
              );
            } catch (error) {
              this.logger.warn(
                `Failed to update Kratos identity password for user ${email}:`,
                error.message,
              );
            }
          }
        }
      }

      return {
        message: 'Account recovery successful',
        data: response.data,
      };
    } catch (error) {
      this.logger.error('Recovery submission failed:', error.message);
      throw new BadRequestException(
        error.response?.data?.ui?.messages?.[0]?.text ||
          error.message ||
          'Failed to recover account',
      );
    }
  }

  // ===========================
  // SESSION MANAGEMENT
  // ===========================

  /**
   * Vérification d'une session Kratos
   */
  async validateSession(sessionToken: string): Promise<Session> {
    try {
      const response = await this.kratosPublicApi.toSession({
        cookie: `ory_kratos_session=${sessionToken}`,
      });

      return response.data;
    } catch (error) {
      this.logger.error('Session validation failed:', error.message);
      throw new UnauthorizedException('Invalid or expired session');
    }
  }

  /**
   * Récupération d'une session à partir du cookie
   */
  async getSession(cookie: string): Promise<Session> {
    try {
      const response = await this.kratosPublicApi.toSession({ cookie });
      return response.data;
    } catch (error) {
      this.logger.error('Failed to get session:', error.message);
      throw new UnauthorizedException('Unable to verify session');
    }
  }

  /**
   * Récupération du profil utilisateur complet
   */
  async getUserProfile(sessionOrEmail: string | Session): Promise<User | null> {
    let email: string;

    if (typeof sessionOrEmail === 'string') {
      email = sessionOrEmail;
    } else {
      email = (sessionOrEmail.identity?.traits as any)?.email;
    }

    if (!email) {
      return null;
    }

    let user = await this.userRepo.findOne({
      where: { email },
      relations: ['needs', 'appointments'],
    });

    // Si l'utilisateur n'existe pas dans la DB locale, tenter de le synchroniser
    if (!user) {
      try {
        user = await this.syncUserByEmail(email);
      } catch (error) {
        this.logger.warn(`Failed to sync user ${email}:`, error.message);
      }
    }

    return user;
  }

  // ===========================
  // LOGOUT
  // ===========================

  /**
   * Déconnexion de l'utilisateur
   */
  async logout(sessionToken?: string): Promise<any> {
    if (!sessionToken) {
      return { message: 'Logout successful (no session to invalidate)' };
    }

    try {
      // Tentative de déconnexion via Kratos
      const logoutFlow = await this.kratosPublicApi.createBrowserLogoutFlow({
        cookie: `ory_kratos_session=${sessionToken}`,
      });

      await this.kratosPublicApi.updateLogoutFlow({
        token: logoutFlow.data.logout_token,
      });

      return { message: 'Logout successful via Kratos' };
    } catch (error) {
      this.logger.warn('Kratos logout failed:', error.message);
      return { message: 'Logout successful (Kratos unavailable)' };
    }
  }

  // ===========================
  // USER MANAGEMENT
  // ===========================

  /**
   * Mise à jour du profil utilisateur
   */
  async updateProfile(
    userId: number,
    updateData: Partial<SignupDto>,
  ): Promise<User> {
    const user = await this.userRepo.findOne({
      where: { id: userId },
      relations: ['needs', 'appointments'],
    });

    if (!user) {
      throw new BadRequestException('User not found');
    }

    // Mise à jour des champs de base
    if (updateData.firstName) user.firstName = updateData.firstName;
    if (updateData.lastName) user.lastName = updateData.lastName;
    if (updateData.phone) user.phone = updateData.phone;
    if (updateData.countryCode) user.countryCode = updateData.countryCode;
    if (updateData.domainActivity)
      user.domainActivity = updateData.domainActivity;
    if (updateData.pack) user.pack = updateData.pack;
    if (updateData.birthDate) user.birthDate = new Date(updateData.birthDate);

    // Mise à jour du mot de passe si fourni
    if (updateData.password) {
      user.password = await bcrypt.hash(updateData.password, 12);
    }

    user.updatedAt = new Date();
    const updatedUser = await this.userRepo.save(user);

    // Mise à jour des besoins si fournis
    if (updateData.needs) {
      // Suppression des anciens besoins
      await this.needsRepo.delete({ user: { id: userId } });

      // Création des nouveaux besoins
      if (updateData.needs.length > 0) {
        const needsEntities = updateData.needs.map((type: string) => {
          const need = new UserNeeds();
          need.type = type;
          need.user = updatedUser;
          return need;
        });
        await this.needsRepo.save(needsEntities);
      }
    }

    // Mise à jour de l'identité Kratos si elle existe
    if (user.kratosIdentityId) {
      try {
        await this.updateKratosIdentity(user.kratosIdentityId, {
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          phone: user.phone,
          birthDate: user.birthDate.toISOString().split('T')[0],
          cinNumber: user.cinNumber,
          countryCode: user.countryCode,
          domainActivity: user.domainActivity,
          pack: user.pack,
        });
      } catch (error) {
        this.logger.warn(
          `Failed to update Kratos identity for user ${userId}:`,
          error.message,
        );
      }
    }

    return await this.userRepo.findOne({
      where: { id: userId },
      relations: ['needs', 'appointments'],
    });
  }

  /**
   * Suppression d'un utilisateur
   */
  async deleteUser(userId: number): Promise<void> {
    const user = await this.userRepo.findOne({ where: { id: userId } });

    if (!user) {
      throw new BadRequestException('User not found');
    }

    // Suppression de l'identité Kratos si elle existe
    if (user.kratosIdentityId) {
      try {
        await this.deleteKratosIdentity(user.kratosIdentityId);
      } catch (error) {
        this.logger.warn(
          `Failed to delete Kratos identity for user ${userId}:`,
          error.message,
        );
      }
    }

    // Suppression des relations
    await this.needsRepo.delete({ user: { id: userId } });
    await this.appointmentRepo.delete({ user: { id: userId } });

    // Suppression de l'utilisateur
    await this.userRepo.delete(userId);

    this.logger.log(`User ${userId} deleted successfully`);
  }

  // ===========================
  // UTILITY METHODS
  // ===========================

  /**
   * Vérification de la disponibilité de Kratos
   */
  async isKratosAvailable(): Promise<boolean> {
    try {
      await axios.get(`${this.kratosPublicUrl}/health/ready`, {
        timeout: 5000,
      });
      return true;
    } catch (error) {
      this.logger.warn('Kratos health check failed:', error.message);
      return false;
    }
  }

  /**
   * Récupération des statistiques d'authentification
   */
  async getAuthStats(): Promise<any> {
    const totalUsers = await this.userRepo.count();
    const verifiedUsers = await this.userRepo.count({
      where: { emailVerified: true },
    });
    const kratosAvailable = await this.isKratosAvailable();

    // Récupération du nombre d'identités Kratos
    let kratosIdentities = 0;
    try {
      const response = await this.kratosAdminApi.listIdentities({
        perPage: 1,
        page: 1,
      });
      kratosIdentities = parseInt(response.headers['x-total-count']) || 0;
    } catch (error) {
      this.logger.warn('Failed to get Kratos identities count:', error.message);
    }

    return {
      totalUsers,
      verifiedUsers,
      kratosIdentities,
      kratosAvailable,
      kratosUrl: this.kratosPublicUrl,
      lastSync: new Date().toISOString(),
    };
  }

  /**
   * Récupération de tous les utilisateurs avec pagination
   */
  async getAllUsers(
    page = 1,
    limit = 10,
  ): Promise<{
    users: User[];
    total: number;
    page: number;
    totalPages: number;
  }> {
    const [users, total] = await this.userRepo.findAndCount({
      relations: ['needs', 'appointments'],
      skip: (page - 1) * limit,
      take: limit,
      order: { createdAt: 'DESC' },
    });

    return {
      users,
      total,
      page,
      totalPages: Math.ceil(total / limit),
    };
  }

  /**
   * Recherche d'utilisateurs par email ou nom
   */
  async searchUsers(
    query: string,
    page = 1,
    limit = 10,
  ): Promise<{ users: User[]; total: number }> {
    const [users, total] = await this.userRepo.findAndCount({
      where: [
        { email: Like(`%${query}%`) },
        { firstName: Like(`%${query}%`) },
        { lastName: Like(`%${query}%`) },
      ],
      relations: ['needs', 'appointments'],
      skip: (page - 1) * limit,
      take: limit,
      order: { createdAt: 'DESC' },
    });

    return { users, total };
  }

  // ===========================
  // ADDITIONAL KRATOS METHODS
  // ===========================

  /**
   * Récupération d'une identité par ID depuis Kratos
   */
  async getKratosIdentity(identityId: string): Promise<any> {
    try {
      const response = await this.kratosAdminApi.getIdentity({
        id: identityId,
      });
      return response.data;
    } catch (error) {
      this.logger.error('Failed to get Kratos identity:', error.message);
      throw new BadRequestException('Identity not found');
    }
  }

  /**
   * Récupération d'une identité Kratos par email
   */
  async getKratosIdentityByEmail(email: string): Promise<any> {
    try {
      const identities = await this.kratosAdminApi.listIdentities({
        perPage: 100,
        page: 1,
      });
      const identity = identities.data.find(
        (id) => (id.traits as any).email === email,
      );

      if (!identity) {
        throw new NotFoundException(`Identity with email ${email} not found`);
      }

      return identity;
    } catch (error) {
      this.logger.error(
        'Failed to get Kratos identity by email:',
        error.message,
      );
      throw new BadRequestException('Failed to get identity by email');
    }
  }

  /**
   * Mise à jour d'une identité Kratos
   */
  async updateKratosIdentity(identityId: string, traits: any): Promise<any> {
    try {
      const response = await this.kratosAdminApi.updateIdentity({
        id: identityId,
        updateIdentityBody: {
          schema_id: 'default',
          traits,
          state: IdentityState.Active,
        },
      });
      return response.data;
    } catch (error) {
      this.logger.error('Failed to update Kratos identity:', error.message);
      throw new BadRequestException('Failed to update identity');
    }
  }

  /**
   * Suppression d'une identité Kratos
   */
  async deleteKratosIdentity(identityId: string): Promise<void> {
    try {
      await this.kratosAdminApi.deleteIdentity({ id: identityId });
      this.logger.log(`Kratos identity ${identityId} deleted successfully`);
    } catch (error) {
      this.logger.error('Failed to delete Kratos identity:', error.message);
      throw new BadRequestException('Failed to delete identity');
    }
  }

  /**
   * Liste de toutes les identités Kratos avec pagination
   */
  async listKratosIdentities(page = 1, limit = 100): Promise<any> {
    try {
      const response = await this.kratosAdminApi.listIdentities({
        perPage: limit,
        page,
      });
      return {
        identities: response.data,
        total: parseInt(response.headers['x-total-count']) || 0,
        page,
        limit,
      };
    } catch (error) {
      this.logger.error('Failed to list Kratos identities:', error.message);
      throw new BadRequestException('Failed to list identities');
    }
  }

  /**
   * Création manuelle d'une identité Kratos
   */
  async createKratosIdentityManual(
    traits: any,
    password?: string,
  ): Promise<any> {
    try {
      const identityPayload: CreateIdentityBody = {
        schema_id: 'default',
        traits,
        state: IdentityState.Active,
      };

      if (password) {
        identityPayload.credentials = {
          password: {
            config: {
              password,
            },
          },
        };
      }

      const response = await this.kratosAdminApi.createIdentity({
        createIdentityBody: identityPayload,
      });
      return response.data;
    } catch (error) {
      this.logger.error(
        'Failed to create Kratos identity manually:',
        error.message,
      );
      throw new BadRequestException('Failed to create identity');
    }
  }

  // ===========================
  // MAINTENANCE & MONITORING
  // ===========================

  /**
   * Nettoyage des sessions expirées
   */
  async cleanupExpiredSessions(): Promise<{ cleaned: number }> {
    try {
      // Kratos gère automatiquement le nettoyage des sessions
      // Ici on peut nettoyer nos propres données si nécessaire
      this.logger.log('Session cleanup completed');
      return { cleaned: 0 };
    } catch (error) {
      this.logger.error('Session cleanup failed:', error.message);
      throw new BadRequestException('Session cleanup failed');
    }
  }

  /**
   * Rapport de santé complet du système d'authentification
   */
  async getHealthReport(): Promise<any> {
    const kratosAvailable = await this.isKratosAvailable();
    const stats = await this.getAuthStats();

    const report = {
      timestamp: new Date().toISOString(),
      services: {
        kratos: {
          available: kratosAvailable,
          publicUrl: this.kratosPublicUrl,
          adminUrl: this.kratosAdminUrl,
        },
        database: {
          available: true, // On peut ajouter une vraie vérification ici
          totalUsers: stats.totalUsers,
          verifiedUsers: stats.verifiedUsers,
        },
      },
      synchronization: {
        kratosIdentities: stats.kratosIdentities,
        localUsers: stats.totalUsers,
        syncNeeded: stats.kratosIdentities !== stats.totalUsers,
      },
      status: kratosAvailable ? 'healthy' : 'degraded',
    };

    return report;
  }
  // Ajoutez ces nouvelles méthodes à votre AuthService existant

  // ===========================
  // WEBHOOK HANDLERS AMÉLIORÉS
  // ===========================

  // Ajoutez ces méthodes manquantes à votre AuthService

  /**
   * Mise à jour de la dernière connexion lors du login - version améliorée
   */
  private async handleLoginWebhookImproved(identity: Identity): Promise<void> {
    const traits = identity.traits as any;

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
        // Si l'utilisateur n'existe pas dans la DB locale, le créer
        await this.handleRegistrationWebhookImproved(identity);
      }
    } catch (error) {
      this.logger.error(
        `Failed to update login for user ${traits.email}:`,
        error.message,
      );
      throw error;
    }
  }

  /**
   * Met à jour le statut de vérification de l'email - version améliorée
   */
  private async handleVerificationWebhookImproved(
    identity: Identity,
  ): Promise<void> {
    const traits = identity.traits as any;

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
        // Si l'utilisateur n'existe pas, le créer d'abord
        await this.handleRegistrationWebhookImproved(identity);

        // Puis marquer comme vérifié
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

  /**
   * Correction de la méthode handleRegistrationWebhookImproved
   */
  private async handleRegistrationWebhookImproved(
    identity: Identity,
  ): Promise<void> {
    const traits = identity.traits as any;

    this.logger.log(`Processing registration webhook for: ${traits.email}`);

    try {
      // Transaction pour assurer la cohérence
      await this.userRepo.manager.transaction(
        async (transactionalEntityManager) => {
          // Vérifier si l'utilisateur existe déjà
          const existingUser = await transactionalEntityManager.findOne(User, {
            where: { email: traits.email },
          });

          if (existingUser) {
            // Mise à jour de l'utilisateur existant avec l'ID Kratos
            existingUser.kratosIdentityId = identity.id;
            existingUser.updatedAt = new Date();
            await transactionalEntityManager.save(existingUser);
            this.logger.log(
              `Updated existing user ${traits.email} with Kratos ID`,
            );
            return;
          }

          // Création d'un nouvel utilisateur
          const user = new User();
          user.email = traits.email;
          user.firstName = traits.firstName;
          user.lastName = traits.lastName;
          user.phone = traits.phone;
          user.birthDate = new Date(traits.birthDate);
          user.cinNumber = traits.cinNumber;
          user.countryCode = traits.countryCode || 'TN';
          user.domainActivity = traits.domainActivity || null;
          user.pack = traits.pack || 'basic';
          user.kratosIdentityId = identity.id;
          user.password = await bcrypt.hash('kratos-managed', 12);
          user.createdAt = new Date();
          user.updatedAt = new Date();

          await transactionalEntityManager.save(user);
          this.logger.log(
            `Created new user ${traits.email} from Kratos webhook`,
          );
        },
      );
    } catch (error) {
      this.logger.error(
        `Failed to sync user ${traits.email} from webhook:`,
        error.message,
      );
      throw error;
    }
  }
  /**
   * Synchronisation automatique périodique
   */
  async performPeriodicSync(): Promise<{
    synced: number;
    errors: number;
    skipped: number;
  }> {
    this.logger.log('Starting periodic sync of Kratos identities');

    let synced = 0;
    let errors = 0;
    let skipped = 0;
    let page = 1;
    const perPage = 50;

    try {
      while (true) {
        const response = await this.kratosAdminApi.listIdentities({
          perPage,
          page,
        });

        const identities = response.data;
        if (!identities || identities.length === 0) {
          break;
        }

        for (const identity of identities) {
          try {
            const traits = identity.traits as any;

            // Vérifier si l'utilisateur existe dans la DB locale
            const existingUser = await this.userRepo.findOne({
              where: { email: traits.email },
            });

            if (existingUser) {
              // Mettre à jour l'ID Kratos si nécessaire
              if (!existingUser.kratosIdentityId) {
                existingUser.kratosIdentityId = identity.id;
                await this.userRepo.save(existingUser);
                synced++;
              } else {
                skipped++;
              }
            } else {
              // Créer l'utilisateur
              await this.handleRegistrationWebhookImproved(identity);
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
      }

      this.logger.log(
        `Periodic sync completed: ${synced} synced, ${skipped} skipped, ${errors} errors`,
      );
      return { synced, errors, skipped };
    } catch (error) {
      this.logger.error('Failed to perform periodic sync:', error.message);
      throw new BadRequestException('Failed to perform sync');
    }
  }

  /**
   * Synchronisation bidirectionnelle - de la DB locale vers Kratos
   */
  async syncLocalUsersToKratos(): Promise<{ synced: number; errors: number }> {
    this.logger.log('Starting sync of local users to Kratos');

    let synced = 0;
    let errors = 0;

    try {
      // Récupérer tous les utilisateurs sans ID Kratos
      const localUsers = await this.userRepo.find({
        where: { kratosIdentityId: null },
      });

      for (const user of localUsers) {
        try {
          // Vérifier si l'utilisateur existe déjà dans Kratos
          const kratosIdentity = await this.getKratosIdentityByEmailSafe(
            user.email,
          );

          if (kratosIdentity) {
            // Lier l'utilisateur existant
            user.kratosIdentityId = kratosIdentity.id;
            await this.userRepo.save(user);
            synced++;
          } else {
            // Créer l'identité dans Kratos
            const newIdentity = await this.createKratosIdentityManual({
              email: user.email,
              firstName: user.firstName,
              lastName: user.lastName,
              phone: user.phone,
              birthDate: user.birthDate.toISOString().split('T')[0],
              cinNumber: user.cinNumber,
              countryCode: user.countryCode,
              domainActivity: user.domainActivity,
              pack: user.pack,
            });

            user.kratosIdentityId = newIdentity.id;
            await this.userRepo.save(user);
            synced++;
          }
        } catch (error) {
          this.logger.error(
            `Failed to sync local user ${user.email}:`,
            error.message,
          );
          errors++;
        }
      }

      this.logger.log(
        `Local to Kratos sync completed: ${synced} synced, ${errors} errors`,
      );
      return { synced, errors };
    } catch (error) {
      this.logger.error('Failed to sync local users to Kratos:', error.message);
      throw new BadRequestException('Failed to sync local users');
    }
  }

  /**
   * Version sécurisée de getKratosIdentityByEmail
   */
  private async getKratosIdentityByEmailSafe(
    email: string,
  ): Promise<any | null> {
    try {
      const identities = await this.kratosAdminApi.listIdentities({
        perPage: 100,
        page: 1,
      });

      const identity = identities.data.find(
        (id) => (id.traits as any).email === email,
      );

      return identity || null;
    } catch (error) {
      this.logger.warn(
        `Failed to get Kratos identity for ${email}:`,
        error.message,
      );
      return null;
    }
  }

  /**
   * Synchronisation complète dans les deux sens
   */
  async performFullSync(): Promise<{
    kratosToLocal: { synced: number; errors: number; skipped: number };
    localToKratos: { synced: number; errors: number };
  }> {
    this.logger.log('Starting full bidirectional sync');

    const kratosToLocal = await this.performPeriodicSync();
    const localToKratos = await this.syncLocalUsersToKratos();

    return {
      kratosToLocal,
      localToKratos,
    };
  }

  /**
   * Tâche de synchronisation programmée (à appeler via un cron job)
   */
  async scheduledSyncTask(): Promise<void> {
    try {
      this.logger.log('Running scheduled sync task');
      await this.performPeriodicSync();
    } catch (error) {
      this.logger.error('Scheduled sync task failed:', error.message);
    }
  }
}
