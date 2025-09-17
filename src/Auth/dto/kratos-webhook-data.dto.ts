import {
  IsString,
  IsObject,
  IsOptional,
  ValidateNested,
  IsEmail,
  IsDateString,
  IsEnum,
  IsBoolean,
  IsArray,
} from 'class-validator';
import { Type, Transform } from 'class-transformer';

// Enum for webhook event types
export enum KratosWebhookType {
  REGISTRATION = 'registration',
  LOGIN = 'login',
  VERIFICATION = 'verification',
  RECOVERY = 'recovery',
  SETTINGS = 'settings',
}

// Identity traits DTO
export class IdentityTraitsDto {
  @IsEmail()
  email: string;

  @IsString()
  firstName: string;

  @IsString()
  lastName: string;

  @IsString()
  phone: string;

  @IsDateString()
  birthDate: string;

  @IsString()
  cinNumber: string;

  @IsString()
  @IsOptional()
  countryCode?: string;

  @IsString()
  @IsOptional()
  domainActivity?: string;

  @IsString()
  @IsOptional()
  pack?: string;
}

// Identity state enum
export enum IdentityState {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
}

// Kratos Identity DTO
export class KratosIdentityDto {
  @IsString()
  id: string;

  @IsString()
  schema_id: string;

  @IsString()
  schema_url: string;

  @IsEnum(IdentityState)
  state: IdentityState;

  @ValidateNested()
  @Type(() => IdentityTraitsDto)
  traits: IdentityTraitsDto;

  @IsArray()
  @IsOptional()
  verifiable_addresses?: Array<{
    id: string;
    value: string;
    verified: boolean;
    via: string;
    status: string;
    created_at: string;
    updated_at: string;
  }>;

  @IsArray()
  @IsOptional()
  recovery_addresses?: Array<{
    id: string;
    value: string;
    via: string;
    created_at: string;
    updated_at: string;
  }>;

  @IsString()
  created_at: string;

  @IsString()
  updated_at: string;

  @IsObject()
  @IsOptional()
  credentials?: Record<string, any>;

  @IsObject()
  @IsOptional()
  metadata_admin?: Record<string, any>;

  @IsObject()
  @IsOptional()
  metadata_public?: Record<string, any>;
}

// Session DTO (for login webhooks)
export class KratosSessionDto {
  @IsString()
  id: string;

  @IsBoolean()
  active: boolean;

  @IsString()
  expires_at: string;

  @IsString()
  authenticated_at: string;

  @IsString()
  authenticator_assurance_level: string;

  @IsArray()
  authentication_methods: Array<{
    method: string;
    aal: string;
    completed_at: string;
  }>;

  @IsString()
  issued_at: string;

  @ValidateNested()
  @Type(() => KratosIdentityDto)
  identity: KratosIdentityDto;

  @IsObject()
  @IsOptional()
  devices?: Array<any>;
}

// Flow DTO (for registration/verification webhooks)
export class KratosFlowDto {
  @IsString()
  id: string;

  @IsString()
  type: string;

  @IsString()
  expires_at: string;

  @IsString()
  issued_at: string;

  @IsString()
  request_url: string;

  @IsBoolean()
  active: boolean;

  @IsObject()
  @IsOptional()
  ui?: Record<string, any>;

  @IsString()
  @IsOptional()
  return_to?: string;

  @IsString()
  state: string;
}

// Webhook data payload DTO
export class KratosWebhookDataDto {
  @ValidateNested()
  @Type(() => KratosIdentityDto)
  identity: KratosIdentityDto;

  @ValidateNested()
  @Type(() => KratosSessionDto)
  @IsOptional()
  session?: KratosSessionDto;

  @ValidateNested()
  @Type(() => KratosFlowDto)
  @IsOptional()
  flow?: KratosFlowDto;
}

// Main webhook DTO
export class KratosWebhookDto {
  @IsEnum(KratosWebhookType)
  @Transform(({ value }) => {
    // Handle different webhook type formats
    const typeMap: Record<string, KratosWebhookType> = {
      registration: KratosWebhookType.REGISTRATION,
      login: KratosWebhookType.LOGIN,
      verification: KratosWebhookType.VERIFICATION,
      recovery: KratosWebhookType.RECOVERY,
      settings: KratosWebhookType.SETTINGS,
    };
    return typeMap[value] || value;
  })
  type: KratosWebhookType;

  @ValidateNested()
  @Type(() => KratosWebhookDataDto)
  data: KratosWebhookDataDto;

  @IsString()
  @IsOptional()
  event_id?: string;

  @IsString()
  @IsOptional()
  timestamp?: string;
}

// Simplified DTO for internal use
export class ProcessedWebhookDataDto {
  @IsEnum(KratosWebhookType)
  type: KratosWebhookType;

  @IsString()
  identityId: string;

  @IsEmail()
  email: string;

  @IsString()
  firstName: string;

  @IsString()
  lastName: string;

  @IsString()
  phone: string;

  @IsDateString()
  birthDate: string;

  @IsString()
  cinNumber: string;

  @IsString()
  @IsOptional()
  countryCode?: string;

  @IsString()
  @IsOptional()
  domainActivity?: string;

  @IsString()
  @IsOptional()
  pack?: string;

  @IsBoolean()
  @IsOptional()
  isVerified?: boolean;

  @IsString()
  @IsOptional()
  sessionId?: string;

  @IsString()
  @IsOptional()
  flowId?: string;

  @IsString()
  createdAt: string;

  @IsString()
  updatedAt: string;
}

// Webhook response DTO
export class WebhookResponseDto {
  @IsString()
  status: 'success' | 'error';

  @IsString()
  message: string;

  @IsObject()
  @IsOptional()
  data?: Record<string, any>;

  @IsString()
  @IsOptional()
  error?: string;
}
