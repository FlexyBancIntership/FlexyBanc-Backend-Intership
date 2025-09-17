import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  IsDateString,
  Matches,
  Length,
  IsIn,
} from 'class-validator';

export class CreateUserDto {
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  firstName: string;

  @IsNotEmpty()
  @IsString()
  lastName: string;

  @IsOptional()
  @IsOptional()
  @IsIn([
    '+216',
    '+33',
    '+49',
    '+34',
    '+39',
    '+351',
    '+32',
    '+31',
    '+41',
    '+43',
  ])
  countryCode?: string;

  @IsNotEmpty()
  @Matches(/^[0-9]+$/, { message: 'Phone must contain only numbers' })
  @Length(6, 15)
  phone: string;

  @IsNotEmpty()
  @IsString()
  @Length(6, 20)
  password: string;

  @IsNotEmpty()
  @IsDateString()
  birthDate: string;

  @IsNotEmpty()
  @IsString()
  cinNumber: string;

  @IsOptional()
  @IsString()
  domainActivity?: string;

  @IsOptional()
  @IsIn(['gratuit', 'pro', 'basic', 'entreprise'])
  pack?: string;
}
