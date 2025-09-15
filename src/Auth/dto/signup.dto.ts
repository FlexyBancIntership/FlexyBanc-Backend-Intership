export class SignupDto {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  phone: string;
  birthDate: string;
  cinNumber: string;
  cinScan?: any; // fichier image
  country?: string;
  domainActivity?: string;
  pack?: string;
  needs?: string[]; // epargne, investissement...
  messageToExpert?: string;
  appointmentDate?: string;
}
