import { Injectable } from '@nestjs/common';
import { Configuration, V0alpha2Api, Session } from '@ory/kratos-client';
import axios from 'axios';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { UserNeeds } from './entities/userNeeds.entity';
import { Appointment } from './entities/appointment.entity';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  private kratos = new V0alpha2Api(
    new Configuration({ basePath: 'http://kratos:4433' }),
  );

  constructor(
    @InjectRepository(User)
    private userRepo: Repository<User>,
    @InjectRepository(UserNeeds)
    private needsRepo: Repository<UserNeeds>,
    @InjectRepository(Appointment)
    private appointmentRepo: Repository<Appointment>,
  ) {}

  // ===========================
  // Signup function
  // ===========================
  async signup(data: any): Promise<{ message: string; userId: number }> {
    // Hash the password
    const hashedPassword = await bcrypt.hash(data.password, 10);

    // Create User entity
    const user = new User();
    user.email = data.email;
    user.firstName = data.firstName;
    user.lastName = data.lastName;
    user.phone = data.phone;
    user.password = hashedPassword;
    user.birthDate = data.birthDate;
    user.cinNumber = data.cinNumber;
    user.country = data.country || null;
    user.domainActivity = data.domainActivity || null;
    user.pack = data.pack || null;

    const savedUser = await this.userRepo.save(user);

    // Save User Needs
    if (data.needs && data.needs.length) {
      const needsEntities: UserNeeds[] = data.needs.map((n: string) => {
        const need = new UserNeeds();
        need.type = n;
        need.user = savedUser;
        return need;
      });
      await this.needsRepo.save(needsEntities);
    }

    // Save Appointment
    if (data.appointmentDate || data.messageToExpert) {
      const appointment = new Appointment();
      appointment.date = data.appointmentDate;
      appointment.message = data.messageToExpert;
      appointment.user = savedUser;
      await this.appointmentRepo.save(appointment);
    }

    // Create user in Ory Kratos
    const flow =
      await this.kratos.initializeSelfServiceRegistrationFlowForBrowsers();
    await axios.post(
      flow.data.ui.action,
      {
        method: 'password',
        password: data.password,
        traits: {
          email: data.email,
          name: { first: data.firstName, last: data.lastName },
        },
      },
      { withCredentials: true },
    );

    return { message: 'User created', userId: savedUser.id };
  }

  // ===========================
  // Login function
  // ===========================
  async login(email: string, password: string) {
    const flow = await this.kratos.initializeSelfServiceLoginFlowForBrowsers();
    const response = await axios.post(
      flow.data.ui.action,
      { method: 'password', identifier: email, password },
      { withCredentials: true },
    );
    return response.data;
  }

  // ===========================
  // Verify session
  // ===========================
  async getSession(cookie: string): Promise<Session> {
    const response = await this.kratos.toSession(cookie);
    return response.data; // Session object only
  }

  // Logout user
  async logout(cookie: string): Promise<void> {
    await axios.delete('http://kratos:4433/sessions', {
      headers: { Cookie: cookie },
    });
  }
}
