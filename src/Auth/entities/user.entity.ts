import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  OneToMany,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { UserNeeds } from './userNeeds.entity';
import { Appointment } from './appointment.entity';

@Entity({ name: 'users' })
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  email: string;

  @Column()
  firstName: string;

  @Column()
  lastName: string;

  @Column({ nullable: true })
  countryCode: string;

  @Column()
  phone: string;

  @Column()
  password: string;

  @Column()
  birthDate: Date;

  @Column()
  cinNumber: string;

  @Column({ nullable: true })
  domainActivity: string;

  @Column({ nullable: true })
  pack: string;

  // Nouvelles propriétés pour résoudre les erreurs
  @Column({ nullable: true })
  kratosIdentityId: string;

  @Column({ default: false })
  emailVerified: boolean;

  @Column({ type: 'timestamp', nullable: true })
  emailVerifiedAt: Date;

  @Column({ type: 'timestamp', nullable: true })
  lastLogin: Date;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @OneToMany(() => UserNeeds, (need) => need.user)
  needs: UserNeeds[];

  @OneToMany(() => Appointment, (appointment) => appointment.user)
  appointments: Appointment[];
}
