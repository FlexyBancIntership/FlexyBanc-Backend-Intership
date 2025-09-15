import { Entity, Column, PrimaryGeneratedColumn, OneToMany } from 'typeorm';
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

  @Column()
  phone: string;

  @Column()
  password: string;

  @Column()
  birthDate: Date;

  @Column()
  cinNumber: string;

  @Column({ nullable: true })
  country: string;

  @Column({ nullable: true })
  domainActivity: string;

  @Column({ nullable: true })
  pack: string; // gratuit / pro / basic / entreprise

  @OneToMany(() => UserNeeds, (need) => need.user)
  needs: UserNeeds[];

  @OneToMany(() => Appointment, (appointment) => appointment.user)
  appointments: Appointment[];
}
