import { Entity, Column, PrimaryGeneratedColumn, ManyToOne } from 'typeorm';
import { User } from './user.entity';

@Entity({ name: 'appointments' })
export class Appointment {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  date: Date;

  @Column()
  message: string;

  @ManyToOne(() => User, (user) => user.appointments)
  user: User;
}
