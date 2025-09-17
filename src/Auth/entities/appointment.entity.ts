// appointment.entity.ts
import { Entity, Column, PrimaryGeneratedColumn, ManyToOne } from 'typeorm';
import { User } from './user.entity';

@Entity({ name: 'appointments' })
export class Appointment {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'timestamp', nullable: true })
  date: Date;

  @Column({ nullable: true })
  message: string; // ⚠️ ton service attend "message"

  @ManyToOne(() => User, (user) => user.appointments, { onDelete: 'CASCADE' })
  user: User;
}
