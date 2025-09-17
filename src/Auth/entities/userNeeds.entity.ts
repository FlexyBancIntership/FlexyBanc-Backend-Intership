// userNeeds.entity.ts
import { Entity, Column, PrimaryGeneratedColumn, ManyToOne } from 'typeorm';
import { User } from './user.entity';

@Entity({ name: 'user_needs' })
export class UserNeeds {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  type: string; // ⚠️ doit être "type" pour matcher ton service

  @ManyToOne(() => User, (user) => user.needs, { onDelete: 'CASCADE' })
  user: User;
}
