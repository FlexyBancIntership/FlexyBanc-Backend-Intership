import { Entity, Column, PrimaryGeneratedColumn, ManyToOne } from 'typeorm';
import { User } from './user.entity';

@Entity({ name: 'user_needs' })
export class UserNeeds {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  type: string; // epargne, investissement, paiement, transfert, budgétisation, crédit

  @ManyToOne(() => User, (user) => user.needs)
  user: User;
}
