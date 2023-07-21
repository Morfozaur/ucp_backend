import { Column, Entity, Index, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index('email_index')
  @Column({ unique: true })
  email: string;

  @Column()
  username: string;

  @Column()
  password: string;

  @Column({ type: 'simple-array', nullable: true })
  role: string[];

  @Column({ type: 'simple-array', nullable: true })
  tokens: string[];
}
