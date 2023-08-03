import { DataSource, DataSourceOptions } from 'typeorm';
import { config } from 'dotenv';
import { ConfigService } from '@nestjs/config';
import { User } from './user/entities/user.entity';

config();

const configService = new ConfigService();

export const dataSourceOptions: DataSourceOptions = {
  type: 'mysql',
  host: configService.get('MYSQL_HOST'),
  port: 3306,
  username: configService.get('MYSQL_USER'),
  password: configService.get('MYSQL_PASS'),
  database: configService.get('MYSQL_DB'),
  logging: false,
  entities: [User],
  migrationsTableName: 'migrations',
  migrations: ['dist/migration/*.js'],
  subscribers: [],
};

const dataSource = new DataSource(dataSourceOptions);

export default dataSource;
