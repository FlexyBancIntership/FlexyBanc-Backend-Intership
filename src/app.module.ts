import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import config from './config/config';
import { AuthModule } from './auth/auth.module';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: config.database.host,
      port: config.database.port,
      username: config.database.username,
      password: config.database.password,
      database: config.database.database,
      autoLoadEntities: true, // charge automatiquement toutes les entités
      synchronize: true, // pour dev seulement, crée les tables automatiquement
    }),
    AuthModule,
  ],
})
export class AppModule {}
