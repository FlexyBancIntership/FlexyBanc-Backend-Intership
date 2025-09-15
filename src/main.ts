import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const port = process.env.PORT ?? 3000;

  // Écoute sur toutes les interfaces réseau pour Docker
  await app.listen(port, '0.0.0.0');

  console.log(`🚀 Backend is running on http://0.0.0.0:${port}`);
}
bootstrap();
