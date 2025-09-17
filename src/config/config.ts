import { config } from 'dotenv';
config(); //.env

export default {
  database: {
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT, 10),
    username: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
  },
  kratos: {
    publicUrl: process.env.KRATOS_PUBLIC_URL,
    adminUrl: process.env.KRATOS_ADMIN_URL,
  },
};
