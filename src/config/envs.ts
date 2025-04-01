import 'dotenv/config';
import * as joi from 'joi';

interface EnvVars {
  PORT: number;
  NTAS_SERVERS: string[];
  JWT_SECRET:string;
}

const envsSchema = joi
  .object({
    PORT: joi.number().required(),
    NTAS_SERVERS: joi.array().items(joi.string()).required(),
    JWT_SECRET: joi.string().required(),
  })
  .unknown(true);

const { error, value } = envsSchema.validate({
  ...process.env,
  NTAS_SERVERS: process.env.NTAS_SERVERS?.split(','),
});
if (error) {
  throw new Error(`Config validation error ${error.message}`);
}

const envVars: EnvVars = value;

export const envs = {
  port: envVars.PORT,
  natsServers: envVars.NTAS_SERVERS,
  jwtSecret: envVars.JWT_SECRET,
};
