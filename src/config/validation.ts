/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */

import Joi, { ObjectSchema } from 'joi';

export const validationSchema: ObjectSchema<Record<string, unknown>> =
  Joi.object({
    NODE_ENV: Joi.string()
      .valid('development', 'production', 'test')
      .default('development'),

    APP_NAME: Joi.string().default('Nest App'),

    PORT: Joi.number().default(3000),

    DATABASE_URL: Joi.string().uri().required().messages({
      'string.empty': 'DATABASE_URL cannot be empty',
      'any.required': 'DATABASE_URL is required',
    }),

    JWT_SECRET: Joi.string().required().messages({
      'string.empty': 'JWT_SECRET cannot be empty',
      'any.required': 'JWT_SECRET is required',
    }),

    JWT_EXPIRES_IN: Joi.string().default('1d'),
  });
