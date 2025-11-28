export default () => ({
  app: {
    name: process.env.APP_NAME || 'Nest App',
    environment: process.env.NODE_ENV || 'development',
    port: parseInt(process.env.PORT || '3000', 10),
  },

  database: {
    url: process.env.DATABASE_URL,
  },

  // Example: add JWT or other future configs here
  jwt: {
    secret: process.env.JWT_SECRET || 'default_secret',
    expiresIn: process.env.JWT_EXPIRES_IN || '1d',
  },
});
