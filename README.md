---

# NestJS + Prisma

## Installation

```bash
npm install
```

## Environment Setup

Remove .local from `.env` files and fill the values.


## Prisma Commands

Generate Prisma Client:

```bash
npx prisma generate
```

Create or update the database schema:

```bash
npx prisma db push
```

Run migrations (if using migrations):

```bash
npx prisma migrate dev
```

Open Prisma Studio:

```bash
npx prisma studio
```

---

## Run the Server

### Development

```bash
npm run start:dev
```

### Production Build

```bash
npm run build
npm run start:prod
```

---