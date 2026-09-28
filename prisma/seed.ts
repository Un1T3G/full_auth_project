import { PrismaClient, Role } from '@prisma/client';
import * as argon2 from 'argon2';

const prisma = new PrismaClient();

async function main() {
  const adminEmail = 'admin@example.com';
  const existingAdmin = await prisma.user.findUnique({
    where: { email: adminEmail },
  });

  if (!existingAdmin) {
    const passwordHash = await argon2.hash('AdminPassword123!', {
      type: argon2.argon2id,
      memoryCost: 2 ** 16,
      timeCost: 3,
      parallelism: 1,
    });

    const admin = await prisma.user.create({
      data: {
        email: adminEmail,
        name: 'Super Admin',
        role: Role.ADMIN,
        passwordHash,
        emailVerified: new Date(),
        isMfaEnabled: false,
      },
    });

    console.log(`Created seed admin user: ${admin.email} (password: AdminPassword123!)`);
  } else {
    console.log(`Admin user already exists: ${adminEmail}`);
  }
}

main()
  .catch((e) => {
    console.error('Seed error:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
