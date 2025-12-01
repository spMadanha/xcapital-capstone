// create-admin.js
import 'dotenv/config';
import bcrypt from 'bcrypt';
import pkg from 'pg';
import { createInterface } from 'readline/promises';
import { stdin as input, stdout as output } from 'node:process';

const { Pool } = pkg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function main() {
  const rl = createInterface({ input, output });

  try {
    console.log('🛠 XCapital Admin Creator (Postgres)');
    console.log('----------------------------------');

    const email = (await rl.question('Admin email: ')).trim();
    if (!email) {
      console.error('❌ Email is required.');
      process.exit(1);
    }

    const password = (await rl.question('Admin password: ')).trim();
    if (!password || password.length < 8) {
      console.error('❌ Password must be at least 8 characters.');
      process.exit(1);
    }

    const roleInput = (await rl.question('Role (viewer/analyst/admin) [admin]: ')).trim();
    const role = roleInput || 'admin';

    if (!['viewer', 'analyst', 'admin'].includes(role)) {
      console.error('❌ Role must be one of: viewer, analyst, admin');
      process.exit(1);
    }

    console.log('\n🔎 Checking if user already exists...');
    const existing = await pool.query('SELECT id, email, role FROM users WHERE email = $1 LIMIT 1', [email]);

    if (existing.rows.length > 0) {
      console.log('⚠️  User already exists:');
      console.log(existing.rows[0]);
      process.exit(0);
    }

    console.log('🔐 Hashing password...');
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);

    console.log('💾 Inserting user into database...');
    const insert = await pool.query(
      'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id, email, role, created_at',
      [email, hash, role]
    );

    console.log('\n✅ Admin user created successfully:');
    console.log(insert.rows[0]);
    console.log('\nYou can now log in with:');
    console.log(`  email:    ${email}`);
    console.log(`  password: (the one you just entered)`);
    console.log(`  role:     ${role}`);
  } catch (err) {
    console.error('❌ Error creating admin user:', err.message || err);
  } finally {
    await pool.end();
    await rl.close();
    process.exit(0);
  }
}

main();
