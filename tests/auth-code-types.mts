import {createClient} from '../dist/index.js';

// Compile only: these examples must work with the package's public declarations.
async function verifyEmailCodes(client: ReturnType<typeof createClient>) {
  await client.auth.verifyOtp({email: 'member@example.test', token: '123456', type: 'email'});
  await client.auth.verifyOtp({email: 'member@example.test', token: '123456', type: 'recovery'});
  await client.auth.verifyOtp({token_hash: 'synthetic-token-hash', type: 'email'});
  // @ts-expect-error Choose a code or a token hash, never both.
  await client.auth.verifyOtp({email: 'member@example.test', token: '123456', token_hash: 'synthetic', type: 'email'});
  // @ts-expect-error A code verification needs its email address.
  await client.auth.verifyOtp({token: '123456', type: 'email'});
  // @ts-expect-error A code verification needs its code.
  await client.auth.verifyOtp({email: 'member@example.test', type: 'email'});
}
void verifyEmailCodes;
