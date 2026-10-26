// STAYO_PUBLIC_KEY is public configuration; never use a service-role/provider key.
import {createClient} from '../dist/index.js'
const client=createClient({url:process.env.STAYO_URL,publicKey:process.env.STAYO_PUBLIC_KEY})
try {
  await client.auth.signInWithPassword({email:process.env.STAYO_EMAIL,password:process.env.STAYO_PASSWORD})
  const {data}=await client.from('notes').select('id,title').limit(10).execute()
  console.log(data)
} finally {client.dispose()}
