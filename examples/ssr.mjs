import {createClient} from '../dist/index.js'

// Call separately for each HTTP request. Adapter is backed by a protected server
// session store identified by a secure session cookie; it contains no global user.
export async function loadNotesForRequest(requestSession, config) {
  const storage = {
    getItem: key => requestSession.read(key),
    setItem: (key,value) => requestSession.write(key,value),
    removeItem: key => requestSession.remove(key),
  }
  const client=createClient({...config,storage,autoRefresh:false})
  try {
    const user=await client.auth.getUser()
    const {data}=await client.from('notes').select('id,title').eq('owner_id',user.id).execute()
    return {user:{id:user.id},notes:data} // never render token/session data
  } finally {client.dispose()}
}
