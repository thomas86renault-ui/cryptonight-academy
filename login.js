// ╔══════════════════════════════════════════╗
// ║   NETLIFY FUNCTION — LOGIN API           ║
// ║   URL : /.netlify/functions/login        ║
// ╚══════════════════════════════════════════╝

const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

exports.handler = async (event) => {
  // CORS
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  let body;
  try {
    body = JSON.parse(event.body);
  } catch {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid JSON' }) };
  }

  const { email, password } = body;

  if (!email || !password) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Email et mot de passe requis' }) };
  }

  // Cherche l'utilisateur
  const { data: user, error } = await supabase
    .from('formation_users')
    .select('*')
    .eq('email', email.toLowerCase().trim())
    .single();

  if (error || !user) {
    return { statusCode: 401, headers, body: JSON.stringify({ error: 'Compte introuvable' }) };
  }

  if (user.status !== 'active') {
    return { statusCode: 403, headers, body: JSON.stringify({ error: 'Accès inactif — contacte le support' }) };
  }

  // Vérifie le mot de passe
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    return { statusCode: 401, headers, body: JSON.stringify({ error: 'Mot de passe incorrect' }) };
  }

  // Génère le token JWT
  const token = jwt.sign(
    { userId: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );

  // Met à jour last_login
  await supabase
    .from('formation_users')
    .update({ last_login: new Date().toISOString() })
    .eq('id', user.id);

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({ token, email: user.email }),
  };
};
