// ╔══════════════════════════════════════════╗
// ║   NETLIFY FUNCTION — STRIPE WEBHOOK      ║
// ║   URL : /.netlify/functions/stripe       ║
// ╚══════════════════════════════════════════╝

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// ── Génère un mot de passe lisible ──
function generatePassword(length = 12) {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  let pass = '';
  for (let i = 0; i < length; i++) {
    pass += chars[Math.floor(Math.random() * chars.length)];
  }
  return pass;
}

// ── Envoie l'email de bienvenue ──
async function sendWelcomeEmail(email, password) {
  const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });

  const html = `
<!DOCTYPE html>
<html>
<head>
<style>
  body{font-family:Georgia,serif;background:#080808;color:#F5F0E8;margin:0;padding:0;}
  .container{max-width:560px;margin:0 auto;padding:48px 32px;}
  .logo{font-size:11px;letter-spacing:4px;color:#C9A96E;text-transform:uppercase;margin-bottom:40px;}
  h1{font-size:36px;font-weight:300;line-height:1.2;margin-bottom:24px;}
  h1 em{font-style:italic;color:#C9A96E;}
  p{font-size:14px;line-height:1.8;color:rgba(245,240,232,0.7);margin-bottom:16px;}
  .box{background:#161616;border:1px solid rgba(201,169,110,0.2);padding:24px 32px;margin:32px 0;}
  .label{font-size:10px;letter-spacing:2px;color:#C9A96E;text-transform:uppercase;margin-bottom:6px;}
  .value{font-size:18px;color:#F5F0E8;font-family:monospace;margin-bottom:20px;}
  .btn{display:inline-block;background:#C9A96E;color:#080808;padding:14px 40px;text-decoration:none;font-size:11px;letter-spacing:3px;text-transform:uppercase;font-weight:600;}
  .divider{height:1px;background:linear-gradient(90deg,transparent,#C9A96E,transparent);margin:32px 0;}
  .footer{margin-top:40px;font-size:11px;color:rgba(245,240,232,0.3);}
</style>
</head>
<body>
<div class="container">
  <div class="logo">CryptoNight Academy</div>
  <div class="divider"></div>
  <h1>Bienvenue dans<br><em>l'académie.</em></h1>
  <p>Ton paiement a été confirmé. Tu as maintenant accès à l'intégralité de la formation.</p>
  <p>Voici tes identifiants :</p>
  <div class="box">
    <div class="label">Email</div>
    <div class="value">${email}</div>
    <div class="label">Mot de passe</div>
    <div class="value">${password}</div>
  </div>
  <a href="${process.env.FORMATION_URL}#login" class="btn">Accéder à la formation →</a>
  <p style="font-size:12px;margin-top:24px;">Conserve cet email précieusement.</p>
  <div class="divider"></div>
  <div class="footer">CryptoNight Academy · Accès à vie inclus</div>
</div>
</body>
</html>`;

  await transporter.sendMail({
    from: `CryptoNight Academy <${process.env.SMTP_USER}>`,
    to: email,
    subject: '🎓 Ton accès CryptoNight Academy',
    html,
  });
}

// ── Handler principal ──
exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  const sig = event.headers['stripe-signature'];

  let stripeEvent;
  try {
    stripeEvent = stripe.webhooks.constructEvent(
      event.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET_FORMATION
    );
  } catch (err) {
    console.error('Webhook signature failed:', err.message);
    return { statusCode: 400, body: `Webhook Error: ${err.message}` };
  }

  // ── Paiement réussi ──
  if (stripeEvent.type === 'checkout.session.completed') {
    const session = stripeEvent.data.object;
    const email = session?.customer_details?.email;
    const customerId = session?.customer;

    if (!email) {
      return { statusCode: 400, body: 'No email found' };
    }

    // Vérifie si l'utilisateur existe déjà
    const { data: existing } = await supabase
      .from('formation_users')
      .select('id')
      .eq('email', email)
      .single();

    if (existing) {
      console.log(`Utilisateur déjà existant : ${email}`);
      return { statusCode: 200, body: JSON.stringify({ status: 'already exists' }) };
    }

    // Crée le compte
    const password = generatePassword();
    const passwordHash = await bcrypt.hash(password, 10);

    const { error } = await supabase.from('formation_users').insert({
      email,
      password_hash: passwordHash,
      stripe_customer_id: customerId,
      status: 'active',
    });

    if (error) {
      console.error('Supabase error:', error);
      return { statusCode: 500, body: 'DB error' };
    }

    // Envoie l'email
    try {
      await sendWelcomeEmail(email, password);
      console.log(`✅ Compte créé et email envoyé → ${email}`);
    } catch (emailErr) {
      console.error('Email error:', emailErr);
    }
  }

  return { statusCode: 200, body: JSON.stringify({ received: true }) };
};
