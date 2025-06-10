const express = require('express');
const jose = require('node-jose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const port = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY || 'sua-chave-secreta';

app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use(cors());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

const verifyApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!API_KEY || API_KEY === 'sua-chave-secreta') {
    console.warn('⚠️ Aviso: API_KEY não configurada ou usando valor padrão.');
  }
  
  if (API_KEY && API_KEY !== 'sua-chave-secreta' && apiKey !== API_KEY) {
    return res.status(401).json({ error: 'API key inválida ou ausente' });
  }
  
  next();
};

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.post('/decrypt', verifyApiKey, async (req, res) => {
  console.log('Requisição de descriptografia recebida');
  
  try {
    const { jwe, privateKeyJwk } = req.body;
    
    if (!jwe) {
      return res.status(400).json({ error: 'JWE ausente na requisição' });
    }
    
    if (!privateKeyJwk) {
      return res.status(400).json({ error: 'Chave privada JWK ausente na requisição' });
    }
    
    console.log(`JWE recebido (primeiros 50 caracteres): ${jwe.substring(0, 50)}...`);
    
    if (!jwe.match(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)) {
      return res.status(400).json({ error: 'Formato JWE inválido' });
    }
    
    let key;
    try {
      key = await jose.JWK.asKey(privateKeyJwk);
    } catch (keyError) {
      console.error('Erro ao carregar chave JWK:', keyError);
      return res.status(400).json({ 
        error: 'Chave JWK inválida', 
        details: keyError.message 
      });
    }
    
    const decryptor = jose.JWE.createDecrypt(key);
    
    let result;
    try {
      result = await decryptor.decrypt(jwe);
    } catch (decryptError) {
      console.error('Erro na descriptografia:', decryptError);
      
      let errorMessage = 'Falha na descriptografia';
      if (decryptError.code === 'ERR_JWE_DECRYPTION_FAILED') {
        errorMessage = 'Falha na descriptografia: possível incompatibilidade de chave ou JWE corrompido';
      } else if (decryptError.message.includes('no key found')) {
        errorMessage = 'Falha na descriptografia: possível incompatibilidade de ID de chave no cabeçalho JWE';
      }
      
      return res.status(400).json({ 
        error: errorMessage, 
        details: decryptError.message 
      });
    }
    
    let decryptedPayload;
    try {
      decryptedPayload = JSON.parse(result.plaintext.toString());
      console.log('Descriptografia bem-sucedida');
    } catch (parseError) {
      console.error('Erro ao parsear payload descriptografado:', parseError);
      return res.status(500).json({ 
        error: 'Falha ao parsear payload descriptografado', 
        details: parseError.message 
      });
    }
    
    return res.json({ 
      decryptedMessages: decryptedPayload.messages || decryptedPayload || [],
      success: true
    });
    
  } catch (error) {
    console.error('Erro não tratado:', error);
    return res.status(500).json({ 
      error: 'Erro interno do servidor', 
      details: error.message 
    });
  }
});

app.listen(port, () => {
  console.log(`🚀 Serviço de descriptografia JWE rodando na porta ${port}`);
  console.log(`📝 Endpoints disponíveis:`);
  console.log(`   - GET /health: Verificação de saúde do serviço`);
  console.log(`   - POST /decrypt: Endpoint principal de descriptografia`);
});
