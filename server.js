const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();

app.use(express.json());
app.use(cors());

const MONGO_URI = process.env.MONGO_URI || '';
const JWT_SECRET = process.env.JWT_SECRET || 'chave_secreta_super_segura';
const PORT = process.env.PORT || 3000;

mongoose.connect(MONGO_URI)
  .then(() => console.log('📦 Conectado ao MongoDB com sucesso!'))
  .catch(err => console.error('Erro ao conectar ao MongoDB:', err));

// Schema de Produtos (com suporte a múltiplas lojas)
const produtoSchema = new mongoose.Schema({
    nome: { type: String, required: true },
    preco: { type: String, required: true },
    categoria: { type: String, required: true },
    loja: { 
        type: String, 
        enum: ['amazon', 'aliexpress', 'shopee', 'kabum', 'outro'], 
        default: 'outro' 
    },
    linkAfiliado: { type: String, required: true }
});
const Produto = mongoose.model('Produto', produtoSchema);

// Schema de Clientes
const clienteSchema = new mongoose.Schema({
    nome: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    senhaHash: { type: String, required: true },
    criadoEm: { type: Date, default: Date.now }
});
const Cliente = mongoose.model('Cliente', clienteSchema);

// Bloqueio contra ataques de força bruta no login
const limiteLogin = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { erro: 'Muitas tentativas. Tente mais tarde.' }
});

// Segurança: Verificar se é Administrador
function exigirAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ erro: 'Token não fornecido.' });

    const token = authHeader.replace('Bearer ', '');
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        if (payload.tipo !== 'admin') {
            return res.status(403).json({ erro: 'Acesso negado.' });
        }
        next();
    } catch (e) {
        return res.status(401).json({ erro: 'Token inválido ou expirado.' });
    }
}

// Rota de Login do Admin
app.post('/api/login', limiteLogin, async (req, res) => {
    const { usuario, senha } = req.body;
    const ADMIN_USER = process.env.ADMIN_USER || 'admin';
    const ADMIN_PASS_HASH = process.env.ADMIN_PASS_HASH; 

    if (usuario === ADMIN_USER) {
        let senhaCorreta = false;
        if (ADMIN_PASS_HASH) {
            senhaCorreta = await bcrypt.compare(senha, ADMIN_PASS_HASH);
        } else {
            senhaCorreta = (senha === '123'); // Senha padrão temporária
        }

        if (senhaCorreta) {
            const token = jwt.sign({ usuario: ADMIN_USER, tipo: 'admin' }, JWT_SECRET, { expiresIn: '1d' });
            return res.json({ token });
        }
    }
    res.status(401).json({ erro: 'Usuário ou senha inválidos.' });
});

// Rota para Registrar Cliente novo
app.post('/api/clientes/registrar', async (req, res) => {
    try {
        const { nome, email, senha } = req.body;
        if (!nome || !email || !senha || senha.length < 6) {
            return res.status(400).json({ erro: 'Dados inválidos. A senha precisa ter pelo menos 6 caracteres.' });
        }
        const emailLower = email.toLowerCase();
        const existe = await Cliente.findOne({ email: emailLower });
        if (existe) return res.status(409).json({ erro: 'E-mail já cadastrado.' });

        const senhaHash = await bcrypt.hash(senha, 12);
        await Cliente.create({ nome, email: emailLower, senhaHash });
        res.status(201).json({ mensagem: 'Conta criada com sucesso!' });
    } catch (err) {
        res.status(500).json({ erro: 'Erro interno ao registrar.' });
    }
});

// Rota para Login de Cliente
app.post('/api/clientes/login', async (req, res) => {
    try {
        const { email, senha } = req.body;
        const cliente = await Cliente.findOne({ email: (email || '').toLowerCase() });
        const senhaOk = cliente && await bcrypt.compare(senha, cliente.senhaHash);
        if (!senhaOk) return res.status(401).json({ erro: 'E-mail ou senha inválidos.' });

        const token = jwt.sign({ id: cliente._id, tipo: 'cliente' }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, nome: cliente.nome });
    } catch (err) {
        res.status(500).json({ erro: 'Erro interno ao logar.' });
    }
});

// Listar Produtos (Público no site)
app.get('/api/produtos', async (req, res) => {
    try {
        const produtos = await Produto.find().sort({ _id: -1 });
        res.json({ produtos });
    } catch (err) {
        res.status(500).json({ erro: 'Erro ao buscar produtos.' });
    }
});

// Cadastrar Produto (Protegido - Só Admin)
app.post('/api/produtos', exigirAdmin, async (req, res) => {
    try {
        const { nome, preco, categoria, loja, linkAfiliado } = req.body;
        const novoProduto = await Produto.create({
            nome, preco, categoria, loja: loja || 'outro', linkAfiliado
        });
        res.status(201).json({ mensagem: 'Produto cadastrado!', produto: novoProduto });
    } catch (err) {
        res.status(500).json({ erro: 'Erro ao salvar produto.' });
    }
});

// Excluir Produto (Protegido - Só Admin)
app.delete('/api/produtos/:id', exigirAdmin, async (req, res) => {
    try {
        const produtoRemovido = await Produto.findByIdAndDelete(req.params.id);
        if (!produtoRemovido) return res.status(404).json({ erro: 'Produto não encontrado.' });
        res.json({ mensagem: 'Produto removido.' });
    } catch (err) {
        res.status(500).json({ erro: 'Erro ao excluir.' });
    }
});

app.listen(PORT, () => console.log(`🚀 Servidor rodando na porta ${PORT}`));
