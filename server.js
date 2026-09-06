const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());

// Chave secreta para assinar os tokens (em produção ficaria protegida, mas por ora está blindada no backend)
const SECRET_KEY = "rythor_deals_super_secret_key_2026";

// Conecta ou cria o banco de dados SQLite
const db = new sqlite3.Database('./rythor.db', (err) => {
    if (err) {
        console.error('Erro ao conectar ao banco de dados:', err.message);
    } else {
        console.log('⚡ Conectado ao banco de dados SQLite do Rythor Deals.');
    }
});

// Inicializa as tabelas do banco
db.serialize(() => {
    // Tabela de Produtos
    db.run(`CREATE TABLE IF NOT EXISTS produtos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        preco TEXT NOT NULL,
        categoria TEXT NOT NULL,
        linkAfiliado TEXT NOT NULL
    )`);

    // Tabela de Usuários Admin
    db.run(`CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario TEXT UNIQUE NOT NULL,
        senha TEXT NOT NULL
    )`, async () => {
        // Cria um usuário admin padrão se não existir (Usuário: admin | Senha: 123)
        db.get("SELECT * FROM usuarios WHERE usuario = ?", ["admin"], async (err, row) => {
            if (!row) {
                const senhaHash = await bcrypt.hash("123", 10);
                db.run("INSERT INTO usuarios (usuario, senha) VALUES (?, ?)", ["admin", senhaHash], () => {
                    console.log('👤 Usuário Admin padrão configurado (User: admin | Pass: 123)');
                });
            }
        });
    });
});

// ==================== ROTAS PÚBLICAS ====================

// Rota GET: Retorna todos os produtos para a vitrine do site
app.get('/api/produtos', (req, res) => {
    db.all("SELECT * FROM produtos", [], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json({ produtos: rows });
    });
});

// Rota de Login: Verifica usuário e senha criptografada
app.post('/api/login', (req, res) => {
    const { usuario, senha } = req.body;

    db.get("SELECT * FROM usuarios WHERE usuario = ?", [usuario], async (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(401).json({ erro: "Usuário ou senha inválidos." });

        // Compara a senha digitada com o hash seguro salvo no banco
        const senhaValida = await bcrypt.compare(senha, user.senha);
        if (!senhaValida) return res.status(401).json({ erro: "Usuário ou senha inválidos." });

        // Gera um Token JWT válido por 8 horas
        const token = jwt.sign({ id: user.id, usuario: user.usuario }, SECRET_KEY, { expiresIn: '8h' });
        
        res.json({ 
            mensagem: "Login realizado com sucesso!", 
            token 
        });
    });
});

// ==================== MIDDLEWARE DE SEGURANÇA ====================
// Impede que pessoas não autorizadas acessem rotas protegidas
function verificarToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Formato: Bearer TOKEN

    if (!token) {
        return res.status(403).json({ erro: "Acesso negado. Token de autenticação não fornecido." });
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ erro: "Token inválido ou expirado." });
        }
        req.user = user;
        next();
    });
}

// ==================== ROTAS PROTEGIDAS ====================

// Rota POST: Cadastra um novo produto (Agora protegida pelo Token de Admin)
app.post('/api/produtos', verificarToken, (req, res) => {
    const { nome, preco, categoria, linkAfiliado } = req.body;
    
    if (!nome || !preco || !categoria || !linkAfiliado) {
        return res.status(400).json({ erro: "Todos os campos são obrigatórios." });
    }

    const query = `INSERT INTO produtos (nome, preco, categoria, linkAfiliado) VALUES (?, ?, ?, ?)`;
    
    db.run(query, [nome, preco, categoria, linkAfiliado], function(err) {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json({ 
            id: this.lastID, 
            mensagem: "Produto cadastrado com sucesso no Rythor Deals!" 
        });
    });
});

// Inicializa o servidor
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor rodando na porta http://localhost:${PORT}`);
});