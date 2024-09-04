// imports de dependencias
require("dotenv").config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// calling express
const app = express();

// Models
const User = require('./models/User');

// Credentials
const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;

// Config JSON response
app.use(express.json());

// Open Route - Public Route
app.get('/', (req, res) => {
    res.status(200).json({msm : 'Bem vindo familha! '})
});

// Private Route
app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id;

    // check if user exists
    const user = await User.findById(id, '-password');

    if (!user) { return res.status(404).json({msg: "Usuario não encontrado."}) }

    res.status(200).json({user})
})

// check token
function checkToken(req, res, next) {
    const authHeaders = req.headers['authorization'];
    const token = authHeaders && authHeaders.split(" ")[1]

    if (!token) {
        return res.status(401).json({msg: "Acesso negado."});
    }

    try {
        const secret = process.env.SECRET;
        jwt.verify(token, secret);
        next()
    } catch (error) {
        return res.status(400).json({msg: "Token Invalido."});
    }
}

// Register User
app.post('/auth/register', async(req, res) => {
    const {name, email, password, confirmpassword} = req.body;

    // validations
    if (!name) { return res.status(422).json({msg: "Campo nome é obrigatório."}) }
    if (!email) { return res.status(422).json({msg: "Campo email é obrigatório."}) }
    if (!password) { return res.status(422).json({msg: "Campo senha é obrigatório."}) }
    if (password !== confirmpassword) { return res.status(422).json({msg: "Os campos senha e confirme senha não conferem."}) }

    // check if user exists
    const userExists = await User.findOne({ email: email });

    if (userExists) { return res.status(422).json({msg: "Já existe um cadastro com esse email."}) }

    // create password add security
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // create user
    const user = new User({
        name,
        email,
        password: passwordHash
    });

    try {
        await user.save();
        res.status(201).json({msg: "Usuario criado com sucesso!"});
    } catch (error) {
        console.log(error);
        res.status(500).json({msg: "Houve um erro no servidor, tente mais tarde."});
    }
});

app.post('/auth/login', async (req, res) => {
    const {email, password} = req.body;

    if (!email) { return res.status(422).json({msg: "Campo email é obrigatório."}) }
    if (!password) { return res.status(422).json({msg: "Campo senha é obrigatório."}) }

    // check if user exists
    const user = await User.findOne({ email: email });

    if (!user) { return res.status(404).json({msg: "Usuario não encontrado."}) }

    // check if password match
    const checkPassword = await bcrypt.compare(password, user.password);

    if (!checkPassword) {
        return res.status(500).json({msg: "Senha Invalida."});
    }

    try {
        const secret = process.env.SECRET;

        const token = jwt.sign(
            {
                id: user._id
            },
            secret 
        )
        res.status(200).json({msg: "Autenticação realizada com sucesso!", token})
    } catch (error) {
        console.log(error);
        res.status(500).json({msg: "Houve um erro no servidor, tente mais tarde."});
    }
});

// conexão com o banco
mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.8d7v1.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`)
    .then(() => {
        app.listen(3000);
        console.log('Conectado ao Banco!');
    })
    .catch((err) => {console.log(err)});