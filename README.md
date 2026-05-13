# Node Auth JWT & MongoDB

Este projeto consiste numa API de autenticação robusta desenvolvida em **Node.js**, utilizando **JSON Web Tokens (JWT)** para a gestão de sessões e **MongoDB** como base de dados NoSQL. O sistema foca-se na segurança e escalabilidade, implementando as melhores práticas para o tratamento de credenciais de utilizadores.

## 🚀 Funcionalidades Principais

* **Registo de Utilizadores:** Permite a criação de novas contas validando campos obrigatórios e garantindo que não existam emails duplicados no sistema.
* **Segurança com Bcrypt:** As passwords não são armazenadas em texto simples; é utilizado um sistema de *hashing* com `salt` para garantir a integridade dos dados.
* **Autenticação JWT:** Ao realizar o login com sucesso, o sistema gera um token assinado que deve ser utilizado para autenticar pedidos subsequentes.
* **Rotas Privadas:** Implementação de um middleware (`checkToken`) que valida a presença e a validade do token JWT antes de permitir o acesso a recursos restritos.
* **Persistência de Dados:** Integração total com o **MongoDB Atlas**, utilizando o **Mongoose** para a modelação e manipulação de dados.

## 🛠️ Tecnologias Utilizadas

* **Express:** Framework base para a construção das rotas e gestão de pedidos HTTP.
* **JSON Web Token (JWT):** Utilizado para a emissão e verificação de tokens de acesso.
* **Bcrypt:** Responsável pela criptografia segura das passwords.
* **Mongoose:** Biblioteca ODM para interação com o MongoDB.
* **Dotenv:** Gestão de variáveis de ambiente para proteger dados sensíveis como credenciais de base de dados e segredos de token.

## 📋 Requisitos de Configuração

Para o correto funcionamento, o projeto requer a configuração de um ficheiro `.env` na raiz, contendo as seguintes variáveis:
* `DB_USER`: Utilizador do cluster MongoDB.
* `DB_PASS`: Palavra-passe do cluster MongoDB.
* `SECRET`: Chave secreta para a assinatura dos tokens JWT.

O servidor está configurado para correr por defeito na porta `3000`, utilizando o `nodemon` em ambiente de desenvolvimento para facilitar o processo de atualização de código.
