const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const SECRET_KEY = "mi_clave_secreta";

const usuario = {
  username: "admin",
  password: bcrypt.hashSync("1234", 8)
};

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (username !== usuario.username) {
    return res.status(404).json({ mensaje: "Usuario no encontrado" });
  }

  const passwordValido = bcrypt.compareSync(password, usuario.password);

  if (!passwordValido) {
    return res.status(401).json({ mensaje: "Contraseña incorrecta" });
  }

  const token = jwt.sign(
    { username: usuario.username },
    SECRET_KEY,
    { expiresIn: "1h" }
  );

  res.json({
    mensaje: "Login exitoso",
    token: token
  });
});

function verificarToken(req, res, next) {
  const bearerHeader = req.headers["authorization"];

  if (!bearerHeader) {
    return res.status(403).json({ mensaje: "Token requerido" });
  }

  const token = bearerHeader.split(" ")[1];

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ mensaje: "Token inválido" });
    }

    req.usuario = decoded;
    next();
  });
}

app.get("/perfil", verificarToken, (req, res) => {
  res.json({
    mensaje: "Acceso permitido",
    usuario: req.usuario
  });
});

app.listen(3000, () => {
  console.log("Servidor corriendo en http://localhost:3000");
});
