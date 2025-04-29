// auth-api.js
// API de autenticación con Express.js
// Funcionalidades:
// 1. Registro de usuario
// 2. Inicio de sesión
// 3. Validación de credenciales

const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'clave_secreta_jwt'; // En producción usar variable de entorno

// Middleware para procesar JSON en las peticiones
app.use(bodyParser.json());

// Base de datos simulada (en producción usar una base de datos real)
const users = [];

/**
 * Middleware para verificar token JWT
 * @param {Object} req - Objeto de solicitud
 * @param {Object} res - Objeto de respuesta
 * @param {Function} next - Función para continuar con el siguiente middleware
 */
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  
  if (!token) {
    return res.status(403).json({ message: 'Token no proporcionado' });
  }
  
  try {
    const decoded = jwt.verify(token.split(' ')[1], JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Token inválido' });
  }
};

/**
 * Ruta para registrar un nuevo usuario
 * @route POST /api/register
 * @param {string} username - Nombre de usuario
 * @param {string} password - Contraseña del usuario
 * @returns {Object} Mensaje de confirmación
 */
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Validar datos recibidos
    if (!username || !password) {
      return res.status(400).json({ message: 'Se requiere usuario y contraseña' });
    }
    
    // Verificar si el usuario ya existe
    if (users.find(user => user.username === username)) {
      return res.status(409).json({ message: 'El usuario ya existe' });
    }
    
    // Encriptar contraseña
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Guardar usuario en la "base de datos"
    users.push({
      id: users.length + 1,
      username,
      password: hashedPassword
    });
    
    res.status(201).json({ message: 'Usuario registrado exitosamente' });
  } catch (error) {
    console.error('Error en registro:', error);
    res.status(500).json({ message: 'Error interno del servidor' });
  }
});

/**
 * Ruta para iniciar sesión
 * @route POST /api/login
 * @param {string} username - Nombre de usuario
 * @param {string} password - Contraseña del usuario
 * @returns {Object} Token JWT si la autenticación es exitosa
 */
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Validar datos recibidos
    if (!username || !password) {
      return res.status(400).json({ message: 'Se requiere usuario y contraseña' });
    }
    
    // Buscar usuario en la "base de datos"
    const user = users.find(user => user.username === username);
    
    // Verificar si el usuario existe
    if (!user) {
      return res.status(401).json({ message: 'Error en la autenticación' });
    }
    
    // Verificar contraseña
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Error en la autenticación' });
    }
    
    // Generar token JWT
    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    res.status(200).json({ 
      message: 'Autenticación satisfactoria',
      token
    });
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ message: 'Error interno del servidor' });
  }
});

/**
 * Ruta protegida que requiere autenticación
 * @route GET /api/protegido
 * @returns {Object} Datos del usuario autenticado
 */
app.get('/api/protegido', verifyToken, (req, res) => {
  res.json({ 
    message: 'Ruta protegida accedida exitosamente',
    user: req.user
  });
});

// Iniciar el servidor
app.listen(PORT, () => {
  console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
});

// Exportar la app para pruebas unitarias
module.exports = app;