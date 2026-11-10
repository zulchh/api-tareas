
require('dotenv').config();

const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

app.use(express.json());

app.use((req, res, next) => {
    console.log('PETICIÓN RECIBIDA:', req.method, req.originalUrl);
    next();
});

// Archivos de almacenamiento
const archivoTareas = path.join(__dirname, 'tareas.json');
const archivoUsuarios = path.join(__dirname, 'usuarios.json');

// Función para leer archivos JSON
async function leerArchivo(archivo) {
    try {
        const datos = await fs.readFile(archivo, 'utf8');
        return JSON.parse(datos);
    } catch (error) {
        if (error.code === 'ENOENT') {
            await fs.writeFile(archivo, '[]', 'utf8');
            return [];
        }
        throw error;
    }
}

// Función para guardar información
async function guardarArchivo(archivo, datos) {
    await fs.writeFile(
        archivo,
        JSON.stringify(datos, null, 2),
        'utf8'
    );
}

// Ruta principal
app.get('/', (req, res) => {
    res.send('API de tareas funcionando correctamente');
});

// REGISTRO DE USUARIOS
console.log('Ruta POST /register cargada');
app.post('/register', async (req, res, next) => {
    try {
        const { usuario, password } = req.body;

        if (
            typeof usuario !== 'string' ||
            !usuario.trim() ||
            typeof password !== 'string' ||
            password.length < 6
        ) {
            return res.status(400).json({
                mensaje: 'Ingresa un usuario y una contraseña de al menos 6 caracteres'
            });
        }

        const usuarios = await leerArchivo(archivoUsuarios);

        const existe = usuarios.find(
            u => u.usuario.toLowerCase() === usuario.trim().toLowerCase()
        );

        if (existe) {
            return res.status(409).json({
                mensaje: 'El usuario ya está registrado'
            });
        }

        const passwordEncriptada = await bcrypt.hash(password, 10);

        const nuevoUsuario = {
            id: Date.now().toString(),
            usuario: usuario.trim(),
            password: passwordEncriptada
        };

        usuarios.push(nuevoUsuario);

        await guardarArchivo(archivoUsuarios, usuarios);

        res.status(201).json({
            mensaje: 'Usuario registrado correctamente'
        });

    } catch (error) {
        next(error);
    }
});

// INICIO DE SESIÓN
console.log('Ruta POST /login cargada');
app.post('/login', async (req, res, next) => {
    try {
        const { usuario, password } = req.body;

        if (
            typeof usuario !== 'string' ||
            typeof password !== 'string' ||
            !usuario.trim() ||
            !password
        ) {
            return res.status(400).json({
                mensaje: 'Debes ingresar usuario y contraseña'
            });
        }

        const usuarios = await leerArchivo(archivoUsuarios);

        const usuarioEncontrado = usuarios.find(
            u => u.usuario.toLowerCase() === usuario.trim().toLowerCase()
        );

        if (!usuarioEncontrado) {
            return res.status(401).json({
                mensaje: 'Usuario o contraseña incorrectos'
            });
        }

        const passwordValida = await bcrypt.compare(
            password,
            usuarioEncontrado.password
        );

        if (!passwordValida) {
            return res.status(401).json({
                mensaje: 'Usuario o contraseña incorrectos'
            });
        }

        const token = jwt.sign(
            {
                id: usuarioEncontrado.id,
                usuario: usuarioEncontrado.usuario
            },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({
            mensaje: 'Inicio de sesión exitoso',
            token: token
        });

    } catch (error) {
        next(error);
    }
});

// MIDDLEWARE DE AUTENTICACIÓN
function verificarToken(req, res, next) {
    const authorization = req.headers.authorization;

    if (!authorization || !authorization.startsWith('Bearer ')) {
        return res.status(401).json({
            mensaje: 'No se proporcionó un token de autenticación'
        });
    }

    const token = authorization.split(' ')[1];

    try {
        const datos = jwt.verify(token, JWT_SECRET);
        req.usuario = datos;
        next();
    } catch (error) {
        return res.status(403).json({
            mensaje: 'Token inválido o expirado'
        });
    }
}

// PROTEGER RUTAS DE TAREAS
app.use('/tareas', verificarToken);

// GET: Consultar tareas
app.get('/tareas', async (req, res, next) => {
    try {
        const tareas = await leerArchivo(archivoTareas);
        res.json(tareas);
    } catch (error) {
        next(error);
    }
});

// POST: Crear tarea
app.post('/tareas', async (req, res, next) => {
    try {
        const { titulo, descripcion } = req.body;

        if (
            typeof titulo !== 'string' || !titulo.trim() ||
            typeof descripcion !== 'string' || !descripcion.trim()
        ) {
            return res.status(400).json({
                mensaje: 'El título y la descripción son obligatorios'
            });
        }

        const tareas = await leerArchivo(archivoTareas);

        const nuevaTarea = {
            id: Date.now().toString(),
            usuarioId: req.usuario.id,
            titulo: titulo.trim(),
            descripcion: descripcion.trim()
        };

        tareas.push(nuevaTarea);
        await guardarArchivo(archivoTareas, tareas);

        res.status(201).json({
            mensaje: 'Tarea creada correctamente',
            tarea: nuevaTarea
        });

    } catch (error) {
        next(error);
    }
});

// PUT: Actualizar tarea
app.put('/tareas/:id', async (req, res, next) => {
    try {
        const tareas = await leerArchivo(archivoTareas);

        const indice = tareas.findIndex(
            t => t.id === req.params.id &&
                 t.usuarioId === req.usuario.id
        );

        if (indice === -1) {
            return res.status(404).json({
                mensaje: 'Tarea no encontrada'
            });
        }

        const { titulo, descripcion } = req.body;

        if (titulo === undefined && descripcion === undefined) {
            return res.status(400).json({
                mensaje: 'Debes proporcionar al menos un campo'
            });
        }

        if (titulo !== undefined &&
            (typeof titulo !== 'string' || !titulo.trim())) {
            return res.status(400).json({
                mensaje: 'El título no es válido'
            });
        }

        if (descripcion !== undefined &&
            (typeof descripcion !== 'string' || !descripcion.trim())) {
            return res.status(400).json({
                mensaje: 'La descripción no es válida'
            });
        }

        if (titulo !== undefined) {
            tareas[indice].titulo = titulo.trim();
        }

        if (descripcion !== undefined) {
            tareas[indice].descripcion = descripcion.trim();
        }

        await guardarArchivo(archivoTareas, tareas);

        res.json({
            mensaje: 'Tarea actualizada correctamente',
            tarea: tareas[indice]
        });

    } catch (error) {
        next(error);
    }
});

// DELETE: Eliminar tarea
app.delete('/tareas/:id', async (req, res, next) => {
    try {
        const tareas = await leerArchivo(archivoTareas);

        const nuevasTareas = tareas.filter(
            t => !(t.id === req.params.id &&
                   t.usuarioId === req.usuario.id)
        );

        if (tareas.length === nuevasTareas.length) {
            return res.status(404).json({
                mensaje: 'Tarea no encontrada'
            });
        }

        await guardarArchivo(archivoTareas, nuevasTareas);

        res.json({
            mensaje: 'Tarea eliminada correctamente'
        });

    } catch (error) {
        next(error);
    }
});

// RUTAS INEXISTENTES
app.use((req, res) => {
    res.status(404).json({
        mensaje: 'La ruta solicitada no existe'
    });
});

// MANEJO GENERAL DE ERRORES
app.use((error, req, res, next) => {
    console.error('Error:', error.message);

    res.status(500).json({
        mensaje: 'Error interno del servidor'
    });
});

// Verificar configuración e iniciar servidor
if (!JWT_SECRET) {
    console.error('Falta configurar JWT_SECRET en el archivo .env');
    process.exit(1);
}

app.listen(PORT, () => {
    console.log(`Servidor funcionando en http://localhost:${PORT}`);
});
