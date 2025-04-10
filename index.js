import express from "express";
import bodyParser from "body-parser";
import crypto from "node:crypto";
import recordatorios from "./recordatorios.json" assert { type: "json" };
import { randomUUID } from "node:crypto";
import fs from "fs";

const app = express();
const PORT = process.env.PORT ?? 3000;

let usuarios = [
  {
    username: "admin",
    name: "Gustavo Alfredo Marín Sáez",
    token:
      "1b6ce880ac388eb7fcb6bcaf95e20083:341dfbbe86013c940c8e898b437aa82fe575876f2946a2ad744a0c51501c7dfe6d7e5a31c58d2adc7a7dc4b87927594275ca235276accc9f628697a4c00b4e01", // certamen123
  },
];

let activeTokens = {};
let todos = [];

app.use(express.static("public"));
// Escriba su código a partir de aquí
app.use(bodyParser.json());

function generarToken() {
  return crypto.randomBytes(48).toString("hex");
}

function autorizacion(req, res, next) {
  const tokenAutorizacion = req.headers["x-authorization"];

  if (
    !tokenAutorizacion ||
    !Object.values(activeTokens).includes(tokenAutorizacion)
  ) {
    return res.status(401).json({ error: "No autorizado" });
  }
  next();
}

// Función para generar el hash de la contraseña usando scrypt

function generarHashPass(password, salt, keylen = 64) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keylen, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(derivedKey.toString("hex"));
    });
  });
}

// desde aquí se llama por metodo post al login con los datos ingreados y luego se valida en autorizacion
app.post("/api/auth/login", async (req, res) => {
  //console.log("llegue al login");
  const { username, password } = req.body;
  const user = usuarios.find((u) => u.username === username);

  if (!user) {
    return res.status(401).json({ error: "El usuario no existe" });
  }

  // Separar la sal y la llave almacenada
  const [storedSalt, storedKey] = user.token.split(":");

  // Generar el hash de la contraseña proporcionada usando la misma sal
  try {
    const passwordHash = await generarHashPass(password, storedSalt);

    // hash generado passwordHash para ver coincide con el hash almacenado storedKey
    if (passwordHash !== storedKey) {
      return res.status(401).json({ error: "Contraseña incorrecta" });
    }

    // esta funcion genera un token para el usuario
    const token = generarToken();
    activeTokens[username] = token;

    // Devolvemos el token
    res.json({ username: user.username, name: user.name, token });
  } catch (err) {
    res.status(500).json({ error: "Error en el servidor" });
  }
});

// Listar recordatorios
app.get("/api/reminders", autorizacion, (req, res) => {
  res.setHeader("Content-Type", "application/json");

  const orderedRecordatorios = recordatorios.sort((a, b) => {
    if (a.important && !b.important) {
      return -1;
    }
    if (!a.important && b.important) {
      return 1;
    }
    return a.createdAt - b.createdAt;
  });
  res.json(orderedRecordatorios);

  res.status(200);
});

//Crear recordatorios

const FILE_PATH = "./recordatorios.json";

app.post("/api/reminders", autorizacion, (req, res) => {
  res.setHeader("Content-Type", "application/json");
  const { content, important } = req.body;

  if (
    typeof content !== "string" ||
    content.length > 120 ||
    content.trim() === ""
  ) {
    return res.status(400).json({
      error:
        "El Contenido debe ser un string de máximo 120 caracteres y no puede estar vacío",
    });
  }
  const isImportant = typeof important === "boolean" ? important : false;

  const nuevoRecordatorio = {
    id: randomUUID(),
    content: content,
    createdAt: Date.now(), //funcion para los milisegundos
    important: isImportant,
  };

  recordatorios.push(nuevoRecordatorio);

  fs.writeFileSync(FILE_PATH, JSON.stringify(recordatorios, null, 2));

  return res.status(201).json(nuevoRecordatorio);
});

//Actualizar recordatorio

app.patch("/api/reminders/:id", autorizacion, (req, res) => {
  res.setHeader("Content-Type", "application/json");
  const { id } = req.params;

  const recordatorio = recordatorios.find(
    (recordatorio) => recordatorio.id === id
  );

  if (recordatorio === undefined) {
    return res.status(400).json({
      error: "Este recordatorio no existe",
    });
  }
  let { content, important } = req.body;

  if (content !== undefined) {
    if (
      typeof content !== "string" ||
      content.length > 120 ||
      content.trim() === ""
    ) {
      return res.status(400).json({
        error: "El formato del contenido no es correcto",
      });
    }
    recordatorio.content = content;
  }

  if (important !== undefined) {
    if (typeof important !== "boolean") {
      return res.status(400).json({
        error: "El formato de 'important' no es correcto",
      });
    }
    recordatorio.important = important;
  }

  fs.writeFileSync(FILE_PATH, JSON.stringify(recordatorios, null, 2));

  return res.status(200).json(recordatorio);
});

//borrar recordatorio
app.delete("/api/reminders/:id", (req, res) => {
  res.setHeader("Content-Type", "application/json");
  const { id } = req.params;

  const indexRecordatorio = recordatorios.findIndex(
    (recordatorio) => recordatorio.id === id
  );

  if (indexRecordatorio === -1) {
    return res.status(404).json({
      error: "Recordatorio no existe",
    });
  }
  recordatorios.splice(indexRecordatorio, 1);

  fs.writeFileSync(FILE_PATH, JSON.stringify(recordatorios, null, 2)); // Actualiza el archivo
  console.log("recordatorio borrado ");

  return res.status(204).json();
});
// Hasta aquí

app.listen(PORT, (error) => {
  if (error) {
    console.error(`No se puede ocupar el puerto ${PORT} :(`);
    return;
  }

  console.log(`Escuchando en el puerto ${PORT}`);
});
