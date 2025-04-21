const express = require("express");
const axios = require("axios");
const multer = require("multer");
const cors = require("cors");
const fs = require("fs");
const path = require("path");

const app = express();
const upload = multer({ dest: "uploads/" });

app.use(cors());
app.use(express.json());

const API_KEY = process.env.API_KEY; // <-- tu clave de VirusTotal desde Render

// Análisis de archivos
app.post("/scan-file", upload.single("file"), async (req, res) => {
  const filePath = req.file.path;
  try {
    const formData = new FormData();
    formData.append("file", fs.createReadStream(filePath));

    const response = await axios.post("https://www.virustotal.com/api/v3/files", formData, {
      headers: {
        ...formData.getHeaders(),
        "x-apikey": API_KEY,
      },
    });

    fs.unlinkSync(filePath);
    res.json(response.data);
  } catch (error) {
    fs.unlinkSync(filePath);
    res.status(500).json({ error: "Error al analizar el archivo" });
  }
});

// Análisis de URLs
app.post("/scan-url", async (req, res) => {
  const { url } = req.body;
  try {
    const response = await axios.post(
      "https://www.virustotal.com/api/v3/urls",
      new URLSearchParams({ url }),
      {
        headers: {
          "x-apikey": API_KEY,
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: "Error al analizar la URL" });
  }
});

app.get("/", (req, res) => {
  res.send("🛡️ Servidor VirusTotal activo.");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor escuchando en el puerto ${PORT}`);
});
