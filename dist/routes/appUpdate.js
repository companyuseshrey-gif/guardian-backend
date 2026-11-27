import express from "express";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VERSION_FILE = path.join(__dirname, "../../public/version.json");
export const appUpdateRouter = express.Router();
appUpdateRouter.get("/v1/app/update", (_req, res) => {
    if (!fs.existsSync(VERSION_FILE)) {
        return res.status(404).json({ error: "no update info available" });
    }
    try {
        const info = JSON.parse(fs.readFileSync(VERSION_FILE, "utf-8"));
        res.json(info);
    }
    catch {
        res.status(500).json({ error: "failed to read version info" });
    }
});
