import express from "express";
import helmet from "helmet";
import cors from "cors";
import dotenv from "dotenv";
import { productsRouter } from "./routes/products";

dotenv.config();

const app = express();

app.use(helmet());
app.use(cors({ origin: process.env.ALLOWED_ORIGIN }));
app.use(express.json({ limit: "10kb" }));

app.use("/api/products", productsRouter);

app.get("/api/health", (_req, res) => {
  res.json({ status: "ok" });
});

const PORT = parseInt(process.env.PORT || "3000", 10);
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
