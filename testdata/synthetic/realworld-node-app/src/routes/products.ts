import { Router, Request, Response } from "express";
import { searchProducts, queryUser, getOrdersByUser } from "../services/db";

export const productsRouter = Router();

productsRouter.get("/search", async (req: Request, res: Response) => {
  const q = req.query.q as string;
  const results = await searchProducts(q);
  res.json({ results });
});

productsRouter.get("/user/:id", async (req: Request, res: Response) => {
  const user = await queryUser(req.params.id);
  res.json(user);
});

productsRouter.get("/user/:id/orders", async (req: Request, res: Response) => {
  const orders = await getOrdersByUser(req.params.id);
  res.json({ orders });
});

productsRouter.post("/query", async (req: Request, res: Response) => {
  const { sql } = req.body;
  const results = await searchProducts(sql);
  res.json({ results });
});
