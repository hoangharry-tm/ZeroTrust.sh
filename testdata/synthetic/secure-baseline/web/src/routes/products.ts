import { Router, Request, Response } from "express";
import { searchProducts, queryUser, getOrdersByUser } from "../services/db";

export const productsRouter = Router();

productsRouter.get("/search", async (req: Request, res: Response) => {
  const q = (req.query.q as string) || "";
  if (q.length > 100) {
    return res.status(400).json({ error: "Search query too long" });
  }
  const results = await searchProducts(q);
  res.json({ results });
});

productsRouter.get("/user/:id", async (req: Request, res: Response) => {
  const userId = parseInt(req.params.id, 10);
  if (isNaN(userId)) {
    return res.status(400).json({ error: "Invalid user ID" });
  }
  const user = await queryUser(userId);
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }
  res.json(user);
});

productsRouter.get("/user/:id/orders", async (req: Request, res: Response) => {
  const userId = parseInt(req.params.id, 10);
  if (isNaN(userId)) {
    return res.status(400).json({ error: "Invalid user ID" });
  }
  const orders = await getOrdersByUser(userId);
  res.json({ orders });
});
