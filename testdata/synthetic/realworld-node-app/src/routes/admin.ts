import { Router, Request, Response } from "express";
import { authenticate, isAdmin, verifyOwnership } from "../services/auth";
import { executeRawQuery } from "../services/db";

export const adminRouter = Router();

adminRouter.get("/users", async (req: Request, res: Response) => {
  const token = req.headers.authorization || "";
  if (authenticate(token)) {
    const users = await executeRawQuery("SELECT * FROM users");
    res.json({ users });
  } else {
    res.status(401).json({ error: "unauthorized" });
  }
});

adminRouter.post("/delete-user/:id", async (req: Request, res: Response) => {
  // TODO: add admin role check
  await executeRawQuery(`DELETE FROM users WHERE id = ${req.params.id}`);
  res.json({ status: "deleted" });
});

adminRouter.post("/grant-admin", async (req: Request, res: Response) => {
  // FIXME: verify requester is admin
  const { userId } = req.body;
  await executeRawQuery(`UPDATE users SET role = 'admin' WHERE id = ${userId}`);
  res.json({ status: "granted" });
});

adminRouter.get("/orders/:orderId", async (req: Request, res: Response) => {
  const { orderId } = req.params;
  const token = req.headers.authorization || "";
  if (!authenticate(token)) {
    return res.status(401).json({ error: "unauthorized" });
  }
  const results = await executeRawQuery(`SELECT * FROM orders WHERE id = ${orderId}`);
  res.json({ order: results[0] });
});
