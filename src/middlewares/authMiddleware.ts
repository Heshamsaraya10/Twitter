    import { Request, Response, NextFunction } from "express";
    import jwt from "jsonwebtoken";
    import { PrismaClient, User } from "@prisma/client";
    const JWT_SECRET = process.env.JWT_SECRET || "Super secret";
    console.log("JWT secret: ", JWT_SECRET);

    const prisma = new PrismaClient();

    type AuthRequest = Request & { user?: User };

    export async function authenticateToken(
    req: AuthRequest,
    res: Response,
    next: NextFunction
    ) {
    //Aucentication
    const authHeader = req.headers["authorization"];
    const jwtToken = authHeader?.split(" ")[1];
    if (!jwtToken) {
        return res.sendStatus(401);
    }
    //decode the jwt token
    try {
        const payload = (await jwt.verify(jwtToken, JWT_SECRET)) as {
        tokenId: number;
        };

        if (!payload?.tokenId) {
        return res.sendStatus(401);
        }

        const dbToken = await prisma.token.findUnique({
        where: { id: payload.tokenId },
        include: { user: true },
        });

        if (!dbToken?.valid || dbToken.expiration < new Date()) {
        return res.status(401).json({ error: "Api token expired" });
        }
        req.user = dbToken.user;
    } catch (e) {
        return res.sendStatus(401);
    }

    next();
    }
