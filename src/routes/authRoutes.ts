import { Router } from "express";
import { PrismaClient } from "@prisma/client";
import jwt from "jsonwebtoken";

const EMAIL_TOKEN_EXPIRATION_MINUTES = 10;
const AUTHENTICATION_EXPIRATION_HOURS = 12;
const JWT_SECRET = process.env.JWT_SECRET || "Super secret";

const router = Router();
const prisma = new PrismaClient();

// Generate a random 5 digit number as the email token
function generateEmailToken(): string {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function generateAuthToken(tokenId: number): string {
  const jwtPayload = { tokenId };

  return jwt.sign(jwtPayload, JWT_SECRET, {
    algorithm: "HS256",
    noTimestamp: true,
  });
}

//Create a user,if dosen`t exists,
//Generate the email token and send it to their email
router.post("/login", async (req, res) => {
  const { email } = req.body;

  //Generate the token
  const emailToken = generateEmailToken();
  const expiration = new Date(
    new Date().getTime() + EMAIL_TOKEN_EXPIRATION_MINUTES * 60 * 1000
  );

  try {
    const createToken = await prisma.token.create({
      data: {
        type: "EMAIL",
        emailToken,
        expiration,

        user: {
          connectOrCreate: {
            where: { email },
            create: { email },
          },
        },
      },
    });
    //send email to the users email
    res.sendStatus(200);
  } catch (e) {
    console.log(e);
    res.status(400).json({ error: "Couldn`t start the authentication procss" });
  }
});

//Validate the emailToken
//Generate a long-lived jwt token
router.post("/authenticate", async (req, res) => {
  const { email, emailToken } = req.body;

  const dbEmailToken = await prisma.token.findUnique({
    where: {
      emailToken,
    },
    include: {
      user: true,
    },
  });
  console.log(dbEmailToken);

  if (!dbEmailToken || !dbEmailToken.valid) {
    return res.sendStatus(401);
  }

  if (dbEmailToken.expiration < new Date()) {
    return res.status(401).json({ error: "Token expired!" });
  }

  if (dbEmailToken?.user?.email !== email) {
    return res.sendStatus(401);
  }

  //Validate that the user is the owner of the email

  //Generate Api token
  const expiration = new Date(
    new Date().getTime() + AUTHENTICATION_EXPIRATION_HOURS * 60 * 60 * 1000
  );
  const apiToken = await prisma.token.create({
    data: {
      type: "API",
      expiration,
      user: {
        connect: {
          email,
        },
      },
    },
  });

  //invalidate email token
  await prisma.token.update({
    where: { id: dbEmailToken.id },
    data: { valid: false },
  });

  //Generate the jwt token
  const authToken = generateAuthToken(apiToken.id);

  res.json({ authToken });
});

export default router;
