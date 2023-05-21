import express from 'express';
import cors from 'cors';
import type { IUser } from '../types';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import fs from 'fs';
import swaggerUi from 'swagger-ui-express';
import { PrismaClient } from '@prisma/client';

require('dotenv').config();

const swaggerSchema = require('../swaggerSchema.json');
const prisma = new PrismaClient();

const salt = bcrypt.genSaltSync(12);
const uploadMiddleware = multer({ dest: 'src/uploads/' });
const app = express();

app.use('/src/uploads', express.static(__dirname + '/uploads'));
app.use(cors({ credentials: true, origin: process.env.ORIGIN_URL }));
app.use(express.json());
app.use(cookieParser());
app.use('/api_docs', swaggerUi.serve, swaggerUi.setup(swaggerSchema));

// --- AUTH ---
app.post('/register', async (req, res) => {
  const { username, password, email }: IUser = req.body;
  try {
    const exsitingUser = await prisma.user.findFirst({
      where: {
        OR: [{ username }, { email }],
      },
    });

    if (exsitingUser) return res.status(400).json({ error: 'User already exists' });

    const hashedPassword = bcrypt.hashSync(password, salt);
    const createdUser = await prisma.user.create({
      data: {
        username,
        password: hashedPassword,
        email,
      },
    });

    if (!createdUser.email || !createdUser.password || !createdUser.username)
      return res.status(400).json({ error: 'Invalid credentials' });

    res.status(200).json(createdUser);
  } catch (err) {
    console.log({ error: 'USER_CREATION_ERROR', err });

    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const existingUser = await prisma.user.findUnique({
    where: {
      email,
    },
  });

  if (!existingUser) return res.status(404).json({ error: 'User not found' });

  const hashedPasswordCheck = bcrypt.compareSync(password, existingUser.password);

  if (hashedPasswordCheck) {
    jwt.sign(
      { email, id: existingUser.id, username: existingUser.username },
      process.env.JWT_PRIVATE_KEY,
      (err: any, token: any) => {
        if (err) throw new Error(err);
        res.cookie('jwtToken', token).json({
          id: existingUser.id,
          email: existingUser.email,
          username: existingUser.username,
        });
      },
    );
  }
});

app.get('/profile', (req, res) => {
  const { jwtToken } = req.cookies;
  if (!jwtToken) return;

  jwt.verify(jwtToken, process.env.JWT_PRIVATE_KEY, {}, (err, data) => {
    if (err) throw err;

    res.json(data);
  });
});

app.post('/logout', (req, res) => {
  res.cookie('jwtToken', '').json({ message: 'Logout' });
});
// --- AUTH/ ---

// --- POSTS ---
app.post('/create_post', uploadMiddleware.single('file'), async (req, res) => {
  const { originalname, path } = req.file;
  const parts = originalname.split('.');
  const ext = parts[parts.length - 1];
  const newPath = path + '.' + ext;
  fs.renameSync(path, newPath);

  const { jwtToken } = req.cookies;

  if (!jwtToken) return;

  jwt.verify(jwtToken, process.env.JWT_PRIVATE_KEY, {}, async (err, info) => {
    if (err) throw err;
    const { title, summary, postContent } = req.body;
    const newPost = await prisma.post.create({
      data: {
        title,
        summary,
        content: postContent,
        image: newPath,
        //@ts-expect-error
        userId: info?.id,
      },
    });
    res.json(newPost);
  });
});

app.get('/posts', async (req, res) => {
  res.status(200).json(
    await prisma.post.findMany({
      include: {
        User: {
          select: {
            username: true,
          },
        },
      },
      orderBy: [
        {
          createdAt: 'desc',
        },
      ],
    }),
  );
});

app.get('/post/:id', async (req, res) => {
  const { id } = req.params;

  if (!id) return res.status(404).json({ error: 'Post not found' });

  res.json(
    await prisma.post.findUnique({
      where: {
        id,
      },
      include: {
        User: {
          select: {
            username: true,
            id: true,
          },
        },
      },
    }),
  );
});

app.put('/post/:id/edit', uploadMiddleware.single('file'), async (req, res) => {
  let newPath: string = null;

  if (req.file) {
    const { originalname, path } = req.file;
    const parts = originalname.split('.');
    const ext = parts[parts.length - 1];
    newPath = path + '.' + ext;
    fs.renameSync(path, newPath);
  }

  const { jwtToken } = req.cookies;

  if (!jwtToken) return;

  jwt.verify(jwtToken, process.env.JWT_PRIVATE_KEY, {}, async (err, info) => {
    if (err) throw err;

    const { postId, title, summary, postContent } = req.body;
    const existingPost = await prisma.post.findUnique({
      where: {
        id: postId,
      },
    });

    //@ts-expect-error
    if (JSON.stringify(existingPost.userId) !== JSON.stringify(info.id)) {
      return res.status(400).json({ error: 'Invalid author' });
    }

    const updatedPost = await prisma.post.update({
      where: {
        id: postId,
      },
      data: {
        title,
        summary,
        content: postContent,
        image: newPath ? newPath : existingPost.image,
      },
    });

    res.status(200).json(updatedPost);
  });
});

app.delete('/post/:id/delete', async (req, res) => {
  const { jwtToken } = req.cookies;

  jwt.verify(jwtToken, process.env.JWT_PRIVATE_KEY, {}, async (err, info) => {
    const { postId } = req.body;

    const existingPost = await prisma.post.findUnique({
      where: {
        id: postId,
      },
    });

    if (!existingPost) return res.status(404).json({ error: 'Post not found' });

    //@ts-expect-error
    if (JSON.stringify(existingPost.userId) !== JSON.stringify(info.id)) {
      return res.status(400).json({ error: 'Invalid author' });
    }

    await prisma.post.delete({
      where: {
        id: postId,
      },
    });

    res.status(200).json({ message: 'Success' });
  });
});
// --- POSTS/ ---

app.listen(process.env.PORT, () => console.log('App started'));
