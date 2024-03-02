const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const fs = require('fs').promises;
const https = require('https');
const { Sequelize, DataTypes } = require('sequelize');
const selfsigned = require('selfsigned');
const errorHandler = require('./errorHandler');
const morgan = require('morgan');
const helmet = require('helmet');
const path = require('path');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

const attrs = [{ name: 'commonName', value: 'localhost' }];
const pems = selfsigned.generate(attrs, { days: 365 });

const sessionSecret = process.env.SESSION_SECRET || 'your-secret-key';

app.use(session({
  secret: sessionSecret,
  resave: true,
  saveUninitialized: false
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(helmet());
app.use(express.static(path.join(__dirname, 'public')));

const sequelize = new Sequelize('postgres://postgres:1234@localhost:5432/educational_portal', {
  logging: false,
  dialect: 'postgres',
  dialectOptions: {
    ssl: false,
  },
});

const User = sequelize.define('User', {
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  role: {
    type: DataTypes.STRING,
    defaultValue: 'user',
    validate: {
      isIn: [['user', 'admin']],
    },
  },
});

sequelize.sync()
  .then(() => {
    console.log('Database synced');
  })
  .catch(err => {
    console.error('Error syncing database:', err);
  });

function requireAuthentication(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    res.redirect('/login');
  }
}

app.use(errorHandler);

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

app.get('/', (req, res) => {
  res.redirect('/register');
});

app.get('/register', (req, res) => {
  const registerFilePath = path.join(__dirname, 'public', 'register.html');
  res.sendFile(registerFilePath);
});

app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;

  const hashedPassword = await bcrypt.hash(password, 12);

  try {
    const user = await User.create({ username, password: hashedPassword, role });
    console.log('User created:', user);
    res.redirect('/login?registration=success');
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/login', (req, res) => {
  const loginFilePath = path.join(__dirname, 'public', 'login.html');
  res.sendFile(loginFilePath);
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ where: { username } });

    if (user && await bcrypt.compare(password, user.password)) {
      req.session.user = user;

      if (user.role === 'admin') {
        return res.redirect('/admin-dashboard');
      } else {
        return res.redirect('/dashboard');
      }
    } else {
      return res.send('Invalid username or password');
    }
  } catch (error) {
    console.error('Error finding user:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/dashboard', requireAuthentication, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.post('/update-user', requireAuthentication, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.session.user.id;

  try {
    const user = await User.findByPk(userId);

    if (user && await bcrypt.compare(currentPassword, user.password)) {
      const hashedNewPassword = await bcrypt.hash(newPassword, 12);
      await User.update({ password: hashedNewPassword }, { where: { id: userId } });
      res.send('Password updated successfully');
    } else {
      res.send('Current password is incorrect');
    }
  } catch (error) {
    console.error('Error updating password:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error(err);
    }
    res.redirect('/');
  });
});

app.get('/profile', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  res.send(`User Profile: ${req.session.user.username}`);
});

app.get('/admin-dashboard', (req, res) => {
  if (req.session.user && req.session.user.role === 'admin') {
    res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
  } else {
    res.redirect('/login');
  }
});

app.post('/admin/manage-users', async (req, res) => {
  const { action, userId, newUsername, newPassword, newRole } = req.body;

  try {
    // Retrieve the user based on userId
    const user = await User.findByPk(userId);

    if (!user) {
      return res.status(404).send('User not found');
    }

    // Implement user management based on the action
    switch (action) {
      case 'update':
        if (newUsername) {
          user.username = newUsername;
        }
        if (newPassword) {
          const hashedNewPassword = await bcrypt.hash(newPassword, 12);
          user.password = hashedNewPassword;
        }
        if (newRole) {
          user.role = newRole;
        }
        await user.save();
        return res.send('User updated successfully');

      case 'delete':
        await user.destroy();
        return res.send('User deleted successfully');

      case 'add':
        // Implement logic to add a new user
        // Make sure to hash the password before saving
        // Set appropriate username, password, and role
        const hashedNewPassword = await bcrypt.hash(newPassword, 12);
        const newUser = await User.create({
          username: newUsername,
          password: hashedNewPassword,
          role: newRole,
        });
        return res.send(`User added successfully with ID: ${newUser.id}`);

      default:
        return res.status(400).send('Invalid action');
    }
  } catch (error) {
    console.error('Error managing user:', error);
    res.status(500).send('Internal Server Error');
  }
});


const httpsOptions = {
  key: pems.private,
  cert: pems.cert
};

app.get('*', (req, res, next) => {
  if (req.secure) {
    next();
  } else {
    res.redirect('https://' + req.get('host') + req.url);
  }
});

https.createServer(httpsOptions, app).listen(PORT, () => {
  console.log(`Server is running on https://localhost:${PORT}`);
});
