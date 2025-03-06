const express = require('express');
const ActiveDirectory = require('activedirectory2').promiseWrapper;
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
app.use(cors()); // Enable CORS for localhost:3000 (your React frontend)
app.use(bodyParser.json());

// AD Configuration (updated with working credentials)
const adConfig = {
  url: 'ldap://10.10.2.34:389', // Use ldaps://10.10.2.34:636 if secure LDAP is required
  baseDN: 'dc=vh,dc=geleximco', // Confirmed from your setup
  username: 'VH\\ldap.verify', // Use NetBIOS format (escape backslash with \\)
  password: '^&^geLexiMco060424^&^' // Confirmed password
};

const ad = new ActiveDirectory(adConfig);

// Login Endpoint (unchanged, handles both NetBIOS and UPN formats)
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    // Try NetBIOS format (DOMAIN\username)
    let adUsername = `VH\\${username}`;
    let isAuthenticated = await ad.authenticate(adUsername, password);
    if (!isAuthenticated) {
      // Try UPN format (username@domain)
      adUsername = `${username}@${adConfig.baseDN}`;
      isAuthenticated = await ad.authenticate(adUsername, password);
    }
    if (isAuthenticated) {
      // Return the username without domain for consistency
      res.json({ success: true, username: username.split('\\')[1] || username.split('@')[0] });
    } else {
      res.status(401).json({ success: false, message: 'Invalid username or password.' });
    }
  } catch (error) {
    console.error('AD Authentication Error:', error);
    res.status(500).json({ success: false, message: 'Authentication failed. Please contact support.' });
  }
});

// Logout Endpoint (unchanged)
app.post('/api/logout', (req, res) => {
  res.json({ success: true, message: 'Logged out successfully.' });
});

// Password Change Endpoint using ldapjs (unchanged from previous fix)
app.post('/api/change-password', async (req, res) => {
  const { username, newPassword } = req.body;
  try {
    // Create LDAP client
    const client = ldap.createClient({
      url: adConfig.url
    });

    // Bind with service account (VH\ldap.verify) to authorize password change
    await new Promise((resolve, reject) => {
      client.bind(adConfig.username, adConfig.password, (err) => {
        if (err) reject(err);
        else resolve(null);
      });
    });

    // Prepare the DN for the user (adjust based on your AD structure)
    const userDN = `CN=${username},OU=Users,DC=vh,DC=geleximco`; // Adjust OU if needed

    // Modify the user's password (unicodePwd requires UTF-16 encoding, wrapped in quotes)
    const change = new ldap.Change({
      operation: 'replace',
      modification: {
        unicodePwd: Buffer.from(`"${newPassword}"`, 'utf16le') // UTF-16 little-endian encoding
      }
    });

    // Perform the password change
    await new Promise((resolve, reject) => {
      client.modify(userDN, change, (err) => {
        if (err) reject(err);
        else resolve(null);
      });
    });

    // Unbind the client
    await new Promise((resolve, reject) => {
      client.unbind((err) => {
        if (err) reject(err);
        else resolve(null);
      });
    });

    res.json({ success: true, message: 'Password changed successfully.' });
  } catch (error) {
    console.error('Password Change Error:', error);
    res.status(500).json({ success: false, message: 'Password change failed. Please contact support.' });
  }
});

// Start the server
const PORT = 3001; // Use a fixed port for local development
app.listen(PORT, () => {
  console.log(`Backend server running on port ${PORT}`);
});