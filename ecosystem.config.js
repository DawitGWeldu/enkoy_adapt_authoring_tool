module.exports = {
  apps : [{
    name: "adapt-authoring", // This is the name PM2 will use for your app
    script: "server.js",     // This tells PM2 to run your server.js file
    cwd: "/var/www/adapt.enkoylearn.com", // The working directory for the app

    // If you are using NVM and have installed a specific Node.js version for Adapt,
    // you MUST specify the absolute path to that Node.js executable here.
    // To find your path:
    //   1. Make sure you're using the correct NVM version: nvm use <version_number> (e.g., nvm use 18)
    //   2. Run: which node
    //   3. Copy the output (e.g., /root/.nvm/versions/node/v18.20.8/bin/node) and paste it below.
    interpreter: "/root/.nvm/versions/node/v16.20.2/bin/node", // UNCOMMENT AND UPDATE THIS LINE IF USING NVM

    env_production: {
      NODE_ENV: "production",
      PORT: 5000, // This should match the serverPort in your config.json
    }
  }]
};
