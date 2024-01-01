const uuid = require("uuid");
const express = require("express");
const onFinished = require("on-finished");
const bodyParser = require("body-parser");
const path = require("path");
const port = 3000;
const fs = require("fs");
const request = require("request");
const axios = require("axios");
const { verify } = require("jsonwebtoken");

const yourDomain = "dev-7whj26jw4qopw248.us.auth0.com";
const client_id = "7EsexnfRLQ8LvVB1ywrhMB758y9ShFtR";
const client_secret =
  "xJ8M5SAQSknS-lqJ2tLtTzen0cQAj0gO5Dy-K7ZSiD1-T_6QUyEGK7O1i3HOPbVw";
const API_IDENTIFIER = "https://dev-7whj26jw4qopw248.us.auth0.com/api/v2/";

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SESSION_KEY = "Authorization";

class Session {
  #sessions = {};

  constructor() {
    try {
      this.#sessions = fs.readFileSync("./sessions.json", "utf8");
      this.#sessions = JSON.parse(this.#sessions.trim());

      console.log(this.#sessions);
    } catch (e) {
      this.#sessions = {};
    }
  }

  #storeSessions() {
    fs.writeFileSync(
      "./sessions.json",
      JSON.stringify(this.#sessions),
      "utf-8"
    );
  }

  set(key, value) {
    if (!value) {
      value = {};
    }
    this.#sessions[key] = value;
    this.#storeSessions();
  }

  get(key) {
    return this.#sessions[key];
  }

  init(res) {
    const sessionId = uuid.v4();
    this.set(sessionId);

    return sessionId;
  }

  destroy(req, res) {
    const sessionId = req.sessionId;
    delete this.#sessions[sessionId];
    this.#storeSessions();
  }
}

const sessions = new Session();

app.use((req, res, next) => {
  let currentSession = {};
  let sessionId = req.get(SESSION_KEY);

  if (sessionId) {
    currentSession = sessions.get(sessionId);
    if (!currentSession) {
      currentSession = {};
      sessionId = sessions.init(res);
    }
  } else {
    sessionId = sessions.init(res);
  }

  req.session = currentSession;
  req.sessionId = sessionId;

  onFinished(req, () => {
    const currentSession = req.session;
    const sessionId = req.sessionId;
    sessions.set(sessionId, currentSession);
  });

  next();
});
const validateJwt = async (jwt) => {
  const cert = fs.readFileSync("cert.pem");
  verify(jwt, cert, { algorithms: ["RS256"] }, (error, payload) => {
    if (error) throw new Error(error);
    console.log("jwt validated");
    console.log(payload);
  });
};

const refreshToken = (refreshToken) => {
  return new Promise((resolve, reject) => {
    const options = {
      method: "POST",
      url: `https://${yourDomain}/oauth/token`,
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
      form: {
        client_id: client_id,
        client_secret: client_secret,
        grant_type: "refresh_token",
        refresh_token: refreshToken,
      },
    };

    request(options, (error, response, body) => {
      if (error) reject(error);
      resolve(body);
    });
  });
};

app.get("/", async (req, res) => {
  if (req.session.access_token) {
    validateJwt(req.session.access_token);
    if (true) {
      const response = await refreshToken(req.session.refresh_token);
      const responseObj = JSON.parse(response);
      req.session.access_token = responseObj.access_token;
      req.session.expires_at =
        Math.floor(Date.now() / 1000) + responseObj.expires_in;
      console.log(`token refreshed:
        ${response}
      `);
    }

    return res.json({
      username: req.session.username,
      logout: "http://localhost:3000/logout",
    });
  }
  res.sendFile(path.join(__dirname + "/index.html"));
});

app.get("/logout", (req, res) => {
  sessions.destroy(req, res);
  res.redirect("/");
});

app.post("/api/login", (req, res) => {
  const { login, password } = req.body;
  const options = {
    method: "POST",
    url: `https://${yourDomain}/oauth/token`,
    headers: { "content-type": "application/x-www-form-urlencoded" },
    form: {
      client_id: client_id,
      client_secret: client_secret,
      audience: API_IDENTIFIER,
      grant_type: "password",
      username: login,
      password: password,
      scope: "offline_access",
    },
  };
  request(options, (error, response, body) => {
    if (error) {
      console.error(error);
      obj.status(401).send();
    }
    const obj = JSON.parse(body);
    console.log(obj);
    req.session.username = login;
    req.session.login = login;
    req.session.access_token = obj.access_token;
    req.session.expires_at = Math.floor(Date.now() / 1000) + obj.expires_in;
    req.session.refresh_token = obj.refresh_token;
    res.json({ token: req.sessionId });
  });
});

const getAccessToken = async () => {
  const options = {
    method: "POST",
    url: `https://${yourDomain}/oauth/token`,
    headers: { "content-type": "application/x-www-form-urlencoded" },
    data: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: client_id,
      client_secret: client_secret,
      audience: API_IDENTIFIER,
    }),
  };

  const response = await axios.request(options);
  return response.data.access_token;
};

app.post("/api/signup", async (req, res) => {
  const accessToken = await getAccessToken();
  const { login, password } = req.body;
  let data = JSON.stringify({
    email: login,
    nickname: login,
    connection: "Username-Password-Authentication",
    password: password,
  });

  let config = {
    method: "post",
    maxBodyLength: Infinity,
    url: `https://${yourDomain}/api/v2/users`,
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      Authorization: `Bearer ${accessToken}`,
    },
    data: data,
  };

  axios
    .request(config)
    .then((response) => {
      console.log(JSON.stringify(response.data));
    })
    .catch((error) => {
      console.log(error);
    });
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
