// Deliberately vulnerable example for ChainGuard. Never deploy.
const express = require("express");

const app = express();
app.get("/", (_req, res) => res.send("chainguard example"));
app.listen(8000);
