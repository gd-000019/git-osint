#!/usr/bin/env node
"use strict";

const { runCli } = require("./lib/cli");

if (require.main === module) runCli("gitlab").then(code => { process.exitCode = code; });

module.exports = { runCli: (argv, dependencies) => runCli("gitlab", argv, dependencies) };
