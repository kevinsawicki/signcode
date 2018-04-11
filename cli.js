#!/usr/bin/env node

var path = require('path')
var prompt = require('prompt')
var signcode = require('./index')
var yargs = require('yargs')

var metadata = require('./package')

processCommand()

function sign (argv) {
  var options = {
    cert: path.resolve(argv.cert),
    hash: ['sha1', 'sha256'],
    key: argv.key ? path.resolve(argv.key) : argv.key,
    name: argv.name,
    overwrite: true,
    password: argv.password,
    path: path.resolve(argv.file_to_sign),
    site: argv.url
  }

  if (argv.prompt) {
    promptForPassword(function (password) {
      options.password = password
      signcode.sign(options, exitIfError)
    })
  } else {
    signcode.sign(options, exitIfError)
  }
}

function verify (argv) {
  var options = {
    path: path.resolve(argv.file_to_verify),
    hash: argv.hash
  }

  signcode.verify(options, exitIfError)
}

function exitIfError (error) {
  if (error) {
    console.error(error.message || error)
    process.exit(1)
  }
}

function promptForPassword (callback) {
  var promptConfig = {
    properties: {
      password: {
        hidden: true,
        required: true,
        message: 'Enter Password'
      }
    }
  }
  prompt.start()
  prompt.get(promptConfig, function (error, result) {
    exitIfError(error)
    callback(result.password)
  })
}

function processCommand () {
  yargs
    .usage(metadata.name + ' <command> path_to_executable [args]\n\nSign Windows executables from a Mac.\nVersion ' + metadata.version)
    .command('sign <file_to_sign>', 'sign an executable', {
      cert: {
        alias: 'c',
        demand: true,
        describe: 'Path to a .pem, .pfx, or .p12 certificate file',
        type: 'string'
      },
      key: {
        alias: 'k',
        describe: 'Path to .pem key file',
        type: 'string'
      },
      name: {
        alias: 'n',
        describe: 'Application name',
        type: 'string'
      },
      password: {
        describe: 'Password to use for certificate/key pair',
        type: 'string'
      },
      prompt: {
        describe: 'Prompt for a password',
        type: 'boolean'
      },
      url: {
        alias: 'u',
        describe: 'Application URL',
        type: 'string'
      }
    }, sign)
    .command('verify <file_to_verify> [args]', 'verify the signature on an executable', {
      hash: {
        alias: 'h',
        describe: 'Certificate fingerprint to expect on executable',
        type: 'string'
      }
    }, verify)
    .demandCommand()
    .help('help')
    .argv
}
