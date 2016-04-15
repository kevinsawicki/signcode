#!/usr/bin/env node

var path = require('path')
var prompt = require('prompt')
var signcode = require('./index')
var yargs = require('yargs')

var metadata = require('./package')

var args = parseArgs()
var fileToSign = args.argv._[0]
if (!fileToSign) {
  args.showHelp()
  process.exit(1)
}
fileToSign = path.resolve(fileToSign)

var options = {
  cert: path.resolve(args.argv.cert),
  hash: ['sha1', 'sha256'],
  key: args.argv.key ? path.resolve(args.argv.key) : args.argv.key,
  name: args.argv.name,
  overwrite: true,
  password: args.argv.password,
  path: fileToSign,
  site: args.argv.url
}

if (args.argv.prompt) {
  promptForPassword(function (password) {
    options.password = password
    sign(options)
  })
} else {
  sign(options)
}

function sign (options) {
  signcode.sign(options, function (error) {
    if (error) {
      console.error(error.message || error)
      process.exit(1)
    }
  })
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
    if (error) {
      console.error(error.message || error)
      process.exit(1)
    }
    callback(result.password)
  })
}

function parseArgs () {
  return yargs
    .usage(metadata.name + ' file_to_sign [args]\n\nSign Windows executables from a Mac.\nVersion ' + metadata.version)
    .option('cert', {
      alias: 'c',
      demand: true,
      describe: 'Path to a .pem, .pfx, or .p12 certificate file',
      type: 'string'
    })
    .option('key', {
      alias: 'k',
      describe: 'Path to .pem key file',
      type: 'string'
    })
    .option('name', {
      alias: 'n',
      describe: 'Application name',
      type: 'string'
    })
    .option('password', {
      describe: 'Password to use for certificate/key pair',
      type: 'string'
    })
    .option('prompt', {
      describe: 'Prompt for a password',
      type: 'boolean'
    })
    .option('url', {
      alias: 'u',
      describe: 'Application URL',
      type: 'string'
    })
    .help('help')
}
