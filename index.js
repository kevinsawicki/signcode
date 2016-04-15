var ChildProcess = require('child_process')
var fs = require('fs')
var path = require('path')

exports.sign = function (options, callback) {
  var signOptions = Object.assign({}, options)

  var hashes = signOptions.hash
  if (!hashes) {
    hashes = ['sha1', 'sha256']
  }
  if (!Array.isArray(hashes)) {
    hashes = [hashes]
  }

  var finalPath = getOutputPath(signOptions.path)
  var signWithNextHash = function (hash) {
    var hash = hashes.shift()
    if (!hash) {
      return callback(null, finalPath)
    }

    signOptions.hash = hash
    spawnSign(signOptions, function (error, outputPath) {
      if (error) return callback(error)
      fs.rename(outputPath, finalPath, function () {
        if (error) return callback(error)

        signOptions.path = finalPath
        signOptions.nest = true
        signWithNextHash()
      })
    })
  }
  signWithNextHash()
}

exports.verify = function (options, callback) {
  spawnVerify(options, callback)
}

function spawnSign (options, callback) {
  var outputPath = getOutputPath(options.path, options.hash)
  var args = [
    '-certs',
    options.cert,
    '-key',
    options.key,
    '-in',
    options.path,
    '-out',
    outputPath,
    '-t',
    'http://timestamp.verisign.com/scripts/timstamp.dll'
  ]

  if (options.hash) {
    args.push('-h', options.hash)
  }

  if (options.name) {
    args.push('-n', options.name)
  }

  if (options.site) {
    args.push('-i', options.site)
  }

  if (options.nest) {
    args.push('-nest')
  }

  if (options.password) {
    args.push('-pass', options.password)
  }

  var spawnOptions = {
    env: process.env
  }

  if (options.password) {
    spawnOptions.detached = true
    spawnOptions.stdio = 'ignore'
  }

  var signcode = ChildProcess.spawn(getSigncodePath(), args, spawnOptions)

  signcode.on('close', function (code, signal) {
    if (code === 0) {
      callback(null, outputPath)
    } else {
      var message = 'osslsigncode signing failed:'
      if (code != null) {
        message += ' ' + code
      }
      if (signal != null) {
        message += ' ' + signal
      }
      callback(Error(message))
    }
  })
}

function spawnVerify (options, callback) {
  var args = [
    'verify',
    '-in',
    options.path,
		'-require-leaf-hash',
    options.hash
  ]

  var signcode = ChildProcess.spawn(getSigncodePath(), args)

  var stdout = ''
  signcode.stdout.on('data', function (data) {
    stdout += data.toString();
  })

  signcode.on('close', function (code, signal) {
    if (stdout.indexOf('No signature found.') !== -1) {
      return callback(Error('No signature found'))
    } else if(stdout.indexOf('Leaf hash match: failed') !== -1) {
      return callback(Error('Leaf hash match failed'))
    } else if (code === 0) {
      callback()
    } else {
      var message = 'osslsigncode verifying failed: '
      if (code != null) {
        message += ' ' + code
      }
      if (signal != null) {
        message += ' ' + signale
      }
      callback(Error(message))
    }
  })
}

function getOutputPath (inputPath, hash) {
  var extension = path.extname(inputPath)
  var name = path.basename(inputPath, extension)
  var outputName = name + '-signed'
  if (hash) outputName += '-' + hash
  outputName += extension
  return path.join(path.dirname(inputPath), outputName)
}

function getSigncodePath () {
  return path.join(__dirname, 'vendor', process.platform, 'osslsigncode')
}
