var ChildProcess = require('child_process')
var fs = require('fs')
var path = require('path')

exports.sign = function (options, callback) {
  var signOptions = Object.assign({}, options)

  var hashes = signOptions.hash
  if (!hashes) {
    hashes = ['sha1', 'sha256']
  } else {
    hashes = Array.isArray(hashes) ? hashes.slice() : [hashes]
  }

  var finalPath = getOutputPath(signOptions.path)
  var signWithNextHash = function () {
    var hash = hashes.shift()
    if (!hash) {
      if (signOptions.overwrite) {
        fs.rename(finalPath, options.path, function (error) {
          if (error) return callback(error)
          callback(null, options.path)
        })
      } else {
        callback(null, finalPath)
      }
      return
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
    '-in',
    options.path,
    '-out',
    outputPath,
    '-t',
    'http://timestamp.verisign.com/scripts/timstamp.dll'
  ]

  var certExtension = path.extname(options.cert)
  if (certExtension === '.p12' || certExtension === '.pfx') {
    args.push('-pkcs12', options.cert)
  } else {
    args.push('-certs', options.cert)
    args.push('-key', options.key)
  }

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

  if (options.passwordPath) {
    args.push('-readpass', options.passwordPath)
  }

  var spawnOptions = {
    env: process.env
  }

  if (options.password || options.passwordPath) {
    spawnOptions.detached = true
    spawnOptions.stdio = ['ignore', 'ignore', 'pipe']
  }

  var signcode = ChildProcess.spawn(getSigncodePath(), args, spawnOptions)

  var stderr = ''
  signcode.stderr.on('data', function (data) {
    stderr += data.toString()
  })

  signcode.on('close', function (code, signal) {
    if (code === 0) {
      callback(null, outputPath)
    } else {
      var message = 'Signing failed with'

      if (code != null) {
        message += ' ' + code
      }

      if (signal != null) {
        message += ' ' + signal
      }

      if (stderr) {
        var errorOutput = formatErrorOutput(stderr)
        if (errorOutput) {
          message += '. ' + errorOutput
        }
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
    stdout += data.toString()
  })

  signcode.on('close', function (code, signal) {
    if (stdout.indexOf('No signature found.') !== -1) {
      return callback(Error('No signature found'))
    } else if (stdout.indexOf('Leaf hash match: failed') !== -1) {
      return callback(Error('Leaf hash match failed'))
    } else if (code === 0) {
      callback()
    } else {
      var message = 'osslsigncode verifying failed: '
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

function formatErrorOutput (output) {
  return output.split('\n').filter(function (line) {
    return !/^\d+:|osslsigncode\(|\*\*\*\s/.test(line)
  }).join('\n')
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
