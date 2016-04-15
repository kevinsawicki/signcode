var ChildProcess = require('child_process')
var path = require('path')

exports.sign = function (options, callback) {
  spawnSign(options, callback)
}

exports.verify = function (options, callback) {
  spawnVerify(options, callback)
}

function spawnSign (options, callback) {
  var outputPath = getOutputPath(options.path)
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

  var signcode = ChildProcess.spawn(getSigncodePath(), args)
  signcode.on('close', function (code, signal) {
    if (code === 0) {
      callback(null, outputPath)
    } else {
      var message = 'osslsigncode signing failed: '
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

function getOutputPath (inputPath) {
  var extension = path.extname(inputPath)
  var name = path.basename(inputPath, extension)
  var outputName = name + '-signed' + extension
  return path.join(path.dirname(inputPath), outputName)
}

function getSigncodePath () {
  return path.join(__dirname, 'vendor', process.platform, 'osslsigncode')
}
