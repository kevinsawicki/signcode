var ChildProcess = require('child_process')
var path = require('path')

exports.sign = function (options, callback) {
  spawn(options, callback)
}

function spawn (options, callback) {
  var args = [
    '-certs',
    options.cert,
    '-key',
    options.key,
    '-in',
    options.path,
    '-out',
    getOutputPath(options.path),
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
  signcode.on('exit', function (code, signal) {
    if (code === 0) {
      callback()
    } else {
      var message = 'osslsigncode failed: '
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
