var ChildProcess = require('child_process')
var path = require('path')

exports.sign = function (options, callback) {
  spawn(options, callback)
}

function spawn (options, callback) {
  var args = [
    '-nest',
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
  signcode.on('exit', function (code) {
    if (code === 0) {
      callback()
    } else {
      callback(Error('Signcode failed: ' + code))
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
  return path.join(__dirname, vendor, process.platform, 'osslsigncode')
}
