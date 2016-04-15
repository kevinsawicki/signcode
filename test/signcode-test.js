var fs = require('fs')
var path = require('path')
var signcode = require('..')
var temp = require('temp').track()

describe('signcode', function () {
  this.timeout(30000)

  describe('.sign(options)', function () {
    it('signs the executable', function (done) {
      var tempPath = temp.path({suffix: '.exe'})
      fs.writeFileSync(tempPath, fs.readFileSync(path.join(__dirname, 'fixtures', 'electron.exe')))

      var options = {
        cert: path.join(__dirname, 'fixtures', 'cert.pem'),
        hash: ['sha1', 'sha256'],
        key: path.join(__dirname, 'fixtures', 'key.pem'),
        path: tempPath
      }

      signcode.sign(options, function (error, outputPath) {
        if (error) return done(error)

        var verifyOptions = {
          hash: 'sha1:9BF51511E06FA5FFE1CE408584B9981AA4EFE7EA',
          path: outputPath
        }
        signcode.verify(verifyOptions, done)
      })
    })
  })
})
