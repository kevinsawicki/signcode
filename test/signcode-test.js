var assert = require('assert')
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

        var sha1 = '9BF51511E06FA5FFE1CE408584B9981AA4EFE7EA'
        var sha256 = '7229D992750771B833BE2C4F497A5853573B55FB9181E4031691A55FBEE496F6'
        verifyExe(outputPath, sha1, sha256done)
      })
    })

    it('signs the executable with a password', function (done) {
      var tempPath = temp.path({suffix: '.exe'})
      fs.writeFileSync(tempPath, fs.readFileSync(path.join(__dirname, 'fixtures', 'electron.exe')))

      var options = {
        cert: path.join(__dirname, 'fixtures', 'cert-with-pw.pem'),
        hash: ['sha1', 'sha256'],
        key: path.join(__dirname, 'fixtures', 'key-with-pw.pem'),
        password: 'signcode',
        path: tempPath
      }

      signcode.sign(options, function (error, outputPath) {
        if (error) return done(error)

        var sha1 = '15D3780E7FD7D18439EFBC6C0413489536B373B9'
        var sha256 = '58B7E3102CBCCB0CF6A462F67F18834B6570C231D721D8AF5E4C4ABF0688BD3F'
        verifyExe(outputPath, sha1, sha256, done)
      })
    })
  })

  describe('.verify(options)', function () {
    it('verifies the sha1 signature on the executable', function (done) {
      var verifyOptions = {
        hash: 'sha1:9BF51511E06FA5FFE1CE408584B9981AA4EFE7EA',
        path: path.join(__dirname, 'fixtures', 'electron-signed.exe')
      }
      signcode.verify(verifyOptions, done)
    })

    it('verifies the sha256 signature on the executable', function (done) {
      var verifyOptions = {
        hash: 'sha256:7229D992750771B833BE2C4F497A5853573B55FB9181E4031691A55FBEE496F6',
        path: path.join(__dirname, 'fixtures', 'electron-signed.exe')
      }
      signcode.verify(verifyOptions, done)
    })

    it('callbacks with an error on an unsigned executable', function (done) {
      var verifyOptions = {
        path: path.join(__dirname, 'fixtures', 'electron.exe')
      }
      signcode.verify(verifyOptions, function (error) {
        assert.equal(error.message, 'No signature found')
        done()
      })
    })

    it('callbacks with an error on an unmatch leaf hash', function (done) {
      var verifyOptions = {
        hash: 'sha1:9BF51511E06FA5FFE1CE408584B9981AA4EFEBAD',
        path: path.join(__dirname, 'fixtures', 'electron-signed.exe')
      }
      signcode.verify(verifyOptions, function (error) {
        assert.equal(error.message, 'Leaf hash match failed')
        done()
      })
    })
  })
})

function verifyExe (outputPath, sha1, sha256, callback) {
  var verifyOptions = {
    hash: 'sha1:' + sha1,
    path: outputPath
  }
  signcode.verify(verifyOptions, function (error) {
    if (error) return callback(error)
    verifyOptions.hash = 'sha256:' + sha256
    signcode.verify(verifyOptions, callback)
  })
}
