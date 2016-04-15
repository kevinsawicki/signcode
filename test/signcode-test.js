var path = require('path')
var signcode = require('..')

describe('signcode', function () {
  this.timeout(30000)

  describe('sign', function () {
    it('signs the executable', function (done) {
      var options = {
        cert: path.join(__dirname, 'fixtures', 'cert.pem'),
        key: path.join(__dirname, 'fixtures', 'key.pem'),
        path: path.join(__dirname, 'fixtures', 'electron.exe')
      }
      signcode.sign(options, done)
    })
  })
})
