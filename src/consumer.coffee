crypto            = require 'crypto'
HMAC_SHA1         = require './hmac-sha1'
MemoryNonceStore  = require './memory-nonce-store'
errors            = require './errors'
extensions        = require './extensions'

class Consumer
  constructor: (consumer_key, consumer_secret, nonceStore, signature_method=(new HMAC_SHA1()) ) ->

    if typeof consumer_key is 'undefined' or consumer_key is null
      throw new errors.ConsumerError 'Must specify consumer_key'

    if typeof consumer_secret is 'undefined' or consumer_secret is null
      throw new errors.ConsumerError 'Must specify consumer_secret'

    if not nonceStore
      nonceStore = new MemoryNonceStore()

    if not nonceStore.isNonceStore?()
      throw new errors.ParameterError 'Fourth argument must be a nonceStore object'

    @consumer_key     = consumer_key
    @consumer_secret  = consumer_secret
    @signer           = signature_method
    @nonceStore       = nonceStore
    @body             = {}

  encode_request: (urlInfo, body, callback) =>
    if not callback
      callback = body
      body = undefined

    callback = callback or () ->

    body.oauth_nonce = crypto.randomBytes(Math.ceil(16)).toString('hex').slice(0, 32)
    body.oauth_consumer_key = @consumer_key
    body.oauth_signature_method = 'HMAC-SHA1'
    body.oauth_timestamp = Math.floor(new Date() / 1000)
    body.oauth_version = '1.0'
    body.oauth_callback = 'about:blank'

    sig = @signer.build_signature urlInfo, body, @consumer_secret
    body.oauth_signature = sig

    callback null, body

exports = module.exports = Consumer
