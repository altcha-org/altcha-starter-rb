require 'bundler/setup'
require 'altcha'
require 'sinatra'
require 'json'
require 'base64'
require 'dotenv'

# Load environment variables
Dotenv.load

ALTCHA_HMAC_KEY = ENV['ALTCHA_HMAC_KEY'] || 'default-hmac-key'

class Server < Sinatra::Base
  set :port, ENV['PORT'] || 3000

  before do
    content_type :json
    headers 'Access-Control-Allow-Origin' => '*',
          'Access-Control-Allow-Methods' => ['GET', 'POST', 'OPTIONS'],
          'Access-Control-Allow-Headers' => '*'
  end

  options '*' do
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = '*'
    200
  end

  get '/' do
    content_type 'text/plain'
    <<~TEXT
      ALTCHA server demo endpoints:

      GET /altcha - use this endpoint as challengeurl for the widget
      POST /submit - use this endpoint as the form action
      POST /submit_spam_filter - use this endpoint for form submissions with spam filtering
    TEXT
  end

  # Fetch challenge
  get '/altcha' do
    options = Altcha::ChallengeOptions.new(
      algorithm: 'SHA-256',
      hmac_key: ALTCHA_HMAC_KEY,
      max_number: 50_000
    )
    challenge = Altcha.create_challenge(options)
    challenge.to_json
  end

  # Handle solution submissions
  post '/submit' do
    payload = params['altcha']
    if payload.nil?
      halt 400, { error: 'Altcha payload missing' }.to_json
    end

    verified = Altcha.verify_solution(payload, ALTCHA_HMAC_KEY)
    if verified
      { success: true, data: params }.to_json
    else
      halt 400, { error: 'Invalid Altcha payload' }.to_json
    end
  end

  # Handle submissions with spam filter
  post '/submit_spam_filter' do
    payload = params['altcha']
    if payload.nil?
      halt 400, { error: 'Altcha payload missing' }.to_json
    end

    verified, verification_data = Altcha.verify_server_signature(payload, ALTCHA_HMAC_KEY)
    fields_verified = Altcha.verify_fields_hash(params, verification_data.fields, verification_data.fields_hash, 'SHA-256')

    if verified && fields_verified
      { success: true, form_data: params, verification_data: verification_data }.to_json
    else
      halt 400, { error: 'Invalid Altcha payload' }.to_json
    end
  end
end

# Run the application
if __FILE__ == $0
  Server.run!
end

