require "bundler/setup"

require 'rack'
require 'json'
require 'sequel'
require 'sequel/extensions/pg_array'
require 'openssl'
require 'base64'

class RippleAPI
  TIMESTAMP_TOLERANCE = 300
  KEY_SUFFIX = /([A-Za-z0-9_+.]+)\.json$/
  BASE64_PADDING = /=+\n?\z/
  
  def initialize(db)
    @db = db
  end
  
  def call(env)
    request = Rack::Request.new(env)
    status = 404
    headers = {'Content-type' => 'text/plain'}
    result = 'Not found'
    
    if env['X_AUTH_TOKEN']
      headers['E-tag'] = env['X_AUTH_TOKEN']
      if env['HTTP_IF_NONE_MATCH']
        status = 304
        result = '"Not modified"'
        return [status, headers, [result]]
      end
    end
    
    begin
      account = nil
      if request.path.match(KEY_SUFFIX)
        md = request.path.match(KEY_SUFFIX)
        key_id = md[1]
        account = api_key_check(key_id, request, env)
      end
      
      if request.get? || request.head?
        case request.path
          when /^\/account\/#{KEY_SUFFIX}/
            status = 200
            result = {}
            result[:account_name] = account
            result[:managers] = @db[:account_managers].where(:account_name => account).get(:minecraft_name).to_a
          when /^\/transactions\/#{KEY_SUFFIX}/
            status = 200
            result = transactions(account, request['start'], request['stop'])
          when /^\/paths\/via\/#{KEY_SUFFIX}/
            status = 200
            result = paths_via(account, request['start'], request['stop'])
          when /^\/trusts\/trusted_by\/#{KEY_SUFFIX}/
            status = 200
            result = @db[:trusts].where(:trustor => account).select(:trustor, :trustee, :amount, :currency).to_a
          when /^\/trusts\/who_trusts\/#{KEY_SUFFIX}/
            status = 200
            result = @db[:trusts].where(:trustee => account).select(:trustor, :trustee, :amount, :currency).to_a
          when /^\/debts\/owed_by\/#{KEY_SUFFIX}/
            status = 200
            result = @db[:debts].where(:debt_from => account).select(:debt_from, :debt_to, :amount, :currency).to_a
          when /^\/debts\/owed_to\/#{KEY_SUFFIX}/
            status = 200
            result = @db[:debts].where(:debt_to => account).select(:debt_from, :debt_to, :amount, :currency).to_a
        end
      end
    rescue APIKeyError => e
      status = 403
      result = e.message
    end
    [status, headers, [result.to_json]]
  end
  
  def api_key_check(key_id, request, env)
    parameters = request.GET() # query string parameters only
    
    # Check for key and signature
    raise APIKeyError.key unless key_id
    
    query_string = request.query_string
    raise APIKeyError.sig unless env['HTTP_X_AUTH_TOKEN']
    signature = env['HTTP_X_AUTH_TOKEN'].sub(BASE64_PADDING, '')
    
    # Check timestamp
    timestamp = parameters['time']
    raise APIKeyError.time unless timestamp
    raise APIKeyError.time if timestamp.to_i < Time.now.to_i - TIMESTAMP_TOLERANCE
    raise APIKeyError.time if timestamp.to_i > Time.now.to_i + TIMESTAMP_TOLERANCE
    
    # Retrieve API key record
    key = @db[:api_keys].where(:key_id => key_id).first
    raise APIKeyError.key unless key
    
    # Find expected signature
    full_path = request.fullpath
    digest  = OpenSSL::Digest::Digest.new('sha1')
    expected_sig = Base64.encode64(OpenSSL::HMAC.digest(digest, key[:secret], full_path)).sub(BASE64_PADDING, '')
    
    raise APIKeyError.sig unless signature == expected_sig
    
    return key[:account_name]
  end
  
  def transactions(account, start_period, stop_period)
    query = @db[:transactions].where('(sent_from = ? OR sent_to = ?)', account, account)
    query = query.where('sent_at >= ?', start_period) if start_period
    query = query.where('sent_at <= ?', stop_period) if stop_period
    query = query.order_by(:sent_at)
    query.select(:sent_at, :sent_from, :sent_to, :amount, :currency).to_a
  end
  
  def paths_via(account, start_period, stop_period)
    query = @db[:shifts].where('(from_account = ? OR to_account = ?)', account, account)
    query = query.join(:transaction_paths, [:path_id])
    query = query.join(:transactions, :transaction_paths__transaction_id => :transactions__transaction_id)
    query = query.where('sent_at >= ?', start_period) if start_period
    query = query.where('sent_at <= ?', stop_period) if stop_period
    query = query.order_by(:sent_at)
    query.select(:sent_at, :transaction_paths__amount, :transactions__currency, :path).distinct.to_a
  end
  
  class APIKeyError < RuntimeError
    def self.time
      APIKeyError.new("Time outside of tolerance")
    end
    
    def self.sig
      APIKeyError.new("Signature invalid")
    end
    
    def self.key
      APIKeyError.new("Key invalid")
    end
    
    def self.access
      APIKeyError.new("Cannot access that account")
    end
  end
end