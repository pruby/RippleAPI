require "bundler/setup"

require 'rack'
require 'json'
require 'sequel'
require 'sequel/extensions/pg_array'
require 'openssl'
require 'base64'

class RippleAPI
  TIMESTAMP_TOLERANCE = 300
  ACCOUNT_SUFFIX = /([A-Za-z0-9_]+)\.json$/
  
  def initialize(db)
    @db = db
  end
  
  def call(env)
    request = Rack::Request.new(env)
    status = 404
    headers = {'Content-type' => 'text/plain'}
    result = 'Not found'
    
    begin
      account = nil
      if request.path.match(ACCOUNT_SUFFIX)
        md = request.path.match(ACCOUNT_SUFFIX)
        account = md[1]
        api_key_check(account, request)
      end
      
      case request.path
        when /^\/transactions\/#{ACCOUNT_SUFFIX}/
          status = 200
          result = transactions(account, request['start'], request['stop'])
        when /^\/paths\/via\/#{ACCOUNT_SUFFIX}/
          status = 200
          result = paths_via(account, request['start'], request['stop'])
        when /^\/trusts\/trusted_by\/#{ACCOUNT_SUFFIX}/
          status = 200
          result = @db[:trusts].where(:trustor => account).select(:trustor, :trustee, :amount, :currency).to_a
        when /^\/trusts\/who_trusts\/#{ACCOUNT_SUFFIX}/
          status = 200
          result = @db[:trusts].where(:trustee => account).select(:trustor, :trustee, :amount, :currency).to_a
        when /^\/debts\/owed_by\/#{ACCOUNT_SUFFIX}/
          status = 200
          result = @db[:debts].where(:debt_from => account).select(:debt_from, :debt_to, :amount, :currency).to_a
        when /^\/debts\/owed_to\/#{ACCOUNT_SUFFIX}/
          status = 200
          result = @db[:debts].where(:debt_to => account).select(:debt_from, :debt_to, :amount, :currency).to_a
      end
    rescue APIKeyError => e
      status = 403
      result = e.message
    end
    [status, headers, [result.to_json]]
  end
  
  def api_key_check(account, request)
    # Check for key and signature
    key_id = request[:key].to_s
    raise APIKeyError.key unless key_id
    
    query_string = request.query_string
    raise APIKeyError.sig unless query_string.match(/&sig=[A-Za-z0-9+\/]+=*\z/)
    
    # Check timestamp
    timestamp = request[:time]
    raise APIKeyError.time unless timestamp
    raise APIKeyError.time unless timestamp.to_i > Time.now.to_i - TIMESTAMP_TOLERANCE
    raise APIKeyError.time unless timestamp.to_i < Time.now.to_i + TIMESTAMP_TOLERANCE
    
    # Retrieve API key record
    key = @db[:api_keys].where(:key_id => key_id).first
    raise APIKeyError.key unless key
    
    # Find expected signature
    full_path = request.fullpath.sub(/=+$/, '')
    trimmed_path = full_path.sub(/&sig=[A-Za-z0-9+\/]+=*\z/, '')
    digest  = OpenSSL::Digest::Digest.new('sha1')
    expected_sig = Base64.b64encode(OpenSSL::HMAC.digest(digest, key[:secret], trimmed_path).sub(/=+$/, ''))
    expected_path = trimmed_path + '&sig=' + expected_sig
    p expected_sig
    raise APIKeyError.sig unless full_path == expected_path
    
    # Check for access to this account
    access = @db[:account_managers].where(:account_name => account, :minecraft_name => key[:minecraft_name])
    raise APIKeyError.access unless access.exists
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