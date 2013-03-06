$:.unshift(File.expand_path(File.dirname(__FILE__)))
require 'ripple_api'
require 'yaml'

config = YAML.load_file(File.dirname(__FILE__) + '/database.yml')

db = Sequel.connect(config['database'])

app = RippleAPI.new(db)
run app