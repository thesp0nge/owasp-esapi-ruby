require 'rubygems'
require 'rake'

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gem|
    gem.name = "owasp-esapi-ruby"
    gem.summary = %Q{Owasp Enterprise Security APIs for Ruby language}
    gem.description = File.read(File.join(File.dirname(__FILE__), 'README'))
    gem.email = "thesp0nge@owasp.org"
    gem.version = File.read(File.join(File.dirname(__FILE__), 'VERSION'))
    gem.homepage = "http://github.com/thesp0nge/owasp-esapi-ruby"
    gem.authors = File.read(File.join(File.dirname(__FILE__), 'AUTHORS'))
    gem.spec.required_ruby_version = '>= 1.9.2'
    gem.add_development_dependency "rspec", ">= 1.2.9"
    gem.add_development_dependency "yard", ">= 0"
    
    # gem is a Gem::Specification... see http://www.rubygems.org/read/chapter/20 for additional settings
  end
  Jeweler::GemcutterTasks.new
rescue LoadError
  puts "Jeweler (or a dependency) not available. Install it with: gem install jeweler"
end

require 'rspec/core/rake_task' 
RSpec::Core::RakeTask.new(:spec) do |t| 
  t.pattern = "./spec/**/*_spec.rb" 
  # Put spec opts in a file named .rspec in root 
end

# require 'spec/rake/spectask'
# Spec::Rake::SpecTask.new(:spec) do |spec|
#   spec.libs << 'lib' << 'spec'
#   spec.spec_files = FileList['spec/**/*_spec.rb']
# end

# Spec::Rake::SpecTask.new(:rcov) do |spec|
#   spec.libs << 'lib' << 'spec'
#   spec.pattern = 'spec/**/*_spec.rb'
#   spec.rcov = true
# end

task :spec => :check_dependencies

task :default => :spec

begin
  require 'yard'
  YARD::Rake::YardocTask.new
rescue LoadError
  task :yardoc do
    abort "YARD is not available. In order to run yardoc, you must: sudo gem install yard"
  end
end

