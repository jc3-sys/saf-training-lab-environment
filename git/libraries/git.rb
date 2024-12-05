# encoding: utf-8
# copyright: 2019, The Authors

class Git < Inspec.resource(1)
  name 'git'

  def initialize(path)
    @path = path
  end

  def branches
    inspec.command("git --git-dir #{@path} branch").stdout
  end

  def current_branch
    branch_name = inspec.command("git --git-dir #{@path} branch").stdout.strip.split("\n").find do |name|
        name.start_with?('*')
    end
    branch_name.gsub(/^\*/,'').strip
  end

end