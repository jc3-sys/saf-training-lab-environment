# encoding: utf-8
# copyright: 2018, The Authors

git_dir = "/workspaces/saf-training-lab-environment/git_test/.git"

# The following banches should exist
describe git(git_dir) do
  its('branches') { should include 'main' }
  its('branches') { should include 'testBranch' }
  its('current_branch') { should cmp 'main' }
end

# What is the current branch
describe command("git --git-dir #{git_dir} branch") do
  its('stdout') { should match /^\* main/ }
end

# What is the latest commit
describe command("git --git-dir #{git_dir} log -1 --pretty=format:'%h'") do
  its('stdout') { should match /edc207f/ }
end

# What is the second to last commit
describe command("git --git-dir #{git_dir} log --skip=1 -1 --pretty=format:'%h'") do
  its('stdout') { should match /8c30bff/ }
end