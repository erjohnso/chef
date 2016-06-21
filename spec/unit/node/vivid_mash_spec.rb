#
# Copyright:: Copyright 2016, Chef Software Inc.
# License:: Apache License, Version 2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require "spec_helper"
require "chef/node/attribute_collections"

describe Chef::Node::VividMash do
  class Root
    attr_accessor :top_level_breadcrumb
  end

  let(:root) { Root.new }

  let(:vivid) do
    expect(root).to receive(:reset_cache).at_least(:once).with(nil)
    Chef::Node::VividMash.new(root, { "one" => { "two" => { "three" => "four" } }, "array" => [ 0, 1, 2 ], "nil" => nil })
  end

  context "#read" do
    before do
      # vivify the vividmash, then we're read-only so the cache should never be cleared afterwards
      vivid
      expect(root).not_to receive(:reset_cache)
    end

    it "reads deeply" do
      expect(root).to receive(:top_level_breadcrumb=).with("one").and_call_original
      expect(vivid.read("one", "two", "three")).to eql("four")
    end

    it "does not trainwreck" do
      expect(root).to receive(:top_level_breadcrumb=).with("one").and_call_original
      expect(vivid.read("one", "five", "six")).to eql(nil)
    end
  end

  context "#exist?" do
    before do
      # vivify the vividmash, then we're read-only so the cache should never be cleared afterwards
      vivid
      expect(root).not_to receive(:reset_cache)
    end

    it "true if there's a hash key there" do
      expect(root).to receive(:top_level_breadcrumb=).with("one").and_call_original
      expect(vivid.exist?("one", "two", "three")).to be true
    end

    it "true for intermediate hashes" do
      expect(root).to receive(:top_level_breadcrumb=).with("one").and_call_original
      expect(vivid.exist?("one")).to be true
    end

    it "true for arrays that exist" do
      expect(root).to receive(:top_level_breadcrumb=).with("array").and_call_original
      expect(vivid.exist?("array", 1)).to be true
    end

    it "true when the value of the key is nil" do
      expect(root).to receive(:top_level_breadcrumb=).with("nil").and_call_original
      expect(vivid.exist?("nil")).to be true
    end

    it "false when attributes don't exist" do
      expect(root).to receive(:top_level_breadcrumb=).with("one").and_call_original
      expect(vivid.exist?("one", "five", "six")).to be false
    end

    it "false when traversing a non-container" do
      expect(root).to receive(:top_level_breadcrumb=).with("one").and_call_original
      expect(vivid.exist?("one", "two", "three", "four")).to be false
    end

    it "false when an array index does not exist" do
      expect(root).to receive(:top_level_breadcrumb=).with("array").and_call_original
      expect(vivid.exist?("array", 3)).to be false
    end

    it "false when traversing a nil" do
      expect(root).to receive(:top_level_breadcrumb=).with("nil").and_call_original
      expect(vivid.exist?("nil", "foo", "bar")).to be false
    end
  end

  context "#read!" do
    before do
      # vivify the vividmash, then we're read-only so the cache should never be cleared afterwards
      vivid
      expect(root).not_to receive(:reset_cache)
    end

    it "reads hashes deeply" do
      expect(root).to receive(:top_level_breadcrumb=).with("one").and_call_original
      expect(vivid.read!("one", "two", "three")).to eql("four")
    end

    it "reads arrays deeply" do
      expect(root).to receive(:top_level_breadcrumb=).with("array").and_call_original
      expect(vivid.read!("array", 1)).to eql(1)
    end

    it "throws an exception when attributes do not exist" do
      expect(root).to receive(:top_level_breadcrumb=).with("one").and_call_original
      expect(vivid.read!("one", "five", "six")).to eql(nil)
    end

    it "throws an exception when traversing a non-container" do
      expect(root).to receive(:top_level_breadcrumb=).with("one").and_call_original
      expect(vivid.read!("one", "two", "three", "four")).to eql(nil)
    end

    it "throws an exception when an array element does not exist" do
      expect(root).to receive(:top_level_breadcrumb=).with("array").and_call_original
      expect(vivid.read!("array", 3)).to eql(nil)
    end
  end

  context "#write" do
  end
end
