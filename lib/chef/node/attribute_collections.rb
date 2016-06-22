#--
# Author:: Daniel DeLeo (<dan@chef.io>)
# Copyright:: Copyright 2012-2016, Chef Software, Inc.
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

class Chef
  class Node

    # == AttrArray
    # AttrArray is identical to Array, except that it keeps a reference to the
    # "root" (Chef::Node::Attribute) object, and will trigger a cache
    # invalidation on that object when mutated.
    class AttrArray < Array

      MUTATOR_METHODS = [
        :<<,
        :[]=,
        :clear,
        :collect!,
        :compact!,
        :default=,
        :default_proc=,
        :delete,
        :delete_at,
        :delete_if,
        :fill,
        :flatten!,
        :insert,
        :keep_if,
        :map!,
        :merge!,
        :pop,
        :push,
        :update,
        :reject!,
        :reverse!,
        :replace,
        :select!,
        :shift,
        :slice!,
        :sort!,
        :sort_by!,
        :uniq!,
        :unshift,
      ]

      # For all of the methods that may mutate an Array, we override them to
      # also invalidate the cached merged_attributes on the root
      # Node::Attribute object.
      MUTATOR_METHODS.each do |mutator|
        define_method(mutator) do |*args, &block|
          ret = super(*args, &block)
          root.reset_cache(root.top_level_breadcrumb)
          ret
        end
      end

      attr_reader :root

      def initialize(root, data)
        @root = root
        super(data)
      end

      # For elements like Fixnums, true, nil...
      def safe_dup(e)
        e.dup
      rescue TypeError
        e
      end

      def dup
        Array.new(map { |e| safe_dup(e) })
      end

    end

    # == VividMash
    # VividMash is identical to a Mash, with a few exceptions:
    # * It has a reference to the root Chef::Node::Attribute to which it
    #   belongs, and will trigger cache invalidation on that object when
    #   mutated.
    # * It auto-vivifies, that is a reference to a missing element will result
    #   in the creation of a new VividMash for that key. (This only works when
    #   using the element reference method, `[]` -- other methods, such as
    #   #fetch, work as normal).
    # * attr_accessor style element set and get are supported via method_missing
    class VividMash < Mash
      attr_reader :root

      # Methods that mutate a VividMash. Each of them is overridden so that it
      # also invalidates the cached merged_attributes on the root Attribute
      # object.
      MUTATOR_METHODS = [
        :clear,
        :delete,
        :delete_if,
        :keep_if,
        :merge!,
        :update,
        :reject!,
        :replace,
        :select!,
        :shift,
      ]

      # For all of the mutating methods on Mash, override them so that they
      # also invalidate the cached `merged_attributes` on the root Attribute
      # object.
      MUTATOR_METHODS.each do |mutator|
        define_method(mutator) do |*args, &block|
          root.reset_cache(root.top_level_breadcrumb)
          super(*args, &block)
        end
      end

      def initialize(root, data = {})
        @root = root
        super(data)
      end

      def [](key)
        root.top_level_breadcrumb ||= key
        value = super
        if !key?(key)
          value = self.class.new(root)
          self[key] = value
        else
          value
        end
      end

      def []=(key, value)
        root.top_level_breadcrumb ||= key
        ret = super
        root.reset_cache(root.top_level_breadcrumb)
        ret
      end

      alias :attribute? :has_key?

      def method_missing(symbol, *args)
        # Calling `puts arg` implicitly calls #to_ary on `arg`. If `arg` does
        # not implement #to_ary, ruby recognizes it as a single argument, and
        # if it returns an Array, then ruby prints each element. If we don't
        # account for that here, we'll auto-vivify a VividMash for the key
        # :to_ary which creates an unwanted key and raises a TypeError.
        if symbol == :to_ary
          super
        elsif args.empty?
          self[symbol]
        elsif symbol.to_s =~ /=$/
          key_to_set = symbol.to_s[/^(.+)=$/, 1]
          self[key_to_set] = (args.length == 1 ? args[0] : args)
        else
          raise NoMethodError, "Undefined node attribute or method `#{symbol}' on `node'. To set an attribute, use `#{symbol}=value' instead."
        end
      end

      # method-style accss to attributes

      # - autovivifying / autoreplacing writer
      # - non-container-ey intermediate objects are replaced with hashes
      def write(*path, last, value)
        prev_memo = prev_key = nil
        chain = path.inject(self) do |memo, key|
          if !(memo.is_a?(Array) || memo.is_a?(Hash)) || (memo.is_a?(Array) && !key.is_a?(Fixnum))
            prev_memo[prev_key] = {}
            memo = prev_memo[prev_key]
          end
          prev_memo = memo
          prev_key = key
          memo[key]
        end
        if !(chain.is_a?(Array) || chain.is_a?(Hash)) || (chain.is_a?(Array) && !last.is_a?(Fixnum))
          prev_memo[prev_key] = {}
          chain = prev_memo[prev_key]
        end
        chain[last] = value
      end

      # this autovivifies, but can throw NoSuchAttribute when trying to access #[] on
      # something that is not a container ("schema violation" issues).
      #
      def write!(*path, last, value)
        obj = path.inject(self) do |memo, key|
          raise Chef::Exceptions::AttributeTypeMismatch unless memo.is_a?(Array) || memo.is_a?(Hash)
          raise Chef::Exceptions::AttributeTypeMismatch if memo.is_a?(Array) && !key.is_a?(Fixnum)
          memo[key]
        end
        raise Chef::Exceptions::AttributeTypeMismatch unless obj.is_a?(Array) || obj.is_a?(Hash)
        raise Chef::Exceptions::AttributeTypeMismatch if obj.is_a?(Array) && !last.is_a?(Fixnum)
        obj[last] = value
      end

      # FIXME:(?) does anyone need a non-autovivifying writer for attributes that throws exceptions?

      # return true or false based on if the attribute exists
      def exist?(*path)
        path.inject(self) do |memo, key|
          if memo.is_a?(Hash)
            if memo.key?(key)
              memo[key]
            else
              return false
            end
          elsif memo.is_a?(Array)
            if !key.is_a?(Fixnum)
              return false
            elsif memo.length > key
              memo[key]
            else
              return false
            end
          else
            return false
          end
        end
        return true
      end

      # this is a safe non-autovivifying reader that returns nil if the attribute does not exist
      def read(*path)
        begin
          read!(*path)
        rescue Chef::Exceptions::NoSuchAttribute
          nil
        end
      end

      # non-autovivifying reader that throws an exception if the attribute does not exist
      def read!(*path)
        raise Chef::Exceptions::NoSuchAttribute unless exist?(*path)
        path.inject(self) do |memo, key|
          memo[key]
        end
      end

      # FIXME:(?) does anyone really like the autovivifying reader that we have and wants the same behavior?

      def unlink(*path, last)
        root.reset_cache
        hash = read(*path)
        return nil unless hash.is_a?(Hash)
        hash.delete(last)
      end

      def unlink!(*path)
        raise "not implemented"
      end

      def convert_key(key)
        super
      end

      # Mash uses #convert_value to mashify values on input.
      # We override it here to convert hash or array values to VividMash or
      # AttrArray for consistency and to ensure that the added parts of the
      # attribute tree will have the correct cache invalidation behavior.
      def convert_value(value)
        case value
        when VividMash
          value
        when Hash
          VividMash.new(root, value)
        when Array
          AttrArray.new(root, value)
        else
          value
        end
      end

      def dup
        Mash.new(self)
      end

    end
  end
end
