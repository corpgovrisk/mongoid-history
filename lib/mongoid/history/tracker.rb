module Mongoid::History
  module Tracker
    extend ActiveSupport::Concern

    included do
      include Mongoid::Document
      include Mongoid::Timestamps

      field           :association_chain,   :type => Array,     :default => []
      field           :modified,            :type => Hash
      field           :original,            :type => Hash

      field           :doc_hash,            :type => Hash
      field           :doc_name,            :type => String
      field           :is_embedded,         :type => Boolean

      field           :root_hash,           :type => Hash       # Optional
      field           :root_name,           :type => String     # Optional

      field           :bubble_chain,        :type => Array,     :default => []   

      field           :version,             :type => Integer
      field           :action,              :type => String
      field           :scope,               :type => String
      referenced_in   :modifier,            :class_name => Mongoid::History.modifier_class_name

      Mongoid::History.tracker_class_name = self.name.tableize.singularize.to_sym
    end

    # ##
    # # Note: I recommend this be limited to only when the action is :destroy (when restoring a removed object)
    # def undo!(modifier)
    #   if action.to_sym == :destroy
    #     class_name = association_chain[0]["name"]
    #     restored = class_name.constantize.new(modified)
    #     restored.save!
    #   else
    #     trackable.update_attributes!(undo_attr(modifier), :without_protection => true)
    #   end
    # end

    # ##
    # # Note: I recommend this be limited to only when the action is :destroy (when removing an object)
    # def redo!(modifier)
    #   if action.to_sym == :destroy
    #     trackable.destroy
    #   else
    #     trackable.update_attributes!(redo_attr(modifier), :without_protection => true)
    #   end
    # end

    def undo_attr(modifier)
      undo_hash = affected.easy_unmerge(modified)
      undo_hash.easy_merge!(original)
      # Note: easy_merge!() choses nil only if the key doesn't exist in the called hash
      undo_hash.merge!(undo_remove_attr(modifier))
      modifier_field = trackable.history_trackable_options[:modifier_field]
      undo_hash[modifier_field] = modifier
      undo_hash
    end
    
    ##
    # Attributes that need to be removed as part of the "undo"
    def undo_remove_attr(modifier)
      remove_attribute_keys = (modified.keys - original.keys)
      undo_remove_hash = {}
      remove_attribute_keys.each do |attr_key|
        undo_remove_hash.easy_merge! attr_key => nil
      end
      undo_remove_hash
    end

    def redo_attr(modifier)
      redo_hash = affected.easy_unmerge(original)
      redo_hash.easy_merge!(modified)
      modifier_field = trackable.history_trackable_options[:modifier_field]
      redo_hash[modifier_field] = modifier
      redo_hash
    end

    def trackable_root
      @trackable_root ||= trackable_parents_and_trackable.first
    end

    ##
    # Note: This is a best effort method (a result is not guarenteed, and any failure returns nil (rescue nil))
    def trackable_root_from_hash
      return unless root_name && root_hash
      @trackable_root_from_hash ||= 
        Mongoid::Factory.from_db(doc_name.classify.constantize, root_hash) rescue nil
      @trackable_root_from_hash["_history_id"] = self.id
      @trackable_root_from_hash.hydrated_from_hash!(self) if !(defined?(@trackable_root_from_hash).nil?) &&  @trackable_root_from_hash.respond_to?(:hydrated_from_hash!)
      @trackable_root_from_hash
    end
    
    def trackable
      if (action == 'destroy') 
        @trackable ||= association_chain.last['name'].classify.constantize.new(modified)
      end
      @trackable ||= trackable_parents_and_trackable.last
    end

    ##
    # Note: This is a best effort method (a result is not guarenteed, and any failure returns nil (rescue nil))
    def trackable_from_hash
      return unless doc_name && doc_hash
      klass = doc_name.classify.constantize
      @trackable_from_hash ||=
        klass.instantiate(doc_hash) rescue nil
      @trackable_from_hash["_history_id"] = self.id
      @trackable_from_hash.hydrated_from_hash!(self) if !(defined?(@trackable_from_hash).nil?) &&  @trackable_from_hash.respond_to?(:hydrated_from_hash!)
      @trackable_from_hash
    end
    
    def trackable_parents
      @trackable_parents ||= trackable_parents_and_trackable[0, -1]
    end

    def affected
      @affected ||= (modified.keys | original.keys).inject({}){ |h,k| h[k] = 
        trackable ? trackable.attributes[k] : modified[k]; h}
    end

    def chain_for_bubble_key(key)
      return nil if self.bubble_chain.nil?
      indexed_mark = self.bubble_chain.index {|obj| obj["key"].eql?(key)}

      indexed_mark.nil? ? nil : self.bubble_chain[indexed_mark]
    end

    def modification_as_array(mod_hash = nil)
      res = []
      mod_hash = self.modified if mod_hash.nil?
      mod_hash.each do |key, value|
        chain = chain_for_bubble_key(key)
        unless chain.nil?
          # try to resolve the type of the relation
          res << {:key => key, :value => chain, :hash => value}
          res = res + modification_as_array(value)
        end
      end
      res
    end

    def original_as_array(orig_hash = nil)
      res = []
      orig_hash = self.original if orig_hash.nil?
      orig_hash.each do |key, value|
        chain = chain_for_bubble_key(key)
        unless chain.nil?
          # try to resolve the type of the relation
          res << {:key => key, :value => chain, :hash => value}
          res = res + original_as_array(value)
        end
      end
      res
    end

    def all_actions
      acts = self.bubble_chain.map{|h| h["history_obj"]["action"] rescue nil}
      acts << self.action
      acts.compact
    end

    def prominent_action
      return 'destroy' if all_actions.include?('destroy')
      return 'create' if all_actions.include?('create')

      self.action
    end

    private
      def trackable_parents_and_trackable
        @trackable_parents_and_trackable ||= traverse_association_chain
      end
      
      def traverse_association_chain
        chain = association_chain.dup
        doc = nil
        documents = []
        begin
          node = chain.shift
          name = node['name']
          col  = doc.nil? ? name.classify.constantize : doc.send(name.tableize)
          doc  = col.where(:_id => node['id']).first
          documents << doc
        end while( !chain.empty? )
        documents
      end

  end
end
