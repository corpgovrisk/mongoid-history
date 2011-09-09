module Mongoid::History
  module Tracker
    extend ActiveSupport::Concern

    included do
      include Mongoid::Document
      include Mongoid::Timestamps

      field       :association_chain,       :type => Array,     :default => []
      field       :modified,                :type => Hash
      field       :original,                :type => Hash
      field       :version,                 :type => Integer
      field       :action,                  :type => String
      field       :scope,                   :type => String
      referenced_in :modifier,              :class_name => Mongoid::History.modifier_class_name

      Mongoid::History.tracker_class_name = self.name.tableize.singularize.to_sym
    end

    ##
    # PH: I recommend this be limited to used only when the action is :destroy (when restoring a removed object)
    def undo!(modifier)
      if action.to_sym == :destroy
        class_name = association_chain[0]["name"]
        restored = class_name.constantize.new(modified)
        restored.save!
      else
        trackable.update_attributes!(undo_attr(modifier))
      end
    end

    ##
    # PH: I recommend this be limited to used only when the action is :destroy (when removing an object)
    def redo!(modifier)
      if action.to_sym == :destroy
        trackable.destroy
      else
        trackable.update_attributes!(redo_attr(modifier))
      end
    end

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

    def trackable
      @trackable ||= trackable_parents_and_trackable.last
    end

    def trackable_parents
      @trackable_parents ||= trackable_parents_and_trackable[0, -1]
    end

    def affected
      @affected ||= (modified.keys | original.keys).inject({}){ |h,k| h[k] = 
        trackable ? trackable.attributes[k] : modified[k]; h}
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
