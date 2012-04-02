module Mongoid::History
  module Trackable
    extend ActiveSupport::Concern

    module ClassMethods
      def track_history(options={})
        model_name = self.name.tableize.singularize.to_sym
        default_options = {
          :on             =>  :all,
          :except         =>  [:created_at, :updated_at],
          :modifier_field =>  :modifier,
          :version_field  =>  :version,
          :scope          =>  model_name,
          :track_root     =>  true,
          :fetch_related  =>  true,
          :track_create   =>  true,
          :track_update   =>  true,
          :track_destroy  =>  true,
          :trigger        =>  nil,
        }

        options = default_options.merge(options)

        # normalize except fields
        # manually ensure _id, id, version will not be tracked in history
        options[:except] = [options[:except]] unless options[:except].is_a? Array
        options[:except] << options[:version_field]
        options[:except] << "#{options[:modifier_field]}_id".to_sym
        options[:except] += [:_id, :id]
        options[:except] = options[:except].map(&:to_s).flatten.compact.uniq
        options[:except].map(&:to_s)

        # normalize fields to track to either :all or an array of strings
        if options[:on] != :all
          options[:on] = [options[:on]] unless options[:on].is_a? Array
          options[:on] = options[:on].map(&:to_s).flatten.uniq
        end

        if options[:trigger].is_a?(Symbol)
          # convert to hash so we know how to find the trigger
          if self.respond_to?(:relations) && self.relations[options[:trigger].to_s] != nil
            options[:trigger] = {:target => options[:trigger], :type => :relation}
          elsif (self.instance_methods + self.private_instance_methods).include?(options[:trigger])
            options[:trigger] = {:target => options[:trigger], :type => :method}
          end
        end

        field options[:version_field].to_sym, :type => Integer
        referenced_in options[:modifier_field].to_sym, :class_name => Mongoid::History.modifier_class_name

        include InstanceMethods
        extend SingletonMethods

        delegate :history_trackable_options, :to => 'self.class'
        delegate :track_history?, :to => 'self.class'

        before_update :track_update if options[:track_update]
        before_create :track_create if options[:track_create]
        before_destroy :track_destroy if options[:track_destroy]

        Mongoid::History.trackable_classes ||= []
        Mongoid::History.trackable_classes << self
        Mongoid::History.trackable_class_options ||= {}
        Mongoid::History.trackable_class_options[model_name] = options
      end

      def track_history?
        enabled = Thread.current[track_history_flag]
        enabled.nil? ? true : enabled
      end

      def disable_tracking(&block)
        begin
          Thread.current[track_history_flag] = false
          yield
        ensure
          Thread.current[track_history_flag] = true
        end
      end

      def track_history_flag
        "mongoid_history_#{self.name.underscore}_trackable_enabled".to_sym
      end

      def history_for_class
        Mongoid::History.tracker_class.where(:scope => history_trackable_options[:scope]).order_by(:created_at.asc)
      end

      def most_recent_history(history_obj, unique = :_id)
        time_point = history_obj.is_a?(Time) ? history_obj : (history_obj.respond_to?(:created_at) ? history_obj.created_at : Time.now)
        ids = history_for_class.where(:created_at.lte => time_point).distinct("doch_hash.#{unique.to_s}")
        history_for_class.in("doc_hash.#{unique.to_s}" => ids)
      end
    end

    module InstanceMethods
      def history_tracks
        @history_tracks ||= Mongoid::History.tracker_class.where(:scope => history_trackable_options[:scope], :association_chain => traverse_association_chain)
      end

      def undo!(modifier, options_or_version=nil)
        _undo(modifier, options_or_version)
        save!
      end

      def _undo(modifier, options_or_version=nil)
        versions = get_versions_criteria(options_or_version).to_a
        versions.sort!{|v1, v2| v2.version <=> v1.version}

        versions.each do |v|
          undo_attr = v.undo_attr(modifier)
          self.write_attributes(v.undo_attr(modifier), false) # guard_protected_attributes = false
        end
      end
      
      def redo!(modifier, options_or_version=nil)
        _redo(modifier, options_or_version)
        save!
      end

      def _redo(modifier, options_or_version=nil)
        versions = get_versions_criteria(options_or_version).to_a
        versions.sort!{|v1, v2| v1.version <=> v2.version}

        versions.each do |v|
          redo_attr = v.redo_attr(modifier)
          self.write_attributes(redo_attr, false) # guard_protected_attributes = false
        end
      end

      def hydrated_from_hash?
        !(defined?(@hydrated_from_hash).nil?) && @hydrated_from_hash.eql?(true)
      end

      def hydrated_from_hash!
        @hydrated_from_hash = true
      end

      def _history_recorded_from_child(child, history_obj, chain = [])
        @history_bubbled_from_child = {:chain => chain, :history => history_obj, :source => child}

        track_update
      end
    
    ##
    # PRIVATE
    private
      def get_versions_criteria(options_or_version)
        if options_or_version.is_a? Hash
          options = options_or_version
          if options[:from] && options[:to]
            lower = options[:from] >= options[:to] ? options[:to] : options[:from]
            upper = options[:from] <  options[:to] ? options[:to] : options[:from]
            versions = history_tracks.where( :version.in => (lower .. upper).to_a )
          elsif options[:last]
            versions = history_tracks.limit( options[:last] )
          else
            raise "Invalid options, please specify (:from / :to) keys or :last key."
          end
        else
          options_or_version = options_or_version.to_a if options_or_version.is_a?(Range)
          version_field_name = history_trackable_options[:version_field]
          version = options_or_version || self.attributes[version_field_name] || self.attributes[version_field_name.to_s]
          version = [ version ].flatten
          versions = history_tracks.where(:version.in => version)
        end
        versions.desc(:version)
      end

      def should_track_update?
        track_history? && (!modified_attributes_for_update.blank? || !(defined?(@history_bubbled_from_child).nil?))
      end

      def traverse_association_chain(node=self)
        list = node._parent ? traverse_association_chain(node._parent) : []
        list << { 'name' => node.class.name, 'id' => node.id }
        list
      end

      def modified_attributes_for_update
        if history_trackable_options[:on] == :all
          changes.reject do |k, v|
            history_trackable_options[:except].include?(k)
          end
        else
          changes.reject do |k, v|
            !history_trackable_options[:on].include?(k)
          end

        end
      end

      def modified_attributes_for_create
        attributes.inject({}) do |h, pair|
          k,v =  pair
          h[k] = [nil, v]
          h
        end.reject do |k, v|
          history_trackable_options[:except].include?(k)
        end
      end
    
      # Note: Does not filter by any attributes
      def modified_attributes_for_destroy
        attributes.inject({}) do |h, pair|
          k,v =  pair
          h[k] = [nil, v]
          h
        end
      end

      def key_for_obj(obj)
        self.class.relations.keys.each do |key|
          target = self.send(key.to_sym)
          return key if (target.eql?(obj) || target.respond_to?(:include?) && target.include?(obj))
        end

        nil
      end

      def history_tracker_attributes(method)
        return @history_tracker_attributes if @history_tracker_attributes

        @history_tracker_attributes = {
          :association_chain  => traverse_association_chain,
          :doc_hash           => self.as_document,
          :doc_name           => self.class.name,
          :is_embedded        => embedded?,
          :scope              => history_trackable_options[:scope],
          :modifier           => send(history_trackable_options[:modifier_field])
        }
        
        # If embedded, store a copy of the root object as well (can be quite heavy)
        if history_trackable_options[:track_root] && embedded?
          @history_tracker_attributes[:root_hash] = _root.as_document
          @history_tracker_attributes[:root_name] = _root.class.name
        end

        original, modified = transform_changes(case method
          when :destroy then modified_attributes_for_destroy
          when :create then modified_attributes_for_create
          else modified_attributes_for_update
        end)

        unless defined?(@history_bubbled_from_child).nil?
          relation_key = key_for_obj(@history_bubbled_from_child[:source])

          unless relation_key.nil?
            original[relation_key] = @history_bubbled_from_child[:history][:original]
            modified[relation_key] = @history_bubbled_from_child[:history][:modified]
          end
        end

        @history_tracker_attributes[:original] = original
        @history_tracker_attributes[:modified] = modified
        
        # Fetch related fields and call to_s
        if history_trackable_options[:fetch_related]
          @history_tracker_attributes[:original].dup.each do |k, v|
            if k =~ /(.+)_id$/
              k_name = $1.to_s
              if !v.blank? && self.relations.include?(k_name)
                @history_tracker_attributes[:original][k_name] = self.relations[k_name].class_name.constantize.find(v).to_s
              end
            end
          end
          @history_tracker_attributes[:modified].dup.each do |k, v|
            if k =~ /(.+)_id$/
              k_name = $1.to_s
              if !v.blank? && self.relations.include?(k_name)
                @history_tracker_attributes[:modified][k_name] = self.send(k_name).to_s
              end
            end
          end
        end
        
        @history_tracker_attributes
      end

      def track_update
        return unless should_track_update?
        current_version = (self.send(history_trackable_options[:version_field]) || 0 ) + 1
        self.send("#{history_trackable_options[:version_field]}=", current_version)
        history_obj = Mongoid::History.tracker_class.create!(history_tracker_attributes(:update).merge(:version => current_version, :action => "update"))
        clear_memoization

        notify_trigger history_obj
      end

      def track_create
        return unless track_history?
        current_version = (self.send(history_trackable_options[:version_field]) || 0 ) + 1
        self.send("#{history_trackable_options[:version_field]}=", current_version)
        history_obj = Mongoid::History.tracker_class.create!(history_tracker_attributes(:create).merge(:version => current_version, :action => "create"))
        clear_memoization
      end

      def track_destroy
        return unless track_history?
        current_version = (self.send(history_trackable_options[:version_field]) || 0 ) + 1
        history_obj = Mongoid::History.tracker_class.create!(history_tracker_attributes(:destroy).merge(:version => current_version, :action => "destroy"))
        clear_memoization

        notify_trigger history_obj
      end

      def clear_memoization
        @history_tracker_attributes =  nil
        #:ToDo: Find a way to make this work reliably
        #@modified_attributes_for_create = nil
        #@modified_attributes_for_update = nil
        #@modified_attributes_for_destroy = nil
        @history_tracks = nil
      end

      ##
      # This function now honours nil values
      def transform_changes(changes)
        original = {}
        modified = {}
        changes.each_pair do |k, v|
          o, m = v
          original[k] = o
          modified[k] = m
        end

        return [original, modified]
      end

      def notify_trigger(history_obj, chain = nil)
        chain = @history_bubbled_from_child if chain.nil? && !(defined?(@history_bubbled_from_child).nil?)

        if history_trackable_options[:trigger].is_a?(Hash) && history_trackable_options[:trigger][:type] != nil
          case history_trackable_options[:trigger][:type]
          when :method
            self.send(history_trackable_options[:trigger][:target], history_obj) if self.respond_to?(history_trackable_options[:trigger][:target])
          when :relation
            target = self.send(history_trackable_options[:trigger][:target])
            if (target.is_a?(Array))
              target.each do |obj|
                obj.send(:_history_recorded_from_child, self, history_obj, chain) if obj.respond_to?(:_history_recorded_from_child)
              end
            else
              target.send(:_history_recorded_from_child, self, history_obj, chain) if target.respond_to?(:_history_recorded_from_child)
            end
          end
        end
      end

    end

    module SingletonMethods
      def history_trackable_options
        @history_trackable_options ||= Mongoid::History.trackable_class_options[self.name.tableize.singularize.to_sym]
      end
    end

  end
end
