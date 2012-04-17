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

        # developer has provided options for defining triggers
        if options[:trigger].is_a?(Symbol)
          # convert to hash so we know how to find the trigger
          if self.respond_to?(:relations) && self.relations[options[:trigger].to_s] != nil # ensure that this relation is valid
            options[:trigger] = {:target => options[:trigger], :type => :relation}
          elsif (self.instance_methods + self.private_instance_methods).include?(options[:trigger]) # developer may have specified a method call, let's be sure it exists
            options[:trigger] = {:target => options[:trigger], :type => :method}
          end
        end

        # developer has specified that certain relations can be brought it as deep versions
        unless options[:restore_for].nil?
          options[:restore_for] = [options[:restore_for]] unless options[:restore_for].is_a?(Array) # suger for quick relation specs

          relation_list = options[:restore_for].map do |obj|
            ret = nil
            obj = obj.to_sym if obj.is_a?(String)
            if obj.is_a?(Symbol)
              begin
                hash_data = relations[obj.to_s]
                # do the hard work now and determine info about our relation
                if hash_data != nil && hash_data.class_name != nil && hash_data.class_name.constantize.respond_to?(:most_recent_history)
                  ret = {:target => obj, :target_class => hash_data.class_name.constantize, 
                          :type => hash_data.relation.eql?(Mongoid::Relations::Referenced::ManyToMany) ? :many_to_many : (hash_data.relation.ancestors.include?(Mongoid::Relations::Many) ? :many : :one),
                          :foreign_key => (hash_data.relation.eql?(Mongoid::Relations::Referenced::ManyToMany) ? hash_data.key : hash_data.as)}
                end
              rescue Exception => e
                puts "#{self.name}: Failure to resolve #{obj} relations. Tried #{hash_data.class_name}. #{e}"
              end
            elsif(obj.is_a?(Hash) && obj[:target] != nil && obj[:target_class] != nil)
              ret = obj # developer has provided direct instructions about the relation
            end

            ret
          end

          options[:restore_for] = relation_list.compact

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
        Mongoid::History.tracker_class.where(:scope => history_trackable_options[:scope]).order_by(:created_at.desc)
      end

      def most_recent_history(history_obj, unique = :_id)
        time_point = history_obj.is_a?(Time) ? history_obj : (history_obj.respond_to?(:created_at) ? history_obj.created_at : Time.now)
        ids = history_for_class.where(:created_at.lte => time_point)

        seen_ids = []
        ids = ids.to_a.reject do |history|
          if seen_ids.include?(history.doc_hash[unique.to_s])
            true
          else
            seen_ids << history.doc_hash[unique.to_s]
            false
          end
        end

        history_for_class.in("_id" => ids.map {|obj| obj.id})
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

      def hydrated_from_hash!(original_history = nil)
        @hydrated_from_hash = true

        # override relation accessors
        if history_trackable_options[:restore_for].is_a?(Array)

          # define a method that allows us to inject methods on the fly
          unless self.respond_to?(:metaclass)
            def self.metaclass
              class << self; self; end
            end
          end

          history_trackable_options[:restore_for].each do |restore_data|
            if (restore_data[:target] != nil && restore_data[:target_class] != nil)
              # if the document hash stored an old embedded version then use that
              if original_history != nil && original_history.doc_hash[restore_data[:target].to_s] != nil
                self.metaclass.send(:define_method, restore_data[:target].to_s) do
                  # wakeup
                  if original_history.doc_hash[restore_data[:target].to_s].is_a?(Array)
                    original_history.doc_hash[restore_data[:target].to_s].map {|hash_obj| restore_data[:target_class].instantiate(hash_obj) }
                  else
                    restore_data[:target_class].instantiate(original_history.doc_hash[restore_data[:target].to_s])
                  end
                end
              else # restore the current version based on related history
                target_created_at = original_history.is_a?(History) ? original_history.created_at : self.created_at

                # override our relation lookup
                self.metaclass.send(:define_method, restore_data[:target].to_s) do
                  history_point = restore_data[:target_class].most_recent_history(target_created_at)

                  target_key = restore_data[:foreign_key].nil? ? "#{restore_data[:target]}_id".to_sym : restore_data[:foreign_key]

                  # scope history
                  if restore_data[:type].eql?(:many)
                    history_point = history_point.where("doc_hash.#{target_key}_id" => self.id)
                  elsif restore_data[:type].eql?(:many_to_many)
                    history_point = history_point.in("doc_hash._id" => self.send(target_key))
                  else
                    history_point = history_point.where("doc_hash._id" => self.send(target_key))
                  end

                  # resolve
                  if restore_data[:type].eql?(:one)

                    # couldn't find a history object
                    if (history_point.first.nil?)
                      # find actual in DB that was created before history
                      obj = nil
                      begin
                        restore_data[:target_class].find(self.send(target_key))
                      rescue
                      end
                      obj
                    else
                      if history_point.first.action.eql?('destroy')
                        nil
                      else
                        (history_point.first.trackable_root_from_hash || history_point.first.trackable_from_hash) # restore
                      end
                    end
                  else
                    # filter out duplicate doc_ids
                    seen_ids = []
                    history_point = history_point.to_a.reject do |history|
                      if history.action.eql?('destroy')
                        true
                        seen_ids << history.doc_hash["_id"]
                      else
                        if seen_ids.include?(history.doc_hash["_id"])
                          true
                        else
                          seen_ids << history.doc_hash["_id"]
                          false
                        end
                      end
                    end

                    (history_point.map {|h| (h.trackable_root_from_hash || h.trackable_from_hash) }) # restore for many relation
                  end
                end
              end
            end
          end
        end
      end

      # Received a notification from a relation that it was updated
      def _history_recorded_from_child(child, history_obj, chain = [])
        @history_bubbled_from_child = {:chain => chain, :history => history_obj, :source => child}
        track_update

        @history_bubbled_from_child = nil

        true
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
        track_history? && (!modified_attributes_for_update.blank? || ((!(defined?(@history_bubbled_from_child).nil?)) && @history_bubbled_from_child != nil))
      end

      def should_track_create?
        track_history?
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

        # store info about relation history events

        unless defined?(@history_bubbled_from_child).nil? || @history_bubbled_from_child.nil?
          relation_key = key_for_obj(@history_bubbled_from_child[:source])

          unless relation_key.nil?
            # record the bubble event
            @history_tracker_attributes[:bubble_chain] = [{:key => relation_key, 
                                                          :id => @history_bubbled_from_child[:source].id, 
                                                          :hash => @history_bubbled_from_child[:source].as_document}].concat(@history_bubbled_from_child[:chain])

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
        return unless should_track_create?
        current_version = (self.send(history_trackable_options[:version_field]) || 0 ) + 1
        self.send("#{history_trackable_options[:version_field]}=", current_version)
        history_obj = Mongoid::History.tracker_class.create!(history_tracker_attributes(:create).merge(:version => current_version, :action => "create"))
        clear_memoization

        notify_trigger history_obj
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

      def notify_trigger(history_obj)
        chain = history_obj.nil? || history_obj.bubble_chain.nil? ? [] : history_obj.bubble_chain

        if history_trackable_options[:trigger].is_a?(Hash) && history_trackable_options[:trigger][:type] != nil
          case history_trackable_options[:trigger][:type]
          when :method # developer has defined a special method that we should call
            self.send(history_trackable_options[:trigger][:target], history_obj) if self.respond_to?(history_trackable_options[:trigger][:target])
          when :relation # we have a relation that may support history tracking
            target = self.send(history_trackable_options[:trigger][:target])
            if (target.is_a?(Array)) # target is a many relation
              target.each do |obj|
                obj.send(:_history_recorded_from_child, self, history_obj, chain) if obj.respond_to?(:_history_recorded_from_child)
              end
            else # target is a single relation
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
