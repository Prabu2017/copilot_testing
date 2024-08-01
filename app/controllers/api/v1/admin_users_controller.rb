class Api::V1::AdminUsersController < Api::V1::BaseController
    include ApplicationHelper
    # skip_before_action :verify_authenticity_token, only: [:update]
    before_action :doorkeeper_authorize!, except: [:sign_in, :forgot_password, :reset_password, :send_token, :verify_token, :enable_authy, :session_valid, :auth_login, :verify_one_touch, :validate_session, :sign_out, :generate_reset_token, :validate_password]
    before_action :set_admin_users, only: [:show_firm_users, :show, :update, :deactivate_user, :add_role, :delete_role, :add_firm_group, :deactivate_user, :remove_firm_group, :remove_firm_group_member, :reassign_advisor, :reassign_households, :login_as, :activities, :activity, :validate_token, :primary_households]
    before_action :set_admin_user, only: [:show, :update, :deactivate_user, :add_role, :delete_role, :add_firm_group, :deactivate_user, :remove_firm_group, :remove_firm_group_member, :login_as, :activities, :activity, :validate_token, :primary_households]
    after_action :darktrace_log_events, only: [:sign_in, :forgot_password, :reset_password, :sign_out, :auth_login, :send_token, :verify_one_touch, :enable_authy, :verify_token]
  
    def show 
      @firm = current_firm
      admin_user = AdminUser.find_by(id: params[:id])
      @is_accessed_by = AdminUsersRole.joins(:role).joins(:admin_user).where(roles: {resource_type: 'AdminUser', resource_id: admin_user.id}).order("admin_users.first_name asc, admin_users.last_name asc")
    end
  
    def create
      @admin_user = current_firm.admin_users.new(firm_admin_user_params)
      if @admin_user.save
        render json: {message: "Admin User Created successfully", status: true }
      else
        render_error(@admin_user,:ok)  
      end
    end
  
    def update
      if @admin_user.update(firm_admin_user_params)
        render json: {message: "Admin User updated successfully", status: true }
      else  
        render_error(@admin_user,:ok)
      end
    end
  
    def deactivate_user
      if @admin_user.de_activate
        render json: {status: true}
      else
        render json: {status: false}
      end
    end
  
    def add_role
      resource_klass = get_valid_resource(params[:resource_type])
      resource = resource_klass.where(id: params[:resource_id]).last if resource_klass.present?
      if resource.present?
        @admin_user.add_role(params[:role].to_sym, resource)
        render json: {message: "Role Added successfully" , status: true}
      else
        render json: {message: "Not a valid #{params[:resource_type]}.camelize" , status: false}
      end  
    end
  
    def delete_role
      admin_user_role = AdminUsersRole.find_by(admin_user_id: @admin_user.id, role_id: params[:role_id])
      if admin_user_role.present?
        admin_user_role.destroy!
        render json: {message: "Role deleted successfully"}
      else
        render json: {message: "Role does not exist"}
      end    
  
      # this appears to delete the role object not the admin_user_role object, this is super bad
      # role = @admin_user.roles.find_by_id(params[:role_id])
      # if role.present?
      #   role.destroy!
      #   render json: {message: "Role deleted successfully"}
      # else
      #   render json: {message: "Role does not exist"}
      # end
    end
  
    def remove_user_role
      admin_user_role = AdminUsersRole.find_by_id(params[:admin_users_role_id])
      if admin_user_role.present?
        admin_user_role.destroy!
        render json: {message: "Role deleted successfully"}
      else
        render json: {message: "Role does not exist"}
      end    
    end
  
    def add_firm_group
      firm_group = current_firm.firm_groups.where(id: params[:firm_group_id]).last
      if firm_group.present?
        firm_group.admin_users << @admin_user
        firm_group.update_attribute("member_count", firm_group.firm_group_members.count)
        render json: {status: true, message: "User added to the group"}
      else
        render json: {status: false, message: "Not a valid group"}
      end
    end
  
    def remove_firm_group
      firm_group= @admin_user.firm_groups.where(id: params[:firm_group_id]).last
      if firm_group.present?
        firm_group.destroy
        render json: {status: true, message: "Group deleted successfully."}
      else
        render json: {status: false, message: "Not a valid group"}
      end
    end
  
    def remove_firm_group_member
      firm_group = @admin_user.firm_groups.where(id: params[:firm_group_id]).last
      if firm_group.present?
        firm_group_member = firm_group.firm_group_members.where(admin_user_id: params[:firm_group_member_id]).last
        if firm_group_member.present?
          firm_group_member.destroy
          firm_group.update_attribute("member_count", firm_group.firm_group_members.count)
          render json: {status: true, message: "User removed from the group"}
        else
          render json: {status: false, message: "Not a valid group member"}
        end
      else
        render json: {status: false, message: "Not a valid group"}
      end  
    end
  
    def forgot_password
      authorize_application
      @user = AdminUser.where(email: params["email"]).first
      if @user
  
        ### Added the below condition for mobile app as firm_id will be blank ###
        if params[:firm_id].nil? or params[:firm_id] == 'undefined'
          params[:firm_id] = @user.selected_firm_id || @user.firm_id
          user_activity = AdminUserActivityConstants::USER_ACTIVITY_DASHSIGHT
        else
          user_activity = AdminUserActivityConstants::USER_ACTIVITY_WEBSITE
        end
  
        # if is_authorized_firm?(user)
          raw, enc = Devise.token_generator.generate(AdminUser, :reset_password_token)
          @user.reset_password_token   = enc
          @user.reset_password_sent_at = Time.now.utc
          @user.save(validate: false)
          is_mobile = params[:mobile].present? ? true : false
          @user.selected_firm_id = params[:firm_id]
          UserMailer.advisor_reset_password_instructions(@user, enc, is_mobile).deliver
          AdminUserActivity.create_activity(@user, user_activity, "Forgot Password mail sent successfully", request.user_agent, request.remote_ip)
          @success = true
        # else
        #   @success = false
        #   @message = "User does not belong to this firm"
        # end
      else
        Airbrake.notify("Forgot Password", {"error": "Forgot Password: User Not Found"  })
        @success = true
      end
    end
  
    def generate_reset_token
      user = AdminUser.find_by(id: params[:id])
      if user.present?
        raw, enc = Devise.token_generator.generate(AdminUser, :reset_password_token)
        user.reset_password_token   = enc
        user.reset_password_sent_at = Time.now.utc
        user.save(validate: false)
        render json: {status: true, message: user.reset_password_token}
      else
        render json: {status: false, message: "Not a valid user"}
      end
    end
  
    def validate_password
      authorize_application
      user = AdminUser.where(reset_password_token: params[:password_token]).first
      if user.present?
        user.password = params[:password]
        if user.valid? and not user.errors[:password].present?
          render json: {success: true}
        else
          render json: {success: false, message: user.errors[:password].map{|a| "Password #{a}"}}
        end
      else
        render json: {status: false, message: "Not a valid user"}
      end
    end
  
    def reset_password
      authorize_application
      token = params[:password_token]
      user = AdminUser.where(reset_password_token: token).first
      if params[:firm_id].nil? or params[:firm_id] == 'undefined'
        user_activity = AdminUserActivityConstants::USER_ACTIVITY_DASHSIGHT
      else
        user_activity = AdminUserActivityConstants::USER_ACTIVITY_WEBSITE
      end
  
      if user.present?
        if params["password"] == params["confirm_password"]
          user.password = params["password"]
          user.password_confirmation = params["confirm_password"]
          user.password_reset_date = Date.today
          if user.save(validate: false)
  
            ### Added the below condition for mobile app as firm_id will be blank ###
            if params[:firm_id].nil? or params[:firm_id] == 'undefined'
              params[:firm_id] = user.selected_firm_id || user.firm_id
            end
  
            access_token = user.get_access_token(@app, params[:firm_id], request.remote_ip).token
            AdminUserActivity.create_activity(user, user_activity, "Reset Password: Password updated successfully", request.user_agent, request.remote_ip)        
            render json: {success: true, msg: "Password updated successfully", access_token: access_token, id: user&.id.to_i, first_name: user&.first_name, last_name: user&.last_name, fullname: user&.fullname, email: user&.email, firm_id: params[:firm_id]}
          else
            render json: {success: false, msg: user.errors.full_messages}
          end
        else
          AdminUserActivity.create_activity(user, user_activity, "Reset Password: Password's didnt match", request.user_agent, request.remote_ip, id: user&.id.to_i, first_name: user&.first_name, last_name: user&.last_name, fullname: user&.fullname, email: user&.email, firm_id: params[:firm_id])        
          render json: {success: false, msg: "Password's didnt match"}
        end
      else
        render json: {success: false, msg: 'Password Link expired.', id: 0, email: params[:email], firm_id: params[:firm_id]}
      end
    end
  
    def sign_out
      access_token = Doorkeeper::AccessToken.where(resource_owner_id: current_user.id, token: params[:access_token]).last
      if params[:mobile].present?
        user_activity = AdminUserActivityConstants::USER_ACTIVITY_DASHSIGHT
      else
        user_activity = AdminUserActivityConstants::USER_ACTIVITY_WEBSITE
      end
      AdminUserActivity.create_activity(current_user, user_activity, "Successful SignOut", request.user_agent, request.remote_ip)        
      status = access_token.present? ? access_token.try(:revoke) : false
      current_user.delete_user_session if current_user.current_session_id.present?
      if status
        render json: {success: true, msg: 'Signed Out'}
      else
        render json: {success: false, msg: 'Invalid AccessToken'}
      end
    end
  
    def index
      if params[:scope] == 'all'
        @admin_users = current_firm.admin_users
      else
        @admin_users = AdminUserPolicy::Scope.new(current_user, AdminUser).resolve
      end
  
      if params[:staff] == 'true'
        @admin_users = @admin_users.active
      elsif params[:active] == 'true'
        @admin_users = @admin_users.advisor.where(active: true)
      else
        @admin_users = @admin_users.advisor
      end
  
      if params[:order] == "fullname"
        @admin_users = @admin_users.order("last_name, first_name")
      end
  
      if params[:search_term].to_s != ''
        @admin_users = @admin_users.where(id: AdminUser.solr_search{fulltext '*' + params[:search_term] + '*'}
          .results.pluck(:id)).order(:last_name, :first_name).limit(15)
      end
    end
  
    def show_firm_users
      sort_on  = params[:sort_on] || 'first_name'
      sort = params[:sort] || "asc"
      @advisors_count = @admin_users.where(admin_user_type_id: AdminUserType.where(description: "Advisor").pluck(:id).last).count
      @in_active_count = @admin_users.where(admin_user_type_id: AdminUserType.where(description: "In-Active").pluck(:id).last).count
      @support_count = @admin_users.where(admin_user_type_id: AdminUserType.where(description: "Support").pluck(:id).last).count
      if params[:search_term].present?
        query = params[:search_term][:query]
        @admin_users = @admin_users.where("UPPER(first_name) like ? or UPPER(last_name) like ? or UPPER(email) like ?", "%#{query.upcase}%", "%#{query.upcase}%", "%#{query.upcase}%") if query.present?
        @admin_users = @admin_users.where(admin_user_type_id: params[:search_term][:admin_user_type_id]) if params[:search_term][:admin_user_type_id].present?
      end
      sort_on = "admin_user_types.description" if params[:sort_on] == "type"
      @admin_users = @admin_users.includes(:admin_user_type).order_by_column(sort_on, sort)
      @admin_users = @admin_users.paginate(page: params[:page], per_page: params[:per_page])
      if request.format == "csv"
        @admin_users = @admin_users.where(id: params[:ids].split(',')) if params[:ids].present?
        send_data @admin_users.convert_to_csv, filename: "admin_users-#{Date.today}.csv"
      else 
        render :admin_users
      end
    end
  
    def sign_in
      app = authorize_application
      if app == 404
        render json: {msg: 'App does not exist'}, status: 404 
      else
        @user = AdminUser.active.find_by(user_name: params[:user_name])
        if @user.present? and @user.valid_password?(params[:password])
  
          ### Added the below condition for mobile app as firm_id will be blank ###
          if params[:firm_id].nil? or params[:firm_id] == 'undefined'
            params[:firm_id] = @user.selected_firm_id || @user.firm_id
          end
  
          if params[:mobile].present?
            @is_mobile = true
            user_activity = AdminUserActivityConstants::USER_ACTIVITY_DASHSIGHT
          else
            user_activity = AdminUserActivityConstants::USER_ACTIVITY_WEBSITE
          end
  
          if is_authorized_firm?(@user)
            @user.update_attribute("selected_firm_id", params[:firm_id]) if params[:firm_id].present?
            if @user.is_password_expired?
              raw, enc = Devise.token_generator.generate(AdminUser, :reset_password_token)
              @user.update_column("reset_password_token", enc)
              AdminUserActivity.create_activity(@user, user_activity, "Password Expired", request.user_agent, request.remote_ip)
              render json: {success: true, msg: "Password Expired", firm_id: @user.firm_id, user_id: @user.id, reset_password_token: enc}            
            else
              send_sms = (@is_mobile || @user.get_firm.show_send_code?)
              is_authy_code_valid = @user.is_authy_code_valid?(send_sms) if @user.mfa_enabled?
              if @user.mfa_enabled? && is_authy_code_valid
                is_valid_device_present, @device,@valid_device = @user.has_valid_authy_device?(params[:device_id])
                unless is_valid_device_present
                  if @user.get_firm.show_send_code? || @is_mobile
                    TwilioVerify.verify_and_send_sms(@user.twilio_to_number) if  @user.twilio_to_number.present?
                  end
                  response_json = {success: true, firm_id: @user.firm_id, user_id: @user.id, authy_enabled: @user.authy_enabled, show_send_code: @user.get_firm&.show_send_code?}
                  # unless Rails.env.production?
                  #   approval_request = Authy::OneTouch.send_approval_request(id: @user.authy_id, message: "SignIn request")
                  #   response_json.merge!({authy_id: @user.authy_id, uuid: approval_request.approval_request["uuid"]}) if approval_request.success          
                  # end
                  response_json = {success: true, firm_id: @user.firm_id, user_id: @user.id, authy_enabled: @user.authy_enabled, show_send_code: @user.get_firm&.show_send_code?, password_expiring_days: @user.password_expiring_days}          
                  AdminUserActivity.create_activity(@user, user_activity, "Requesting user to enter two-factor authentication from SMS text or phone call.", request.user_agent, request.remote_ip)
                  render json: response_json, status: :ok
                else
                  if @is_mobile
                    @jwt_token = JWTAuth.new.encode({email: @user.email, firm_id: params[:firm_id], app_id: @app.id, secure_unique_id: @user.secure_unique_id})
                  end
                  @user.update_login_info(request.remote_ip, request.user_agent)
                  @access_token = @user.get_access_token(@app, params[:firm_id], request.remote_ip)
                  AdminUserActivity.create_activity(@user, user_activity, "Successful SignIn with Valid Device", request.user_agent, request.remote_ip)              
                  render :sign_in
                end  
              elsif @user.mfa_enabled? && !is_authy_code_valid
                AdminUserActivity.create_activity(@user, user_activity, "Authy register", request.user_agent, request.remote_ip)              
                ## Generating A QR code if authy enabled is false
                response = {success: true, msg: "Need to register for Authy", firm_id: @user.firm_id, user_id: @user.id, authy_enabled: is_authy_code_valid, show_send_code: @user.get_firm&.show_send_code?}
                unless (@is_mobile || @user.get_firm.show_send_code?)
                  if @user.secure_unique_id.blank?
                    @user.update_column("secure_unique_id", Guid.new)
                  end
                  twilio_qr_code = TwilioVerify.create_qr_code(@user.secure_unique_id, "QRcode")
                  @user.update_columns(twilio_entity_sid: twilio_qr_code[:entity_id], twilio_factor_sid: twilio_qr_code[:factor_id]) if twilio_qr_code[:status] != "error"
                  response.merge!({qr_code: twilio_qr_code[:qr_code], secret_key: twilio_qr_code[:secret_key]}) if twilio_qr_code[:status] != "error"
                end
                render json: response, status: :ok
              else
                if @is_mobile
                  @jwt_token = JWTAuth.new.encode({email: @user.email, firm_id: params[:firm_id], app_id: @app.id, secure_unique_id: @user.secure_unique_id})
                end
                @user.update_login_info(request.remote_ip, request.user_agent)
                @access_token = @user.get_access_token(@app, params[:firm_id], request.remote_ip)
                AdminUserActivity.create_activity(@user, user_activity, "Successful SignIn", request.user_agent, request.remote_ip)              
                render :sign_in
              end
            end
          else
            AdminUserActivity.create_activity(@user, user_activity, "UnSuccessful SignIn: User does not belong to this firm", request.user_agent, request.remote_ip)          
            render json: {success:false, msg: "User does not belong to this firm"}, status: 404
          end  
        else
           render json: {success: false, msg: 'User/Password Combination is Incorrect'}, status: 404
        end
      end
    end
  
    def auth_login
      auth_token = request.headers.env["HTTP_AUTHORIZATION"]
      auth_data = JWTAuth.new.decode(auth_token)
      if auth_data.present?
        @user = AdminUser.where(email: auth_data["email"], secure_unique_id: auth_data["secure_unique_id"]).last
        if @user.present? 
          @user.update_login_info(request.remote_ip, request.user_agent)
          app = Doorkeeper::Application.find_by(id: auth_data["app_id"])
          @access_token = @user.get_access_token(app, auth_data["firm_id"], request.remote_ip)
          render :sign_in
        else
          render json: {success: false, msg: "User Not Found"}
        end
      else 
        render json: {success: false, msg: "Token expired"}
      end
    end
  
    def login_as
      if Pundit.authorize(current_user, current_user, :login_as?)
        @admin_user = AdminUser.where(id: params[:id]).last
        @admin_user.selected_firm = current_user.selected_firm
        @admin_user.save(validate: false)
        url = @admin_user.new_client_url(@admin_user.selected_firm)
        redirect_to URI.parse(url).to_s
      end
    end
  
    def send_token
      user = AdminUser.find(params[:id])
      if params[:request_msg] == 'false'
        render json: {success: true, msg: 'Type in the authy code', user_id: user.id, authy_enabled: user.authy_enabled}, status: :ok
      else
        response = TwilioVerify.verify_and_send_sms(user.twilio_to_number)
        data = {message: defined?(response.status).present? ? "SMS token was sent" : response.error_message}
        update_mfa_log(params, data) if params["request_type"].present?
        if params[:mobile].present?
          user_activity = AdminUserActivityConstants::USER_ACTIVITY_DASHSIGHT
        else
          user_activity = AdminUserActivityConstants::USER_ACTIVITY_WEBSITE
        end
        AdminUserActivity.create_activity(user, user_activity, "Authy Enabled and SMS was sent", request.user_agent, request.remote_ip)      
        render json: {success: defined?(response.status).present? ? true : false, cellphone: user.mfa_phone, msg: data[:message], firm_id: user.firm_id, user_id: user.id, authy_enabled: user.authy_enabled}, status: :ok
      end
    end
  
    def verify_one_touch
      @user = AdminUser.where(authy_id: params[:authy_id]).last
      response = Authy::OneTouch.approval_request_status(:uuid => params[:uuid])
      if response.success
        if response.approval_request["status"] == "approved"
          @user.update_login_info(request.remote_ip, request.user_agent)
          @user.last_sign_in_with_authy = DateTime.now()
          @user.save
          authorize_application
  
          ### Added the below condition for mobile app as firm_id will be blank ###
          if params[:firm_id].nil? or params[:firm_id] == 'undefined'
            params[:firm_id] = @user.selected_firm_id || @user.firm_id
          end
  
          @access_token = @user.get_access_token(@app, params[:firm_id], request.remote_ip)
          render :sign_in
        else
          render json: {success: false, msg: "The request has been rejected.", user_id: @user.id}, status: :ok
        end
      else
        render json: {success: false, msg: response.message, user_id: @user.id}, status: :ok
      end
    end
  
    def verify_token
      @user = AdminUser.find(params[:id])
      if params[:mobile].present? || @user.get_firm.show_send_code?
        response = TwilioVerify.verify_token(@user.twilio_to_number, params[:token])
        status = defined?(response.valid).present? and response.valid 
      else
        if params[:create_record].to_s == "true"
          response = TwilioVerify.create_record(@user.twilio_entity_sid, @user.twilio_factor_sid, params[:token])
          status = response[:status] == "verified"
        else
          response = TwilioVerify.create_challenge(@user.twilio_entity_sid, @user.twilio_factor_sid, params[:token])
          status = response[:status] == "approved"
        end
      end
      if params[:mobile].present?
        user_activity = AdminUserActivityConstants::USER_ACTIVITY_DASHSIGHT
      else
        user_activity = AdminUserActivityConstants::USER_ACTIVITY_WEBSITE
      end
      
      if status
        if params[:device_id].present? and params[:user_agent].present? and params[:remember_me].present?
          ip_address = request.remote_ip
          AdminUserDevice.CreateOrUpdate(@user,params[:device_id],params[:user_agent],params[:token],ip_address,params[:remember_me])
          AdminUserActivity.create_activity(@user, user_activity, "Successful SignIn and User Device Added", request.user_agent, request.remote_ip)      
        else
          AdminUserActivity.create_activity(@user, user_activity, "Successful SignIn After validating the one-time password (two-factor authentication)", request.user_agent, request.remote_ip)      
        end
  
        @user.authy_enabled = true
        @user.update_login_info(request.remote_ip, request.user_agent)
        @user.last_sign_in_with_authy = DateTime.now()
        @user.save
        authorize_application
  
        ### Added the below condition for mobile app as firm_id will be blank ###
        if params[:firm_id].nil? or params[:firm_id] == 'undefined'
          @is_mobile = true
          params[:firm_id] = @user.selected_firm_id || @user.firm_id
        end
  
        if @is_mobile
          @jwt_token = JWTAuth.new.encode({email: @user.email, firm_id: params[:firm_id], app_id: @app.id, secure_unique_id: @user.secure_unique_id})
        end
  
        @access_token = @user.get_access_token(@app, params[:firm_id], request.remote_ip)
        render :sign_in
      else
        AdminUserActivity.create_activity(@user, user_activity, "UnSuccessful SignIn: one-time password (two-factor authentication) not valid", request.user_agent, request.remote_ip)            
        render json: {success: false, msg: "Security Code is invalid.", user_id: @user.id}, status: :ok
      end
    end
  
    def enable_authy
      @user = AdminUser.find(params[:id])
      @user.update_columns(mfa_phone: params[:cellphone], mfa_country_code: params[:country_code])
  
      if params[:mobile].present? || @user.get_firm.show_send_code?
        user_activity = AdminUserActivityConstants::USER_ACTIVITY_DASHSIGHT
        ## Below code twiggers SMS
        twilio_id = @user.twilio_to_number.present? ? @user.twilio_to_number : @user.mfa_phone_with_country_code
        @authy_user = TwilioVerify.verify_and_send_sms(twilio_id)
        @user.twilio_verification_id = @authy_user.sid
        @user.twilio_to_number = @authy_user.to
        @user.authy_enabled = true
      else
        @user.skip_authy_callback = true
        user_activity = AdminUserActivityConstants::USER_ACTIVITY_WEBSITE
      end
      
      if @user.save
        if @user.get_firm.show_send_code? || params[:mobile].present?
          AdminUserActivity.create_activity(@user, user_activity, "Authy Enabled and SMS was sent", request.user_agent, request.remote_ip)            
          render json: {success: true, cellphone: params['cellphone'], msg: 'Authy Enabled', firm_id: @user.firm_id, user_id: @user.id, authy_enabled: @user.authy_enabled}, status: :ok
        else
          AdminUserActivity.create_activity(@user, user_activity, "Authy Enabled", request.user_agent, request.remote_ip)            
          render json: {success: true, cellphone: params['cellphone'], msg: "Authy Enabled", firm_id: @user.firm_id, user_id: @user.id, authy_enabled: @user.authy_enabled}, status: :ok
        end
      end 
    end
   
    def redirect
      respond_to do |format|
        format.html {
          warden.set_user current_user
          redirect_to request['url']
        }
      end
    end 
  
    def session_valid
      if current_token.present?
        if current_token.revoked? || current_token.expired?
          AdminUserActivity.create_activity(current_user, AdminUserActivityConstants::USER_ACTIVITY_WEBSITE, "Session Expired", request.user_agent, request.remote_ip, current_token.expires_at, current_token.expires_at) if current_user.present?            
          render json: {status: false, error: "Session Expired"}, status: 500
        else  
          render json: {status: true}
        end
      else
        render json: {status: false, error: "Invalid Session"}, status: 500
      end
    end
  
    def reassign_advisor
      users = UserPolicy::Scope.new(current_user, User).resolve
      users = users.where(advisor_admin_user_id: params[:from_admin_user_ids])
      to_admin_user = @admin_users.where(id: params[:to_admin_user_id]).last
      if to_admin_user.present?
        users.update_all(advisor_admin_user_id: to_admin_user.id )
        render json: {success: true, message: "Advisor's updated successfully"}
      else
        render json: {success: false, message: "Assigned To Advisor not Found"}
      end
    end
  
    def reassign_households
      from_admin_users = @admin_users.where(id: params[:from_admin_user_ids])
      household_admin_users = HouseholdAdminUser.where(admin_user_id: from_admin_users.pluck(:id))
      to_admin_user = @admin_users.where(id: params[:to_admin_user_id]).last
      if to_admin_user.present?
        household_admin_users.update_all(admin_user_id: to_admin_user.id )
        render json: {success: true, message: "Household's updated successfully"}
      else
        render json: {success: false, message: "Assigned To Advisor not Found"}
      end
    end  
  
    # def redirect_classic
    #   respond_to do |format|
    #     format.html {
    #       warden.set_user current_user
    #       redirect_to 'https://' + current_user.selected_firm.domain + '?access_token=' + request['access_token'] + '&url=' + request['url']
    #     }
    #   end
    # end
  
    def selected_firm
      admin_user = AdminUser.where(id: params[:id]).last
      if admin_user.present? and is_authorized_firm?(admin_user)
        if admin_user.update(selected_firm_id: params[:firm_id])
          current_token.update_attribute("firm_id", params[:firm_id])
          render json: {success: true}
        else
          render json: {success: false}
        end
      else
        render json: {success: false, message: "Not Authorized Firm"}
      end
    end
  
    def get_task_types
      task_types = current_user.get_task_types
      render json: task_types
    end
  
    def save_state
      begin
        admin_user = AdminUser.find_by(id: params[:id])
        admin_user.update(admin_user_panel_params)
        status = true
      rescue Exception => e
        Airbrake.notify e
        status = false
      end
      if admin_user.save and status
        render json: {success: true}
      else
        render json: {success: false}
      end
    end
  
    def activities
      scope = @admin_user.admin_user_activities.joins(:admin_user_activity_type)
      
      if params[:admin_user_activity_type_id] 
        scope = scope.where(admin_user_activity_type_id: params[:admin_user_activity_type_id])
      end
      
      if params[:search_term].present?
        scope = scope.where("description like ? OR ip_address like ? OR user_agent like ?", '%' + params[:search_term] + '%', '%' + params[:search_term] + '%', '%' + params[:search_term] + '%')
      end
      
      if (params[:sort].present? && params[:sort_on].present?)
        scope = scope.order_by_column(params[:sort_on], params[:sort])
      end
  
      @types = AdminUserActivityType.all
      @activities = scope.paginate(page: params[:page], per_page: params[:per_page])
  
      # re-hydrate data blobs
      @activities.each do |r|
        if !r.data.nil?
          begin
            r.data = Marshal.load(Base64.decode64(r.data)).to_json
          rescue
            r.data = nil
          end
        end
      end
    end    
  
    def activity
      @activity = @admin_user.admin_user_activities.find(params[:activity_id])
      begin
        @data =  @activity.get_decoded_data
      rescue
      end
    end
  
    def validate_session
      if current_token.present? and (current_token.revoked? || current_token.expired?)
        AdminUserActivity.create_activity(current_user, AdminUserActivityConstants::USER_ACTIVITY_WEBSITE, "Session Expired", request.user_agent, request.remote_ip, current_token.expires_at, current_token.expires_at) if current_user.present?            
        render json: {status: false, error: "Session Expired"}
      elsif current_token.blank?
        render json: {status: false, error: "Session Expired"}
      else  
        render json: {status: true}
      end
    end
  
    def validate_token
      if params[:mobile].present? || @admin_user.get_firm.show_send_code?
        response = TwilioVerify.verify_token(@admin_user.twilio_to_number, params["token"])
        data = {message: (defined?(response.valid).present? and response.valid) ? "Token valid." : "Security Code is invalid."}
        status = defined?(response.valid).present? and response.valid 
      else
        response = TwilioVerify.create_challenge(@admin_user.twilio_entity_sid, @admin_user.twilio_factor_sid, params[:token])
        data = {message: response[:status] == "verified" ? "Token valid." : "Security Code is invalid."}
        status = response[:status] != "error"
      end
      update_mfa_log(params, data) if params["request_type"].present?
      if status
        session = current_token.session_status if current_token.present?
        session_status = session.present? ? JSON.parse(session) : {}
        current_token.update_attribute("session_status", session_status.merge({"is_ssn_mfa_enabled"=> true, "can_view_metadata"=> true}).to_json)
      end
      render json: {success: status ? true : false, msg: data[:message], user_id: @admin_user.id}, status: :ok
    end
  
    def update_mfa_log(parameters = {}, response = {})
      case parameters["request_type"]
        when "user_ssn"
          user = User.find_by(id: parameters[:user_id])
          AdminUserMfaLog.create_record(current_user.id, user, AdminUserMfaLog.activity_types["Request SSN"], "Token Verfication:" + response[:message])
      end
    end
  
    def primary_households
      household_ids = HouseholdAdminUser.where(admin_user_id: @admin_user.id).pluck(:household_id).uniq
      @households = Household.where(id: household_ids)
  
      if params[:search_term].present?
        @households = @households.where(id: Household.solr_search{fulltext '*' + params[:search_term] + '*'}.results.pluck(:id))
      end
  
      params[:sort_on] ||= 'name'
      params[:sort] ||= 'asc'
      @households = @households.order_by_column(params[:sort_on], params[:sort])
  
      @households = @households.includes(:advisor, :current_allocation, :account_groups).paginate(page: params[:page], per_page: params[:per_page])
  
    end
  
    private 
  
    def set_admin_users
      @admin_users = AdminUserPolicy::Scope.new(current_user, AdminUser).resolve.unscope(:order)
    end
  
    def set_admin_user
      @admin_user = @admin_users.where(id: params[:id]).last
      if @admin_user.nil?
        raise ActiveRecord::RecordNotFound
      end
    end
  
    def firm_admin_user_params
      params.require(:admin_user).permit(:first_name, :middle_initial, :last_name, :phone_mobile, :business_phone, :email, 
                :team_email, :admin_user_type_id, :time_zone, :daily_summary, :active, :profile_image, :title,
                :tamarac_advisor_id, :tamarac_advisor_name, :docusign_rep_code, :docusign_firm_signer, :has_daily_digest_emails,
                :docusign_embedded_signing, :tda_username, :is_recalc_email_enabled, :mfa_enabled, :authy_enabled,
                :notify_link_bank, :notify_overdue_task, :booking_url, :scheduling_integration, :notify_unlinked_bank,
                :notify_past_appointments, :notify_future_contacts, :notify_cash_reserves_with_unmatched_threshold,
                :is_sync_appointment_enabled, :user_name,
                admin_user_households_attributes: [:id, :household_id, :_destroy],
                admin_user_team_members_attributes: [:id, :team_member_id, :_destroy])
                .merge!({notify_past_appointment_enabled_date: (params[:admin_user] and params[:admin_user][:notify_past_appointments] == "true" ? DateTime.now : nil)})
    end
  
    def is_authorized_firm?(user)
      authorized_firms =  user.authorized_firms.to_a
      is_authorized = authorized_firms.pluck(:id).include?(params[:firm_id].to_i)  
      return is_authorized
    end
  
    def admin_user_panel_params
      params.require(:admin_user).permit(:active_panels, accordian_columns: [household_accordian: [:rebalancing_group, :household_details, :clients, :trusted_contacts, :advisory_team, 
                    :address, :net_worth, :income_expense, :cash_reserves, :savings_waterfall, :withdrawal_plan, :protection_data_square, :estate_plan_square, :external_provider, :accounting_data, :referred_info], 
                    client_accordian: [:contact, :client_details, :households, :employer], dashboard_accordian: [:tasks, :opportunities , :saved_xports, :business_analytics, :contact_birthdays, 
                    :contact_appointments]], list_columns: [household_listing: [:name, :cached_advisor_name, :primary_csa_advisor_name, :managed_value, :status, :created_at, :last_contact_date, :alert,
                    :allocation, :ytd],
                    client_listing: [:name, :advisor, :csa, :category, :created_at, :last_sign_in_at, :current_sign_in_at, :client_view]])
    end
  end