class UsersController < ApplicationController
  before_action :doorkeeper_authorize!
  before_action :set_users, only: [:copy_address, :client_view, :reassign_advisor, :client_view_mobile]
  before_action :set_user, only: [:update, :show, :tasks, :activity, :activities, :copy_address, :client_view, :reset_onboarding, :reset_mfa, :client_view_mobile, :social, :employer_info, :add_tda_multi_form]

  include UserConstants
  include PhoneTypes

  def index
    @can_delete = current_user.has_role?(:admin, current_firm)

    user = UserPolicy::Scope.new(current_user, User).resolve
    @total_clients_count = user.count

    per_page = params[:format] == 'csv' ? 100_000 : params[:per_page]
    conditions = ''
    conditions = "advisor_admin_user_id = #{params[:advisor_id].to_i}" if params[:advisor_id].present?
    conditions += " and " if params[:advisor_id].present? && params[:category].present?
    conditions += "category = #{params[:category].to_i}" if params[:category].present?
    users = user.where(conditions)
    @active_clients = users.active.mine(current_user.id).count
    @inactive_clients = users.inactive.mine(current_user.id).count
    users = users.select("users.id, users.first_name, users.middle_initial, users.last_name, users.selected_household_id, users.category, users.user_type_id, users.email, users.advisor_admin_user_id, users.created_at, users.last_sign_in_at, users.current_sign_in_at, users.cached_csa_name, users.cached_advisor_name")

    if params[:my_active_clients].present?
      @clients = if conditions == ''
                   user.active.mine(current_user.id)
                 else
                   user.where(conditions).active.mine(current_user.id)
                 end
    elsif params[:inactive_clients].present?
      @clients = if conditions == ''
                   user.inactive.mine(current_user.id)
                 else
                   user.where(conditions).inactive.mine(current_user.id)
                 end
    else
      @clients = users.joins(:advisor)
    end

    if params[:search_term].present?
      search_results = User.solr_search { fulltext '*' + params[:search_term] + '*' }.results.pluck(:id)
      search_results += User.solr_search { fulltext params[:search_term] }.results.pluck(:id)
      @clients = @clients.where(id: search_results)
    end

    if params[:sort].present? && params[:sort_on].present?
      sort_on = params[:sort_on].starts_with?("admin_users.") ? params[:sort_on] : "users.#{params[:sort_on]}"
      @clients = @clients.order_by_column(sort_on, params[:sort])
    end

    @clients = @clients.paginate(page: params[:page], per_page: per_page)

    if params[:format] == 'csv'
      if params[:search_term].present?
        @clients = generate_search_csv
        @clients = generate_search_csv.where(id: params[:ids].split(',')) if params[:ids].present?
        return send_data @clients.to_csv, filename: "clients-#{Date.today}.csv"
      else
        @clients = @clients.where(id: params[:ids].split(',')) if params[:ids].present?
        return send_data @clients.to_csv, filename: "clients-#{Date.today}.csv"
      end
    end
  end

  def clients
    if params[:user_type] == "firm_client"
      users = UserPolicy::Scope.new(current_user, User).resolve("firm_client")
    else
      users = UserPolicy::Scope.new(current_user, User).resolve
    end
    if params[:household_id].present?
      users = users.joins(:households).where("households.id = ?", params[:household_id])
    end
    if params[:search_term].present?
      users = users.where(id: User.solr_search { fulltext '*' + params[:search_term] + '*' }.results.pluck(:id))
    end
    @users = users.order(:first_name, :last_name)
  end

  def categories
    @categories = User.categories
  end

  def delete_users
    if current_user.has_role?(:admin, current_firm)
      user_ids = params[:ids].split(",")&.map(&:to_i) if params[:ids].present?
      if user_ids.present?
        users = UserPolicy::Scope.new(current_user, User).resolve.where(id: user_ids).pluck(:id)
        users.each do |user_id|
          user = User.find(user_id)
          user.destroy
        end
        render json: { success: true }
        return
      else
        render json: { success: false, message: 'Could Not Found Users' }
        return
      end
    end
  end

  def is_valid
    @user = User.new(user_params)
    if @user.valid?
      render json: { success: true, message: "Valid User" }
    else
      render json: { success: true, message: "Invalid User" }
      return
    end
  end

  def show
  end

  def employer_info
  end

  def dropdown_values
    dropdown_types = Struct.new(:phone_types, :email_types, :address_types, :employment_types, :marital_statuses, :categories,
                                :employer_status, :gender, :user_status, :household_statuses, :household_roles, :expense_types, :advisor_types,
                                :income_types, :waterfall_status, :household_grades, :callback_schedules, :cdd_annual_incomes, :cdd_net_worths,
                                :cdd_initial_source_of_funds, :cdd_ongoing_source_of_funds, :employer_industry_codes, :employer_occupation_codes,
                                :contact_roles, :trusted_contact_disclosure, :personally_identifiable_disclosure, :account_custodians,
                                :household_tax_bracket_filing_status, :user_employer_industry, :user_employer_occupation,
                                :insurance_beneficiary_types, :estate_category_types, :estate_contact_types, :insurance_premium_frequencies,
                                :duration_of_premium_options, :elimination_period_options, :benefit_duration_options, :insurance_user_types,
                                :convertible_to_age_options, :note_contact_types, :estate_trustee_types, :estate_asset_types, :estate_attorney_types,
                                :prospect_stage, :contact_reminder)

    @dropdown_values = dropdown_types.new(User.phone_types, User.email_types, User.address_types, User.employment_types,
                                          User.marital_statuses, User.categories, User.employer_statuses, User.genders,
                                          UserType.pluck(:description), Household.statuses, HouseholdUser.household_user_types, UserExpenseType.pluck(:description),
                                          HouseholdAdminUser.household_admin_user_types, UserIncomeType.pluck(:description, :id).uniq,
                                          WaterfallRecommendation.statuses, HouseholdGrade.pluck(:id, :name),
                                          CallbackSchedule.where(firm_id: current_firm.id), User.cdd_annual_incomes, User.cdd_net_worths, User.cdd_initial_source_of_funds,
                                          User.cdd_ongoing_source_of_funds, User.employer_industry_codes, User.employer_occupation_codes, HouseholdContact.roles.map { |k, v| [v, k] },
                                          HouseholdContact.disclosure_methods.map { |k, v| [v, k] }, HouseholdContact.disclosure_methods.except('Trusted Contact Addendum').map { |k, v| [v, k] },
                                          AccountCustodian.all.map { |ac| { id: ac.id, name: ac.name, icon: ac.icon.url, unique_id: ac.unique_id, integration_type: ac.integration_type } },
                                          Household.tax_bracket_filing_types, UserEmployerIndustry.pluck(:id, :name), UserEmployerOccupation.pluck(:id, :name),
                                          HouseholdInsuranceBeneficiary.beneficiary_types.map { |k, v| [v, k] },
                                          EstateCategory.category_types.map { |k, v| [v, k] }, EstateContact.contact_types.map { |k, v| [v, k] }, HouseholdInsurance.premium_frequencies.map { |k, v| [v, k] },
                                          HouseholdInsuranceCategory.duration_of_premium_options, HouseholdInsuranceCategory.elimination_period_options, HouseholdInsuranceCategory.benefit_duration_options,
                                          HouseholdInsuranceUser.user_types.map { |k, v| [v, k] }, HouseholdInsuranceCategory.convertible_to_age_options, Note.get_contact_type_label.map { |k, v| [v, k] },
                                          EstateTrustee.trustee_types.map { |k, v| [v, k] }, EstateCategory.asset_types.map { |k, v| [v, k] }, EstateCategory.attorney_types.reject { |k, v| ["other_attorney_type"].include?(k) }.map { |k, v| [v, k] },
                                          Household.prospect_stages.map { |k, v| [v, k] }, Household.contact_reminders.map { |k, v| [v, k] }
    )
  end

  def delete_household_users
    @household_users = UserPolicy::Scope.new(current_user, User).resolve.where(id: params[:id]).first&.households&.where(id: params[:household_id])&.first&.household_users
    if @household_users.present?
      @household_users.where(id: params[:household_users_id].split(',')).delete_all
      render json: { success: true }
    else
      render json: { success: false }
    end
  end

  def tasks
    scope = @user.tasks
    case params[:filter]
    when 'current_tasks'
      scope = scope.where("(status in (?) and task_recurrence_id is ?) or (status in (?) and task_recurrence_id is not null and is_latest = true)", [1, 2], nil, [1, 2]).order(due_date: :asc, updated_at: :desc)
    when 'all'
      scope = scope.where("(task_recurrence_id is ?) or (task_recurrence_id is not null and is_latest = true)", nil).order(Arel.sql("ifnull(completed_date, '2999-12-31') desc, due_date asc"))
    else
      scope = scope.where(status: 99).order(completed_date: :desc, updated_at: :desc)
    end
    @tasks = scope.paginate(page: params[:page], per_page: params[:per_page])
  end

  def email_exists
    attrs = params.permit(:access_token, :email, :user_id)

    scope = current_firm.users.where(email: attrs[:email])
    if attrs[:user_id]
      scope = scope.where.not(id: attrs[:user_id])
    end

    render json: { success: true, message: scope.any? }
    
    render json: { success: true, message: scope.any? }
  end

  def valid_name
    parts = NameParsing.parse_name(params.permit(:access_token, :name)[:name])
    render json: { success: true, message: ((parts[:first_name_with_prefix].to_s != '' and parts[:last_name_with_suffix].to_s != '') ? true : false )}
  end

  def create
    attrs = user_params
    # parse out name parts
    parts = NameParsing.parse_name(attrs[:name])
    attrs[:first_name] = parts[:first_name_with_prefix]
    attrs[:last_name] = parts[:last_name_with_suffix]
    attrs[:middle_initial] = parts[:middle_name]

    # generate email if it's blank
    attrs[:email] = current_firm.generated_email if attrs[:email].to_s == ''

    @user = User.new(attrs.except(:name, :household_id, :default_household, :household_role))
    @user.password = Devise.friendly_token
    @user.firm = current_firm
    @user.terms_and_conditions = false
    @user.user_type_id = USERTYPE_ACTIVE
    if @user.save
      @user.update!(category: attrs[:category])
      if attrs[:household_id].present?
        household = Household.find_by(id: attrs[:household_id])
        role = if not household.primary.present?
                 HouseholdUser.household_user_types[:Primary]
               elsif not household.spouse.present?
                 HouseholdUser.household_user_types[:Secondary]
               else
                 HouseholdUser.household_user_types[:Dependent]
               end
        household.copy_address("#{@user.id}_mailing") if household.present? and @user.copy_address_to_household
        @user.household_users.create!(household_id: household.id, household_user_type: role, user_household_type: HouseholdUser.user_household_types[:Default])
        @user.update!(selected_household_id: household.id)
      end
      render json: {success: true, user_id: @user.id}
    else
      render_error(@user, :unprocessable_entity)
    end
  end

  def update
    if params[:contact].present?
      # generate random email if they blank out primary email
      primary_email = params[:contact]["primary_email"].to_s
      secondary_email = params[:contact]["secondary_email"].to_s
      tertiary_email = params[:contact]["tertiary_email"].to_s

      if ['', 'null', 'undefined'].include?(primary_email)
        primary_email = current_firm.generated_email
      end  
      
      @user.update!(user_contact_params.merge(
        email: primary_email, 
        email2: secondary_email,
        email3: tertiary_email)
      ) 
    end
      

    if params[:details].present?
      detail_params = form_user_details_params

      # parse out name parts
      if detail_params[:name].present?
        parts = NameParsing.parse_name(detail_params[:name])
        detail_params[:first_name] = parts[:first_name_with_prefix]
        detail_params[:last_name] = parts[:last_name_with_suffix]
        detail_params[:middle_initial] = parts[:middle_name] 
      end

      @user.update(detail_params.except(:name))
    end

    @user.update(employer_details_params) if params[:employer].present?
    if params[:households].present?
      create_household_records
    end
    
    if params[:user].present? and household_external_provider_params[:household_external_providers].present?
      create_household_external_provider_records
    end
    @user.reload

    household = Household.find_by(id: params[:household_id])
    if household.present? and @user.copy_address_to_household == "true"
      household.copy_address("#{@user.id}_mailing") 
    end
    render :show
  end

  def email_templates
    @templates = [
      { id: 'welcome_email', value: 'Welcome Email' },
      { id: 'reset_password', value: 'Reset Password Email' },
      { id: 'onboarding_invitation', value: 'Onboarding invitation email' },
      { id: 'rtq_invitation', value: 'RTQ Invitation Email' },
      { id: 'dashboard_invitation', value: 'Dashboard Invitation Email' },
      { id: 'document_posted', value: 'Document Posted Email' },
    ]
  end

  def preview_email
    user = authorize User.find(params[:id])
    household = Household.find(params[:household_id]) if params[:household_id].present?
    case params[:template]
      when 'welcome_email'
        render plain: UserMailer.advisor_welcome_email(user, user.token_reset).body
      when 'reset_password'
        render plain: UserMailer.reset_password_instructions(user, user.token_reset).body
      when 'onboarding_invitation'
        render plain: UserMailer.onboarding_invitation_email(user).body
      when 'rtq_invitation'
        render plain: UserMailer.advisor_rtq_invitation_email(user, user.advisor).body
      when 'dashboard_invitation'
        render plain: UserMailer.dashboard_invitation_email(user, user.token_reset).body
      when 'document_posted'
        if params[:user_ids].present?
          user_ids = params[:user_ids].split(",")
          render plain: UserMailer.advisor_document_uploaded_email(user_ids).body
        else
          render plain: UserMailer.advisor_document_posted_email(user, household).body
        end
    end  
  end

  def send_email
    user = authorize User.find(params[:id])
    status = true 
    user_status = {}
    case params[:template]
      when 'welcome_email'
        UserMailer.advisor_welcome_email(user, user.token_reset).deliver
      when 'reset_password'
        UserMailer.reset_password_instructions(user, user.token_reset).deliver
      when 'onboarding_invitation'
        find_or_create_household(user, user.advisor_admin_user_id)
        if params[:household_id].blank?
          @message = "#{@household.name} has been created for you."
        end
        UserMailer.onboarding_invitation_email(user, @household, @rtq, user.token_reset).deliver
      when 'rtq_invitation'
        find_or_create_household(user, user.advisor&.id)
        @rtq.update_column("initiated_date", DateTime.now) if @rtq.present?
        token = JWTAuth.new(1.week).encode({user_id: user.id, rtq_id: @rtq.id, household_id: @household.id, firm_id: current_firm.id, user_name: user.name})
        UserMailer.advisor_rtq_invitation_email(user, user.advisor, @household, @rtq, token).deliver
      when 'dashboard_invitation'
        UserMailer.dashboard_invitation_email(user, user.token_reset).deliver
      when 'document_posted'
        UserMailer.advisor_document_posted_email(user).deliver
    end 

    render json: {success: status, user_status: user_status}, status: :ok 
  end

  def find_or_create_household(user, admin_user_id = nil)
    if params[:household_id].present?
      @household = user.households.where(id: params[:household_id]).last
    else
      @household = Household.CreateDefaultForFrontEndUser(user, admin_user_id)
    end
    @rtq = @household.create_rtq(user, params[:rtq_title]) if @household.present?
  end

  def activity
    @activity = @user.user_activities.find(params[:activity_id])
    begin
      @data =  @activity.get_decoded_data
    rescue
    end
  end

  def activities
    scope = @user.user_activities.joins(:user_activity_type)
    
    if params[:user_activity_type_id] 
      scope = scope.where(user_activity_type_id: params[:user_activity_type_id])
    end

    if params[:search_term].present?
      scope = scope.where("description like ? OR ip_address like ? OR user_agent like ?", '%' + params[:search_term] + '%', '%' + params[:search_term] + '%', '%' + params[:search_term] + '%')
    end
    
    if (params[:sort].present? && params[:sort_on].present?)
      scope = scope.order_by_column(params[:sort_on], params[:sort])
    end

    @types = UserActivityType.all
    @activites = scope.paginate(page: params[:page], per_page: params[:per_page])

    # re-hydrate data blobs
    @activites.each do |r|
      if !r.data.nil?
        begin
          r.data = Marshal.load(Base64.decode64(r.data)).to_json
        rescue
          r.data = nil
        end
      end  
    end
  end

 def create_household_records
   household_params["household_users"].each do |household_user_val|
     household_user = HouseholdUser.find_or_initialize_by(user_id: @user.id, household_id: household_user_val[:household_id] )
     household_user.household_user_type = household_user_val["role"] 
     household_user.visible = household_user_val["visible"]
     household_user.user_household_type = household_user_val["is_default"] == true ? "Default" : nil
     household_user.save!

     if household_user_val["is_default"] == true
      @user.selected_household = household_user.household
      @user.save!
     end
   end
 end

 def create_household_external_provider_records
  household_external_provider_params[:household_external_providers].each do |hep|
    if hep[:_destroy] and hep[:id].present?
      @user.household_external_providers.where(id: hep[:id]).destroy_all
    else
      household_external_provider = HouseholdExternalProvider.find_or_initialize_by(user_id: @user.id, household_id: hep[:household_id] )
      household_external_provider.household_external_provider_role_id = hep[:household_external_provider_role_id]
      household_external_provider.save!
    end
  end
 end

  def generate_search_csv
    UserPolicy::Scope.new(current_user, User).resolve.where(id: @clients.map{|x| x.id})
  end

  def copy_address
    if request.post?
      source_user = @users.where(id: params[:source_user_id]).last
      if source_user.present?
        contact_params = params[:contact].present? ? params[:contact] : {}
        @user.copy_address(source_user, contact_params) 
        render json: {success: true, user: @user}
      else
        render json: {success: false, message: "Source User not found"}
      end
    end
  end

  def client_view
    if @user.active? == false
      @user.user_type_id = UserConstants::USERTYPE_ACTIVE
      @user.save!
    end

    if current_firm.client_version == 'angular'
      is_mobile = params[:mobile].present? ? true : false
      url = URI.parse(@user.new_client_url(current_firm, is_mobile, current_user.id)).to_s
      redirect_to url
    else
      sign_in @user, {:bypass => true}
      redirect_to current_firm.legacy_client_url + '/iframe/dashboard'
    end
  end

  def client_view_mobile
    if @user.active? == false
      @user.user_type_id = UserConstants::USERTYPE_ACTIVE
      @user.save!
    end
    token = Base64.encode64(Marshal.dump({id: @user.id}))
    render json: {token: token}
  end

  def reset_onboarding
    @user.gettingstarted_step = nil
    if @user.save
      render json: {status: true, message: "Resetted the Onboarding status"}
    else
      render_error(@user, :unprocessable_entity)
    end 
  end

  def reset_mfa
    @user.mfa_enabled = false
    if @user.save
      render json: {status: true, message: "MFA disabled successfully"}
    else
      render_error(@user, :unprocessable_entity)
    end
  end

  def reassign_advisor
    admin_users = AdminUserPolicy::Scope.new(current_user, AdminUser).resolve.unscope(:order)
    if params[:re_assign] == "all" and params[:from_admin_user_id].present?
      from_admin_user = admin_users.where(id: params[:from_admin_user_id]).last
      users = from_admin_user.present? ? @users.where(advisor_admin_user_id: from_admin_user.id) : []
    else  
      users = @users.where(id: params[:user_ids])
    end
    to_admin_user = admin_users.where(id: params[:to_admin_user_id]).last
    if to_admin_user.present?
      users.update_all(advisor_admin_user_id: to_admin_user.id )
      render json: {success: true, message: "User's updated successfully"}
    else
      render json: {success: false, message: "Advisor not Found"}
    end
  end

  def upload_clients_preview
    can_upload_multiple_household = current_user.has_role?(:admin, current_firm)
    @result = User.upload_clients_preview(current_firm, params, can_upload_multiple_household)
  end

  def upload_clients_submit
    @result = User.update_client_submit(current_firm, params)
    render json: {success: true, message: "Clients imported successfully!"}
  end

  def social
    session_status = current_token.session_status
    parsed_status = session_status.present? ? JSON.parse(session_status) : {}
    if parsed_status["is_ssn_mfa_enabled"] == true
      AdminUserMfaLog.create_record(current_user.id, @user, AdminUserMfaLog.activity_types["Request SSN"], "SSN viewed after validating the one-time password (two-factor authentication)")
      render json: {success: true, social: @user.social}
    else
      send_sms = (params[:mobile].present? || current_user.get_firm.show_send_code?)
      is_authy_code_valid = current_user.is_authy_code_valid?(send_sms) if current_user.mfa_enabled?
      description = if current_user.mfa_enabled? and is_authy_code_valid
                      "Requesting user to enter two-factor authentication from SMS text or phone call." 
                    elsif current_user.mfa_enabled? and !is_authy_code_valid
                      "Need to register for Authy"
                    else
                      "MFA not Enabled"
                    end
      AdminUserMfaLog.create_record(current_user.id, @user, AdminUserMfaLog.activity_types["Request SSN"], description)
      render json: {success: false, mfa_enabled: current_user.mfa_enabled, authy_enabled: is_authy_code_valid}
    end
  end

  def add_tda_multi_form
    @user_document = UserDocument.new
    @document_templates = DocumentTemplate.where(document_template_type: "Tda").order(:name)
    @my529_templates = DocumentTemplate.where(document_template_type: "my529").order(:name)
    @schwab_templates = DocumentTemplate.where(document_template_type: "schwab").order(:name)
  end

 private

  def set_users
    @users = UserPolicy::Scope.new(current_user, User).resolve
  end

  def set_user
    user =  User.find(params[:id])
    authorize user
    @user = user
  end

 def form_user_details_params
   marital_status = user_details_params[:marital_status].to_i if user_details_params[:marital_status].present?
   gender = user_details_params[:gender].to_i if user_details_params[:gender].present?
   user_type_id = user_details_params[:status] == "Inactive" ? USERTYPE_INACTIVE : USERTYPE_ACTIVE if user_details_params[:status].present?
   user_details_params.merge!( marital_status: marital_status, gender: gender, user_type_id: user_type_id ).reject!{|k,v| k == "status"} 
 end

 def check_role
  case user_params[:household_role].downcase
  when 'primary'
    HouseholdUser.household_user_types[:Primary]
  when 'secondary'
    HouseholdUser.household_user_types[:Secondary]
  when 'beneficiary'
    HouseholdUser.household_user_types[:Beneficiary]
  end
 end

 def user_params
   params.require(:user).permit(:name, :first_name, :last_name, :middle_initial, :email, :birthday, :household_id, :default_household, :household_role,
                                :category, :advisor_admin_user_id, :employer_industry, :employer_occupation, :employer_status, :employer_name, :employer_address,
                                :employer_city, :employer_state, :employer_zipcode, :employer_address2, :employer_industry_code, :employer_occupation_code,
                                :user_employer_industry_id, :user_employer_occupation_id, :affiliated_with_finra, :is_company_board_member, :address_name,
                                :address1, :address2, :city, :state, :zipcode, :address_salutation, :copy_address_to_household, :cdd_annual_income, :cdd_net_worth, 
                                :cdd_initial_source_of_funds, :cdd_ongoing_source_of_funds, :country, :social)
 end

 def user_contact_params
   params.require(:contact).permit(:phone1_type, :phone2_type, :phone3_type, :phone1, :phone2, :country,
                                   :phone3, :email, :email2, :email3, :address_name, :primary_phone_type,
                                   :address1, :address2, :city, :state, :zipcode, :address_salutation, :second_address1, :second_address2,
                                   :second_city, :second_state, :second_zipcode, :second_country, :copy_address_to_household)
 end

  def user_details_params
    params.require(:details).permit(:retirement_age, :advisor_admin_user_id, :social, :citizenship, :marital_status,
                                   :gender, :deceased_date, :category, :status, :user_type_id, :birthday, :firm_client, :preferred_name,
                                   :name, :first_name, :last_name, :middle_initial, :cdd_annual_income, :cdd_net_worth, :cdd_initial_source_of_funds, 
                                   :cdd_ongoing_source_of_funds, :referred_by_id).merge!(firm_client: (params[:details] and params[:details][:firm_client].to_s == "true"))
 end

 def employer_details_params
   params.require(:employer).permit(:employer_industry, :employer_occupation, :employer_status, :employer_name, :employer_address,
                                    :employer_city, :employer_state, :employer_zipcode, :employer_address2, :employer_industry_code,
                                    :employer_occupation_code, :user_employer_industry_id, :user_employer_occupation_id, :affiliated_with_finra,
                                    :is_company_board_member )
 end

 def household_params
  params.require(:households).permit(household_users: [[:name, :role, :visible, :is_default, :household_id]])
 end

 def household_external_provider_params
   params.require(:user).permit(household_external_providers: [:id, :household_external_provider_role_id, :household_id, :_destroy])
 endend
