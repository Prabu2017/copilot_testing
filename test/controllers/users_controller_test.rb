require 'test_helper'

class UsersControllerTest < ActionController::TestCase
  setup do
    @user = users(:one)
  end

  test "should get index" do
    get :index
    assert_response :success
    assert_not_nil assigns(:users)
  end

  test "should get show" do
    get :show, params: { id: @user.id }
    assert_response :success
    assert_not_nil assigns(:user)
  end

  test "should create user" do
    assert_difference('User.count') do
      post :create, params: { user: { name: "John", email: "john@example.com" } }
    end

    assert_redirected_to user_path(assigns(:user))
  end

  test "should update user" do
    patch :update, params: { id: @user.id, user: { name: "Updated Name" } }
    assert_redirected_to user_path(assigns(:user))
    @user.reload
    assert_equal "Updated Name", @user.name
  end

  test "should destroy user" do
    assert_difference('User.count', -1) do
      delete :destroy, params: { id: @user.id }
    end

    assert_redirected_to users_path
  end
end