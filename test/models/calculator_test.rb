require 'test_helper'

class CalculatorTest < ActiveSupport::TestCase
  test "add method should return the sum of two numbers" do
    calculator = Calculator.new
    result = calculator.add(1, 2)
    assert_equal 3, result
  end

  test "subtract method should return the difference between two numbers" do
       calculator = Calculator.new
        result = calculator.subtract(5, 3)
    assert_equal 2, result
  end

  test "multiply method should return the product of two numbers" do
    calculator = Calculator.new
    result = calculator.multiply(2, 4)
    assert_equal 8, result
  end

  test "divide method should return the quotient of two numbers" do
    calculator = Calculator.new
    result = calculator.divide(10, 2)
    assert_equal 5.0, result
  end

  test "sqrt method should return the square root of a number" do
    calculator = Calculator.new
    result = calculator.sqrt(16)
    assert_equal 4.0, result
  end
end