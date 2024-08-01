class Calculator
    def add(a = 0, b = 0)
        a + b
    end

    def subtract(a, b)
        a - b
    end

    def multiply(a, b)
        a * b
    end

    def divide(a, b)
        a.to_f / b.to_f
    end

    def sqrt(a)
        Math.sqrt(a)
    end
end