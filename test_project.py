from project import average, count_words, even_or_odd, factorial, find_max, is_palindrome, list_length, reverse_string, square_number, sum_of_digits


def main():
    test_average()
    test_count_words()
    test_even_or_odd()
    test_factorial()
    test_find_max()
    test_is_palindrome()
    test_list_length()
    test_reverse_string()
    test_square_number()
    test_sum_of_digits()


def test_reverse_string():
    assert reverse_string("hello") == "olleh"
    assert reverse_string("python") == "nohtyp"
    assert reverse_string("") == ""


def test_square_number():
    assert square_number(4) == 16
    assert square_number(0) == 0
    assert square_number(-3) == 9


def test_even_or_odd():
    assert even_or_odd(4) == "Even"
    assert even_or_odd(7) == "Odd"
    assert even_or_odd(0) == "Even"


def test_factorial():
    assert factorial(5) == 120
    assert factorial(0) == 1
    assert factorial(1) == 1


def test_count_words():
    assert count_words("This is a test") == 4
    assert count_words("") == 0
    assert count_words("OneWord") == 1


def test_find_max():
    assert find_max([3, 7, 2, 8, 5]) == 8
    assert find_max([0, 0, 0, 0]) == 0
    assert find_max([-1, -5, -2]) == -1


def test_is_palindrome():
    assert is_palindrome("racecar") == True
    assert is_palindrome("hello") == False
    assert is_palindrome("") == True


def test_sum_of_digits():
    assert sum_of_digits(12345) == 15
    assert sum_of_digits(0) == 0
    assert sum_of_digits(9) == 9


def test_list_length():
    assert list_length([1, 2, 3, 4, 5]) == 5
    assert list_length([]) == 0
    assert list_length(["apple", "banana", "cherry"]) == 3


def test_average():
    assert average([1, 2, 3, 4, 5]) == 3.0
    assert average([]) == 0
    assert average([-1, -2, -3, -4, -5]) == -3.0


if __name__ == '__main__':
    main()
